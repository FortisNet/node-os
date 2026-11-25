#include "bounded_json.h"

#include "json_lex.h"

#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

namespace fortis::codec {

namespace {
namespace lex = fortis::codec::json_lex;

bool hex4(const unsigned char* input, size_t length, size_t* position,
          uint32_t* value) {
  if (length - *position < 4) return false;
  // A bad digit fails the document; the position is not used afterwards.
  if (!lex::Hex4(input + *position, value)) return false;
  *position += 4;
  return true;
}

bool decode_scalar(const unsigned char* input, size_t length, size_t* position,
                   uint32_t* codepoint) {
  if (*position >= length) return false;
  const unsigned char c = input[(*position)++];
  if (c == '\\') {
    if (*position >= length) return false;
    const unsigned char escaped = input[(*position)++];
    switch (escaped) {
      case '"': *codepoint = '"'; return true;
      case '\\': *codepoint = '\\'; return true;
      case '/': *codepoint = '/'; return true;
      case 'b': *codepoint = '\b'; return true;
      case 'f': *codepoint = '\f'; return true;
      case 'n': *codepoint = '\n'; return true;
      case 'r': *codepoint = '\r'; return true;
      case 't': *codepoint = '\t'; return true;
      case 'u': {
        uint32_t first = 0;
        if (!hex4(input, length, position, &first)) return false;
        if (first >= 0xd800 && first <= 0xdbff) {
          size_t next = *position;
          uint32_t second = 0;
          if (length - next >= 6 && input[next] == '\\' && input[next + 1] == 'u') {
            next += 2;
            if (hex4(input, length, &next, &second) && second >= 0xdc00 && second <= 0xdfff) {
              *position = next;
              *codepoint = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
              return true;
            }
          }
          *codepoint = 0xfffd;
          return true;
        }
        if (first >= 0xdc00 && first <= 0xdfff) { *codepoint = 0xfffd; return true; }
        *codepoint = first;
        return true;
      }
      default: return false;
    }
  }
  if (c < 0x20) return false;
  if (c < 0x80) { *codepoint = c; return true; }
  const unsigned trailing = (c & 0xe0) == 0xc0 ? 1 :
                            (c & 0xf0) == 0xe0 ? 2 :
                            (c & 0xf8) == 0xf0 ? 3 : 99;
  if (trailing == 99 || length - *position < trailing) return false;
  uint32_t result = c & (trailing == 1 ? 0x1f : trailing == 2 ? 0x0f : 0x07);
  for (unsigned i = 0; i < trailing; ++i) {
    const unsigned char next = input[(*position)++];
    if ((next & 0xc0) != 0x80) return false;
    result = (result << 6) | (next & 63);
  }
  if ((trailing == 1 && result < 0x80) ||
      (trailing == 2 && result < 0x800) ||
      (trailing == 3 && result < 0x10000) || result > 0x10ffff ||
      (result >= 0xd800 && result <= 0xdfff)) return false;
  *codepoint = result;
  return true;
}

bool number_syntax(const unsigned char* input, size_t length, size_t* position) {
  const size_t start = *position;
  const unsigned char* after = lex::ScanNumber(input + start, input + length);
  if (!after) return false;
  *position = static_cast<size_t>(after - input);
  // Native bounds beyond the grammar: fewer than 64 bytes and a finite double.
  const size_t length_parsed = *position - start;
  if (length_parsed >= 64) return false;
  char number[64];
  memcpy(number, input + start, length_parsed);
  number[length_parsed] = '\0';
  char* end = nullptr;
  errno = 0;
  const double parsed = strtod(number, &end);
  return end == number + length_parsed && isfinite(parsed);
}

struct Parser {
  const unsigned char* input;
  size_t length;
  BoundedJsonToken* tokens;
  size_t capacity;
  size_t count = 0;
  size_t position = 0;
  BoundedJsonError error = BoundedJsonError::kInvalidInput;

  void whitespace() {
    while (position < length && lex::IsSpace(input[position])) ++position;
  }

  uint32_t add(BoundedJsonType type, uint32_t parent, uint32_t* last_child) {
    if (count >= capacity) {
      error = BoundedJsonError::kTokenLimit;
      return kBoundedJsonNoToken;
    }
    const uint32_t index = static_cast<uint32_t>(count++);
    tokens[index] = BoundedJsonToken{};
    tokens[index].type = type;
    if (parent != kBoundedJsonNoToken) {
      if (*last_child == kBoundedJsonNoToken) tokens[parent].first_child = index;
      else tokens[*last_child].next_sibling = index;
      *last_child = index;
    }
    return index;
  }

  bool string_token(uint32_t parent, uint32_t* last_child) {
    whitespace();
    if (position >= length || input[position] != '"') return false;
    const uint32_t index = add(BoundedJsonType::kString, parent, last_child);
    if (index == kBoundedJsonNoToken) return false;
    ++position;
    tokens[index].start = static_cast<uint32_t>(position);
    while (position < length && input[position] != '"') {
      uint32_t scalar = 0;
      if (!decode_scalar(input, length, &position, &scalar)) return false;
    }
    if (position >= length) return false;
    tokens[index].length = static_cast<uint32_t>(position - tokens[index].start);
    ++position;
    return true;
  }

  bool value(uint32_t parent, uint32_t* last_child, size_t depth,
             uint32_t* result) {
    whitespace();
    if (position >= length) return false;
    const unsigned char c = input[position];
    if (c == '{' || c == '[') {
      if (depth >= kBoundedJsonMaxDepth) {
        error = BoundedJsonError::kDepthLimit;
        return false;
      }
      const BoundedJsonType type = c == '{' ? BoundedJsonType::kObject :
                                                   BoundedJsonType::kArray;
      const uint32_t index = add(type, parent, last_child);
      if (index == kBoundedJsonNoToken) return false;
      if (result) *result = index;
      ++position;
      whitespace();
      const unsigned char close = c == '{' ? '}' : ']';
      if (position < length && input[position] == close) { ++position; return true; }
      uint32_t child_last = kBoundedJsonNoToken;
      for (;;) {
        if (type == BoundedJsonType::kObject) {
          if (!string_token(index, &child_last)) return false;
          whitespace();
          if (position >= length || input[position] != ':') return false;
          ++position;
        }
        if (!value(index, &child_last, depth + 1, nullptr)) return false;
        whitespace();
        if (position < length && input[position] == close) { ++position; return true; }
        if (position >= length || input[position] != ',') return false;
        ++position;
        whitespace();
      }
    }
    if (c == '"') {
      const uint32_t index_before = static_cast<uint32_t>(count);
      if (!string_token(parent, last_child)) return false;
      if (result) *result = index_before;
      return true;
    }
    BoundedJsonType type = BoundedJsonType::kNumber;
    size_t start = position;
    if (c == 't' && length - position >= 4 && memcmp(input + position, "true", 4) == 0) {
      type = BoundedJsonType::kTrue; position += 4;
    } else if (c == 'f' && length - position >= 5 && memcmp(input + position, "false", 5) == 0) {
      type = BoundedJsonType::kFalse; position += 5;
    } else if (c == 'n' && length - position >= 4 && memcmp(input + position, "null", 4) == 0) {
      type = BoundedJsonType::kNull; position += 4;
    } else if (!number_syntax(input, length, &position)) {
      return false;
    }
    const uint32_t index = add(type, parent, last_child);
    if (index == kBoundedJsonNoToken) return false;
    tokens[index].start = static_cast<uint32_t>(start);
    tokens[index].length = static_cast<uint32_t>(position - start);
    if (result) *result = index;
    return true;
  }

  bool document(uint32_t* root) {
    whitespace();
    uint32_t last = kBoundedJsonNoToken;
    if (!value(kBoundedJsonNoToken, &last, 0, root)) return false;
    whitespace();
    return position == length;
  }
};

void append_utf8(uint32_t cp, char* output, size_t capacity, size_t* used,
                 bool* ok) {
  unsigned char bytes[4];
  const size_t count = lex::EncodeUtf8(cp, bytes);
  if (*used + count >= capacity) { *ok = false; return; }
  memcpy(output + *used, bytes, count);
  *used += count;
  output[*used] = '\0';
}
}  // namespace

bool BoundedJsonDocument::Parse(const unsigned char* input, size_t length,
                                BoundedJsonToken* tokens, size_t token_capacity,
                                BoundedJsonError* error) {
  return ParseWithLimit(input, length, tokens, token_capacity,
                        kBoundedJsonMaxTokens, error);
}

bool BoundedJsonDocument::ParseWithLimit(const unsigned char* input, size_t length,
                                BoundedJsonToken* tokens, size_t token_capacity,
                                size_t token_limit, BoundedJsonError* error) {
  return ParseWithLimits(input, length, tokens, token_capacity, token_limit,
                         kBoundedJsonMaxInputBytes, error);
}

bool BoundedJsonDocument::ParseWithLimits(const unsigned char* input, size_t length,
                                BoundedJsonToken* tokens, size_t token_capacity,
                                size_t token_limit, size_t input_limit,
                                BoundedJsonError* error) {
  input_ = nullptr; length_ = token_count_ = 0; tokens_ = nullptr;
  token_capacity_ = 0; root_ = kBoundedJsonNoToken;
  if (error) *error = BoundedJsonError::kInvalidInput;
  if (!input || !tokens || !token_capacity || !token_limit || !length ||
      !input_limit || input_limit > kBoundedJsonMaxExpandedInputBytes) return false;
  if (length > input_limit) {
    if (error) *error = BoundedJsonError::kInputTooLarge;
    return false;
  }
  const size_t capacity = token_capacity < token_limit ? token_capacity : token_limit;
  Parser parser{input, length, tokens, capacity};
  uint32_t root = kBoundedJsonNoToken;
  if (!parser.document(&root)) {
    if (error) *error = parser.error;
    return false;
  }
  input_ = input; length_ = length; tokens_ = tokens;
  token_capacity_ = parser.capacity; token_count_ = parser.count; root_ = root;
  if (error) *error = BoundedJsonError::kNone;
  return true;
}

const BoundedJsonToken* BoundedJsonDocument::token(uint32_t index) const {
  return index < token_count_ ? &tokens_[index] : nullptr;
}

bool BoundedJsonDocument::DecodeString(uint32_t index, char* output,
                                       size_t capacity, size_t* output_length) const {
  const BoundedJsonToken* item = token(index);
  if (!item || item->type != BoundedJsonType::kString || !output || !capacity)
    return false;
  size_t position = item->start, end = item->start + item->length, used = 0;
  output[0] = '\0';
  while (position < end) {
    uint32_t scalar = 0;
    if (!decode_scalar(input_, end, &position, &scalar)) return false;
    bool ok = true;
    append_utf8(scalar, output, capacity, &used, &ok);
    if (!ok) return false;
  }
  if (output_length) *output_length = used;
  return true;
}

bool BoundedJsonDocument::StringEquals(uint32_t index, const char* value,
                                       bool ascii_case_insensitive) const {
  const BoundedJsonToken* item = token(index);
  if (!item || item->type != BoundedJsonType::kString || !value) return false;
  size_t position = item->start, end = item->start + item->length, wanted = 0;
  while (position < end) {
    uint32_t scalar = 0;
    if (!decode_scalar(input_, end, &position, &scalar) || !value[wanted]) return false;
    if (ascii_case_insensitive) {
      if (scalar > 0x7f) return false;
      unsigned char actual = static_cast<unsigned char>(scalar);
      unsigned char expected = static_cast<unsigned char>(value[wanted++]);
      if (actual >= 'A' && actual <= 'Z') actual += 'a' - 'A';
      if (expected >= 'A' && expected <= 'Z') expected += 'a' - 'A';
      if (actual != expected) return false;
    } else {
      unsigned char encoded[4];
      const size_t encoded_length = lex::EncodeUtf8(scalar, encoded);
      for (size_t i = 0; i < encoded_length; ++i) {
        if (!value[wanted] || encoded[i] != static_cast<unsigned char>(value[wanted]))
          return false;
        ++wanted;
      }
    }
  }
  return value[wanted] == '\0';
}

uint32_t BoundedJsonDocument::FindObjectValue(uint32_t object, const char* key,
                                             bool ascii_case_insensitive) const {
  const BoundedJsonToken* item = token(object);
  if (!item || item->type != BoundedJsonType::kObject || !key) return kBoundedJsonNoToken;
  uint32_t found = kBoundedJsonNoToken;
  for (uint32_t child = item->first_child; child != kBoundedJsonNoToken;) {
    const uint32_t value = token(child) ? token(child)->next_sibling : kBoundedJsonNoToken;
    if (value == kBoundedJsonNoToken) return kBoundedJsonNoToken;
    if (StringEquals(child, key, ascii_case_insensitive)) found = value;
    child = token(value) ? token(value)->next_sibling : kBoundedJsonNoToken;
  }
  return found;
}

bool BoundedJsonDocument::Number(uint32_t index, double* value) const {
  const BoundedJsonToken* item = token(index);
  if (!item || item->type != BoundedJsonType::kNumber || !value ||
      item->length >= 64 || item->start > length_ ||
      item->length > length_ - item->start) return false;
  char text[64];
  memcpy(text, input_ + item->start, item->length);
  text[item->length] = '\0';
  char* end = nullptr;
  const double parsed = strtod(text, &end);
  if (end != text + item->length || !isfinite(parsed)) return false;
  *value = parsed;
  return true;
}

}  // namespace fortis::codec

