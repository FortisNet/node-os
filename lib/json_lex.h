#pragma once

#include <stddef.h>
#include <stdint.h>

// The lexical rules every JSON reader in src/ shares (RFC 8259 = ECMA-404 =
// what JSON.parse accepts): whitespace, the number grammar, hex digits of a
// \uXXXX escape, and UTF-8 encoding of a decoded code point. The readers
// themselves stay separate because their models differ; see
// docs/codec-semantics.md for which one to use:
//  - BoundedJsonDocument (bounded_json.h): strict, allocation-free tokenizer
//    for untrusted provider and request bodies;
//  - tj (token_json.h): mutable DOM with JavaScript value semantics;
//  - news::json (news_json.h): read-only DOM with UTF-16 strings and source
//    spans for the news store's own cached documents.
// Header-only and guest-safe: no C++ standard-library headers.
namespace fortis::codec::json_lex {

inline bool IsSpace(uint8_t c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

// The value of one hex digit, or -1.
inline int HexDigit(uint8_t c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Four hex digits at `text` (the caller has checked that four bytes exist).
inline bool Hex4(const uint8_t* text, uint32_t* value) {
  uint32_t result = 0;
  for (int i = 0; i < 4; ++i) {
    const int digit = HexDigit(text[i]);
    if (digit < 0) return false;
    result = result << 4 | static_cast<uint32_t>(digit);
  }
  *value = result;
  return true;
}

// The JSON number grammar: -? (0 | [1-9][0-9]*) (\.[0-9]+)? ([eE][+-]?[0-9]+)?
// Returns the first byte after the number, or null when no number starts at
// `p` or a leading zero is followed by another digit ("01"). How the text
// becomes a value (strtod to a double, length and finiteness bounds) is each
// reader's own, documented, rule.
inline const uint8_t* ScanNumber(const uint8_t* p, const uint8_t* end) {
  if (p < end && *p == '-') ++p;
  if (p >= end) return nullptr;
  if (*p == '0') {
    ++p;
    if (p < end && *p >= '0' && *p <= '9') return nullptr;
  } else {
    if (*p < '1' || *p > '9') return nullptr;
    while (p < end && *p >= '0' && *p <= '9') ++p;
  }
  if (p < end && *p == '.') {
    ++p;
    if (p >= end || *p < '0' || *p > '9') return nullptr;
    while (p < end && *p >= '0' && *p <= '9') ++p;
  }
  if (p < end && (*p == 'e' || *p == 'E')) {
    ++p;
    if (p < end && (*p == '+' || *p == '-')) ++p;
    if (p >= end || *p < '0' || *p > '9') return nullptr;
    while (p < end && *p >= '0' && *p <= '9') ++p;
  }
  return p;
}

// Generalized UTF-8 of one code point into `out` (room for four bytes);
// returns the byte count. A surrogate code point (U+D800..U+DFFF) gets its
// three-byte form: that is WTF-8, which tj uses to carry a lone UTF-16
// surrogate from a JSON escape (a JavaScript-parity rule). Readers that must
// not produce it (BoundedJsonDocument) reject surrogates before calling.
inline size_t EncodeUtf8(uint32_t cp, uint8_t* out) {
  if (cp < 0x80) {
    out[0] = static_cast<uint8_t>(cp);
    return 1;
  }
  if (cp < 0x800) {
    out[0] = static_cast<uint8_t>(0xC0 | (cp >> 6));
    out[1] = static_cast<uint8_t>(0x80 | (cp & 0x3F));
    return 2;
  }
  if (cp < 0x10000) {
    out[0] = static_cast<uint8_t>(0xE0 | (cp >> 12));
    out[1] = static_cast<uint8_t>(0x80 | ((cp >> 6) & 0x3F));
    out[2] = static_cast<uint8_t>(0x80 | (cp & 0x3F));
    return 3;
  }
  out[0] = static_cast<uint8_t>(0xF0 | (cp >> 18));
  out[1] = static_cast<uint8_t>(0x80 | ((cp >> 12) & 0x3F));
  out[2] = static_cast<uint8_t>(0x80 | ((cp >> 6) & 0x3F));
  out[3] = static_cast<uint8_t>(0x80 | (cp & 0x3F));
  return 4;
}

}  // namespace fortis::codec::json_lex
