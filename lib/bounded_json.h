#pragma once

#include <stddef.h>
#include <stdint.h>

namespace fortis::codec {

constexpr size_t kBoundedJsonMaxInputBytes = 256 * 1024;
// Hard ceiling for ParseWithLimits callers that own a measured larger input
// buffer and token arena (the 512 KiB CoinGecko history body).
constexpr size_t kBoundedJsonMaxExpandedInputBytes = 1024 * 1024;
constexpr size_t kBoundedJsonMaxTokens = 8192;
constexpr size_t kBoundedJsonMaxDepth = 16;
constexpr uint32_t kBoundedJsonNoToken = UINT32_MAX;

enum class BoundedJsonType : uint8_t { kObject, kArray, kString, kNumber, kTrue, kFalse, kNull };
enum class BoundedJsonError : uint8_t {
  kNone, kInvalidInput, kInputTooLarge, kTokenLimit, kDepthLimit
};

// String and number spans refer to the caller's input buffer. Objects have
// alternating key/value children; arrays have value children. Tokens and all
// traversal storage are caller-owned, bounded, and never allocate.
struct BoundedJsonToken {
  BoundedJsonType type = BoundedJsonType::kNull;
  uint32_t start = 0;
  uint32_t length = 0;
  uint32_t first_child = kBoundedJsonNoToken;
  uint32_t next_sibling = kBoundedJsonNoToken;
  // Reserved parse/extractor scratch; currently used for a last duplicate-key
  // value index after the document has been validated.
  uint32_t auxiliary = kBoundedJsonNoToken;
};

class BoundedJsonDocument {
 public:
  bool Parse(const unsigned char* input, size_t length, BoundedJsonToken* tokens,
             size_t token_capacity, BoundedJsonError* error);
  // Explicit per-document expansion for callers with a measured larger
  // caller-owned arena; ordinary parsers retain the global 8,192-token cap.
  bool ParseWithLimit(const unsigned char* input, size_t length,
             BoundedJsonToken* tokens, size_t token_capacity,
             size_t token_limit, BoundedJsonError* error);
  // As ParseWithLimit, with an explicit input bound of at most
  // kBoundedJsonMaxExpandedInputBytes; a larger input_limit is rejected.
  bool ParseWithLimits(const unsigned char* input, size_t length,
             BoundedJsonToken* tokens, size_t token_capacity,
             size_t token_limit, size_t input_limit, BoundedJsonError* error);
  uint32_t root() const { return root_; }
  // The parsed input; token spans index into it. Null before a successful parse.
  const unsigned char* input() const { return input_; }
  size_t token_count() const { return token_count_; }
  const BoundedJsonToken* token(uint32_t index) const;
  uint32_t FindObjectValue(uint32_t object, const char* key,
                           bool ascii_case_insensitive = false) const;
  bool StringEquals(uint32_t index, const char* value,
                    bool ascii_case_insensitive = false) const;
  bool DecodeString(uint32_t index, char* output, size_t capacity,
                    size_t* output_length) const;
  bool Number(uint32_t index, double* value) const;

 private:
  const unsigned char* input_ = nullptr;
  size_t length_ = 0;
  BoundedJsonToken* tokens_ = nullptr;
  size_t token_capacity_ = 0;
  size_t token_count_ = 0;
  uint32_t root_ = kBoundedJsonNoToken;
};

}  // namespace fortis::codec

