#pragma once
// The key service's wire format (docs/fortis-did.md, section 10): a 16-byte
// header, then a body. Numbers are unsigned and big-endian.
//
//   0  4  magic "FKD1"
//   4  1  direction: 0 request, 1 reply
//   5  1  code: the operation in a request, the result in a reply
//   6  2  reserved, 0
//   8  4  request ID, copied into the reply
//  12  4  body length
#include "key_algorithms.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace fortis::keys::wire {
using Header = std::array<uint8_t, 16>;

enum class Direction : uint8_t { Request = 0, Reply = 1 };
enum class Operation : uint8_t {
  Info = 1,
  PublicKey = 2,
  Sign = 3,
  OpenChannel = 4,
  Manifest = 5,          // the identity's public manifest
  MachineStatement = 6,  // this machine's statement, signed by the identity's ML-DSA-87 root
  Checkpoint = 7,        // a checkpoint of the signing log, signed by the machine key
  LogEntries = 8,        // a run of signing log entries
};
enum class Result : uint8_t { Ok = 0, BadRequest = 1, Denied = 2, Busy = 3, Unavailable = 4, Failed = 5 };

/// A Sign request: algorithm, label length, label, then a message of up to kMessageMax bytes.
inline constexpr uint32_t kRequestMax = 2 + kLabelMax + kMessageMax;
/// The largest reply: an ML-DSA-87 public key or signature, with room to spare.
inline constexpr uint32_t kReplyMax = 65536;

constexpr bool KnownOperation(uint8_t code) noexcept { return code >= 1 && code <= 8; }
constexpr bool KnownResult(uint8_t code) noexcept { return code <= 5; }

/// The most a request with this operation may carry.
constexpr uint32_t RequestLimit(Operation operation) noexcept {
  switch (operation) {
    case Operation::Info:
    case Operation::OpenChannel:
    case Operation::Manifest:
    case Operation::MachineStatement: return 0;
    case Operation::PublicKey: return 1;
    case Operation::Sign: return kRequestMax;
    case Operation::Checkpoint: return 8;   // the entry to cover; 0 for the latest
    case Operation::LogEntries: return 10;  // the first entry (u64) and how many (u16)
  }
  return 0;
}

constexpr Header Encode(Direction direction, uint8_t code, uint32_t id, uint32_t length) noexcept {
  return {'F',
          'K',
          'D',
          '1',
          static_cast<uint8_t>(direction),
          code,
          0,
          0,
          static_cast<uint8_t>(id >> 24),
          static_cast<uint8_t>(id >> 16),
          static_cast<uint8_t>(id >> 8),
          static_cast<uint8_t>(id),
          static_cast<uint8_t>(length >> 24),
          static_cast<uint8_t>(length >> 16),
          static_cast<uint8_t>(length >> 8),
          static_cast<uint8_t>(length)};
}

struct Decoded {
  uint8_t code;
  uint32_t id;
  uint32_t length;
};

/// Refuses a wrong magic, direction or reserved field, an unknown code, and a
/// body longer than that code allows, so nothing larger is ever read.
constexpr std::optional<Decoded> Decode(const Header& h, Direction expected) noexcept {
  if (h[0] != 'F' || h[1] != 'K' || h[2] != 'D' || h[3] != '1') return std::nullopt;
  if (h[4] != static_cast<uint8_t>(expected) || h[6] != 0 || h[7] != 0) return std::nullopt;
  const uint32_t id = uint32_t{h[8]} << 24 | uint32_t{h[9]} << 16 | uint32_t{h[10]} << 8 | h[11];
  const uint32_t length = uint32_t{h[12]} << 24 | uint32_t{h[13]} << 16 | uint32_t{h[14]} << 8 | h[15];
  if (expected == Direction::Request) {
    if (!KnownOperation(h[5]) || length > RequestLimit(static_cast<Operation>(h[5]))) return std::nullopt;
  } else if (!KnownResult(h[5]) || length > kReplyMax) {
    return std::nullopt;
  }
  return Decoded{h[5], id, length};
}
}  // namespace fortis::keys::wire
