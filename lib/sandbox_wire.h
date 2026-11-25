#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

namespace fortis::codec::sandbox {
/// Local-only protocol. No descriptors, host paths, environment or commands beyond these operations.
enum class Operation : uint8_t { Start = 1, Status = 2, Stop = 3 };
/// Accepted means a durable job exists, not that its application is ready or succeeded.
enum class ReplyCode : uint8_t {
  Ok = 0,
  Accepted = 1,
  NotFound = 2,
  Conflict = 3,
  Denied = 4,
  Busy = 5,
  BadRequest = 6,
  Unavailable = 7
};
inline constexpr size_t kRequestLimit = 16384;
inline constexpr size_t kReplyLimit = 8192;
using Header = std::array<uint8_t, 12>;

/// Encode fixed framing; inputs must have a nonempty bounded body. No borrowed data survives.
inline Header Encode(bool reply, uint8_t code, uint32_t length) {
  return {'F',
          'S',
          'B',
          '1',
          static_cast<uint8_t>(reply ? 1 : 0),
          code,
          0,
          0,
          static_cast<uint8_t>(length >> 24),
          static_cast<uint8_t>(length >> 16),
          static_cast<uint8_t>(length >> 8),
          static_cast<uint8_t>(length)};
}
/// Reject wrong direction/version/reserved bits, unsupported codes and overflowing lengths. Outputs change only on
/// success.
inline bool Decode(const Header& input, bool reply, uint8_t& code, uint32_t& length) {
  if (input[0] != 'F' || input[1] != 'S' || input[2] != 'B' || input[3] != '1' || input[4] != (reply ? 1 : 0) ||
      input[6] || input[7])
    return false;
  const auto value = (uint32_t{input[8]} << 24) | (uint32_t{input[9]} << 16) | (uint32_t{input[10]} << 8) | input[11];
  if (!value || value > (reply ? kReplyLimit : kRequestLimit) ||
      (reply ? input[5] > 7 : input[5] < 1 || input[5] > 3) || (!reply && input[5] != 1 && value > 48))
    return false;
  code = input[5];
  length = value;
  return true;
}
}  // namespace fortis::codec::sandbox
