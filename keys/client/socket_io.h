#pragma once
// Whole-message I/O on a Unix stream socket, for the key client and service.
// A stream keeps no message boundaries (docs/fortis-did.md, section 8.2), so
// these loop until every byte has moved.
#include <cstddef>
#include <cstdint>
#include <span>

namespace fortis::keys::io {
/// Send every byte. With attach >= 0, that descriptor travels with the first
/// byte (SCM_RIGHTS). False if the peer is gone or the send timed out.
bool SendAll(int fd, std::span<const uint8_t> data, int attach = -1) noexcept;
/// Receive exactly output.size() bytes. A descriptor that arrives with them is
/// stored in *received when received is given, and closed otherwise, so a
/// peer can never leave descriptors behind. False on end of stream, error or
/// timeout; then nothing is left open.
bool ReceiveExact(int fd, std::span<uint8_t> output, int* received = nullptr) noexcept;
/// Limit how long one send or receive may block.
bool SetTimeouts(int fd, int seconds) noexcept;
}  // namespace fortis::keys::io
