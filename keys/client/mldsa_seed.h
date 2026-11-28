#pragma once
// Internal to keys/client: makes one ML-DSA call deterministic.
#include <array>
#include <cstddef>
#include <cstdint>

extern "C" void fortis_mldsa_randombytes(uint8_t* out, size_t length);

namespace fortis::keys::detail {
/// While it lives, this thread's next request for randomness from the ML-DSA
/// code gets these 32 bytes; a second request aborts.
class ScriptedRandomness {
 public:
  explicit ScriptedRandomness(const std::array<uint8_t, 32>& bytes) noexcept;
  ~ScriptedRandomness();
  ScriptedRandomness(const ScriptedRandomness&) = delete;
  ScriptedRandomness& operator=(const ScriptedRandomness&) = delete;
  /// Whether the bytes were used: a call that should have used them and did not is a bug.
  bool Consumed() const noexcept;
};
}  // namespace fortis::keys::detail
