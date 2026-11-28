// The one source of randomness for the key code: the kernel's generator.
//
// The ML-DSA reference code asks for randomness through a C function named
// randombytes. So does SQIsign, with another signature, so the ML-DSA files
// are compiled with -Drandombytes=fortis_mldsa_randombytes and get theirs
// here. No upstream file is changed (docs/fortis-did.md, section 18).
#include "key_algorithms.h"
#include "mldsa_seed.h"

#include <cstdlib>
#include <cstring>
#include <cerrno>

#include <sys/random.h>
#include <unistd.h>

namespace fortis::keys::primitives {
void FillRandom(std::span<uint8_t> output) noexcept {
  size_t done = 0;
  while (done < output.size()) {
#if defined(__linux__)
    const ssize_t got = getrandom(output.data() + done, output.size() - done, 0);
    if (got < 0 && errno == EINTR) continue;
    if (got <= 0) std::abort();
    done += static_cast<size_t>(got);
#else
    const size_t chunk = output.size() - done < 256 ? output.size() - done : 256;
    if (getentropy(output.data() + done, chunk) != 0) std::abort();
    done += chunk;
#endif
  }
}
}  // namespace fortis::keys::primitives

namespace fortis::keys::detail {
namespace {
// Set only for the duration of one ML-DSA call that must be deterministic:
// key generation from a seed, or a known-answer test.
thread_local const uint8_t* pending = nullptr;
thread_local bool consumed = false;
}  // namespace

ScriptedRandomness::ScriptedRandomness(const std::array<uint8_t, 32>& bytes) noexcept {
  pending = bytes.data();
  consumed = false;
}
ScriptedRandomness::~ScriptedRandomness() { pending = nullptr; }
bool ScriptedRandomness::Consumed() const noexcept { return consumed; }
}  // namespace fortis::keys::detail

// The ML-DSA code asks for exactly 32 bytes at a time: the key generation seed,
// or the per-signature randomness of hedged signing.
extern "C" void fortis_mldsa_randombytes(uint8_t* out, size_t length) {
  using namespace fortis::keys::detail;
  if (pending) {
    // A scripted call that asks for anything but one 32-byte value is a bug.
    if (consumed || length != 32) std::abort();
    std::memcpy(out, pending, 32);
    consumed = true;
    return;
  }
  fortis::keys::primitives::FillRandom({out, length});
}
