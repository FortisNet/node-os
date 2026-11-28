// ML-DSA-87 (FIPS 204) through the pq-crystals reference code in
// third_party/crypto/mldsa, compiled with DILITHIUM_MODE=5 and hedged signing.
#include "key_algorithms.h"
#include "mldsa_seed.h"

extern "C" {
#include "mldsa/ref/api.h"
}

#include <cstring>

static_assert(pqcrystals_dilithium5_PUBLICKEYBYTES == fortis::keys::kMlDsa87Sizes.public_key);
static_assert(pqcrystals_dilithium5_SECRETKEYBYTES == fortis::keys::kMlDsa87Sizes.secret_key);
static_assert(pqcrystals_dilithium5_BYTES == fortis::keys::kMlDsa87Sizes.signature);

namespace fortis::keys::primitives {
bool MlDsa87KeyPair(std::span<uint8_t, 2592> public_key, std::span<uint8_t, 4896> secret_key,
                    const std::array<uint8_t, 32>* seed) noexcept {
  if (!seed) return pqcrystals_dilithium5_ref_keypair(public_key.data(), secret_key.data()) == 0;
  const detail::ScriptedRandomness scripted(*seed);
  return pqcrystals_dilithium5_ref_keypair(public_key.data(), secret_key.data()) == 0 && scripted.Consumed();
}

bool MlDsa87Sign(std::span<uint8_t, 4627> signature, View message, View context, View secret_key) noexcept {
  if (secret_key.size() != kMlDsa87Sizes.secret_key || context.size() > 255) return false;
  size_t length = 0;
  return pqcrystals_dilithium5_ref_signature(signature.data(), &length, message.data(), message.size(), context.data(),
                                             context.size(), secret_key.data()) == 0 &&
         length == signature.size();
}

bool MlDsa87SignWith(const std::array<uint8_t, 32>& randomness, std::span<uint8_t, 4627> signature, View message,
                     View context, View secret_key) noexcept {
  const detail::ScriptedRandomness scripted(randomness);
  return MlDsa87Sign(signature, message, context, secret_key) && scripted.Consumed();
}

bool MlDsa87Verify(View signature, View message, View context, View public_key) noexcept {
  if (signature.size() != kMlDsa87Sizes.signature || public_key.size() != kMlDsa87Sizes.public_key ||
      context.size() > 255)
    return false;
  return pqcrystals_dilithium5_ref_verify(signature.data(), signature.size(), message.data(), message.size(),
                                          context.data(), context.size(), public_key.data()) == 0;
}
}  // namespace fortis::keys::primitives
