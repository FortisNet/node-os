// SQIsign-V v3, parameter set p664_17, through the upstream reference code in
// third_party/crypto/sqisign. Its randomness comes from its own
// randombytes_system.c, which reads the kernel's generator.
#include "key_algorithms.h"

// As in its own build (the Makefile's SQISIGN_DEFINES): the signing functions
// are declared only with ENABLE_SIGN, and the variant and build type select
// the names its functions are compiled under.
#define ENABLE_SIGN
#define SQISIGN_VARIANT p664_17
#define SQISIGN_BUILD_TYPE_REF
extern "C" {
#include "sqisign/src/nistapi/p664_17/api.h"
}

static_assert(CRYPTO_PUBLICKEYBYTES == fortis::keys::kSqiSignVSizes.public_key);
static_assert(CRYPTO_SECRETKEYBYTES == fortis::keys::kSqiSignVSizes.secret_key);
static_assert(CRYPTO_BYTES == fortis::keys::kSqiSignVSizes.signature);

namespace fortis::keys::primitives {
bool SqiSignVKeyPair(std::span<uint8_t, 169> public_key, std::span<uint8_t, 549> secret_key) noexcept {
  return crypto_sign_keypair(public_key.data(), secret_key.data()) == 0;
}

bool SqiSignVSign(std::span<uint8_t, 406> signature, View message, View secret_key) noexcept {
  if (secret_key.size() != kSqiSignVSizes.secret_key) return false;
  unsigned long long length = 0;
  return crypto_sign_signature(signature.data(), &length, message.data(), message.size(), secret_key.data()) == 0 &&
         length == signature.size();
}

bool SqiSignVVerify(View signature, View message, View public_key) noexcept {
  if (signature.size() != kSqiSignVSizes.signature || public_key.size() != kSqiSignVSizes.public_key) return false;
  return crypto_sign_verify(signature.data(), signature.size(), message.data(), message.size(), public_key.data()) == 0;
}
}  // namespace fortis::keys::primitives
