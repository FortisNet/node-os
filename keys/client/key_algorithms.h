#pragma once
// The three signature algorithms of a Fortis identity, and the labelled
// signing that the key service offers the node (docs/fortis-did.md, section 11).
//
// This file and the rest of keys/client/ are what the node copies: they hold
// no secret and no state. Verify() needs only public keys.
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace fortis::keys {
using Bytes = std::vector<uint8_t>;
using View = std::span<const uint8_t>;

/// The numbers are part of the wire format (docs/fortis-did.md, section 10.2).
enum class Algorithm : uint8_t { MlDsa87 = 1, SqiSignV = 2, Secp256k1 = 3 };
inline constexpr std::array<Algorithm, 3> kAlgorithms = {Algorithm::MlDsa87, Algorithm::SqiSignV, Algorithm::Secp256k1};

struct Sizes {
  size_t public_key;
  size_t secret_key;
  /// Exact for ML-DSA-87 and SQIsign-V; the DER encoding of secp256k1 varies, 8 to 72 bytes.
  size_t signature;
};
inline constexpr Sizes kMlDsa87Sizes{2592, 4896, 4627};
inline constexpr Sizes kSqiSignVSizes{169, 549, 406};
inline constexpr Sizes kSecp256k1Sizes{65, 32, 72};

constexpr Sizes SizesOf(Algorithm algorithm) noexcept {
  switch (algorithm) {
    case Algorithm::MlDsa87: return kMlDsa87Sizes;
    case Algorithm::SqiSignV: return kSqiSignVSizes;
    case Algorithm::Secp256k1: return kSecp256k1Sizes;
  }
  return {0, 0, 0};
}
/// The algorithm with this wire number, or none.
std::optional<Algorithm> AlgorithmFrom(uint8_t number) noexcept;
/// Its standard name, such as "ML-DSA-87".
std::string_view Name(Algorithm algorithm) noexcept;

/// A label names what a signature is for: 1 to 64 bytes of a-z, 0-9, '.', '_' and '-'.
inline constexpr size_t kLabelMax = 64;
bool ValidLabel(std::string_view label) noexcept;
/// The largest message the key service signs in one request.
inline constexpr size_t kMessageMax = 1024 * 1024;

/** The stack a thread needs (docs/fortis-did.md, section 13.1). These
 * algorithms keep large values on the stack, and a C library's default for a
 * new thread may be too small: musl gives 128 KiB, glibc usually 8 MiB. Give
 * threads these sizes yourself (pthread_attr_setstacksize), never rely on the
 * default. tests/keys_test.cpp measures what every operation really uses and
 * fails if it comes within half of these. */
/// For a thread that calls Verify(), or any other function of key_log.h.
inline constexpr size_t kVerifyStack = 512 * 1024;
/// For a thread that generates keys or signs: the key service's threads.
inline constexpr size_t kSigningStack = 2 * 1024 * 1024;

/// "fortis/app/" + label: the ML-DSA-87 context string, and the domain the others are tagged with.
Bytes Domain(std::string_view label);

/** The key service's stamp on every labelled signature (docs/fortis-did.md,
 * section 11.2). The key service chooses it, never the node: the machine that
 * signed, its signature number, and its clock. Signed together with the
 * message, so it cannot be changed or left out. */
struct Stamp {
  std::array<uint8_t, 16> machine{};  // the machine ID
  uint64_t sequence = 0;              // 1, 2, 3, ... on this machine, never reused
  uint64_t time = 0;                  // Unix seconds, the key service's clock
  bool operator==(const Stamp&) const = default;
};
inline constexpr size_t kStampSize = 32;
/// machine[16] || sequence (u64, big-endian) || time (u64, big-endian).
std::array<uint8_t, kStampSize> EncodeStamp(const Stamp& stamp) noexcept;
/// Exactly 32 bytes, else none.
std::optional<Stamp> DecodeStamp(View bytes) noexcept;

/// A labelled signature as the key service returns it and as it travels:
/// the 32-byte stamp, then the signature.
struct StampedSignature {
  Stamp stamp;
  Bytes signature;
};
Bytes EncodeStamped(const StampedSignature& stamped);
std::optional<StampedSignature> DecodeStamped(View bytes);

/// What ML-DSA-87 signs for a labelled request, with context Domain(label): stamp || message.
Bytes MlDsa87AppMessage(const Stamp& stamp, View message);
/// What SQIsign-V signs: "FORTIS-SQI-APP" 0x00 len(D) D stamp message.
Bytes SqiSignAppMessage(std::string_view label, const Stamp& stamp, View message);
/// The digest secp256k1 signs: SHA-256("FORTIS-K1-APP" 0x00 len(D) D stamp message).
std::array<uint8_t, 32> Secp256k1AppDigest(std::string_view label, const Stamp& stamp, View message);

/// Check a labelled signature and its stamp. False for any malformed input; never throws.
bool Verify(Algorithm algorithm, View public_key, std::string_view label, View message, const Stamp& stamp,
            View signature) noexcept;
/// The same, for a stamped signature as it travels (EncodeStamped).
bool Verify(Algorithm algorithm, View public_key, std::string_view label, View message, View stamped) noexcept;
}  // namespace fortis::keys

/// The unlabelled building blocks. The node needs only the Verify functions;
/// the others are for the key service and the tests. None of them allocates
/// secret memory: the caller provides where secrets go.
namespace fortis::keys::primitives {
/// Fill with bytes from the kernel's random number generator. Aborts if there are none.
void FillRandom(std::span<uint8_t> output) noexcept;

/// With a seed, the key pair FIPS 204 ML-DSA.KeyGen_internal derives from it; without, a random one.
bool MlDsa87KeyPair(std::span<uint8_t, 2592> public_key, std::span<uint8_t, 4896> secret_key,
                    const std::array<uint8_t, 32>* seed = nullptr) noexcept;
/// Hedged signing (fresh randomness for each signature). Context: at most 255 bytes.
bool MlDsa87Sign(std::span<uint8_t, 4627> signature, View message, View context, View secret_key) noexcept;
/// Deterministic signing with the given randomness: for the NIST known-answer tests only.
bool MlDsa87SignWith(const std::array<uint8_t, 32>& randomness, std::span<uint8_t, 4627> signature, View message,
                     View context, View secret_key) noexcept;
bool MlDsa87Verify(View signature, View message, View context, View public_key) noexcept;

bool SqiSignVKeyPair(std::span<uint8_t, 169> public_key, std::span<uint8_t, 549> secret_key) noexcept;
bool SqiSignVSign(std::span<uint8_t, 406> signature, View message, View secret_key) noexcept;
bool SqiSignVVerify(View signature, View message, View public_key) noexcept;

/// A random secret scalar in [1, n-1] and its uncompressed public point (0x04 x y).
bool Secp256k1KeyPair(std::span<uint8_t, 65> public_key, std::span<uint8_t, 32> secret_key) noexcept;
/// The uncompressed public point of a secret scalar; false if it is not in [1, n-1].
bool Secp256k1PublicKey(std::span<uint8_t, 65> public_key, View secret_key) noexcept;
/// Deterministic ECDSA (RFC 6979) over a 32-byte digest, low s, strict DER. Returns the length written.
size_t Secp256k1SignDigest(std::span<uint8_t, 72> signature, View digest, View secret_key) noexcept;
/// Accepts only strict DER with a low s, over a valid uncompressed public point.
bool Secp256k1VerifyDigest(View signature, View digest, View public_key) noexcept;

/// A labelled, stamped signature with this secret key: what the key service
/// makes for a Sign request. Empty if the algorithm failed.
Bytes SignLabelled(Algorithm algorithm, View secret_key, std::string_view label, const Stamp& stamp, View message);
}  // namespace fortis::keys::primitives
