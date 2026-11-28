#include "key_algorithms.h"

#include <mbedtls/sha256.h>

#include <algorithm>
#include <string_view>

namespace fortis::keys {
namespace {
constexpr std::string_view kDomainPrefix = "fortis/app/";
constexpr std::string_view kSqiTag = "FORTIS-SQI-APP";
constexpr std::string_view kSecp256k1Tag = "FORTIS-K1-APP";

void Append(Bytes& out, std::string_view text) { out.insert(out.end(), text.begin(), text.end()); }

// tag 0x00 len(D) D message: the length comes first, so two different
// (label, message) pairs never give the same bytes.
Bytes Tagged(std::string_view tag, std::string_view label, View message) {
  const auto domain = Domain(label);
  Bytes out;
  out.reserve(tag.size() + 2 + domain.size() + message.size());
  Append(out, tag);
  out.push_back(0);
  out.push_back(static_cast<uint8_t>(domain.size()));
  out.insert(out.end(), domain.begin(), domain.end());
  out.insert(out.end(), message.begin(), message.end());
  return out;
}
}  // namespace

std::optional<Algorithm> AlgorithmFrom(uint8_t number) noexcept {
  for (const auto algorithm : kAlgorithms)
    if (static_cast<uint8_t>(algorithm) == number) return algorithm;
  return std::nullopt;
}

std::string_view Name(Algorithm algorithm) noexcept {
  switch (algorithm) {
    case Algorithm::MlDsa87: return "ML-DSA-87";
    case Algorithm::SqiSignV: return "SQIsign-V-v3-p664_17";
    case Algorithm::Secp256k1: return "secp256k1";
  }
  return "unknown";
}

bool ValidLabel(std::string_view label) noexcept {
  if (label.empty() || label.size() > kLabelMax) return false;
  for (const char c : label)
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) return false;
  return true;
}

Bytes Domain(std::string_view label) {
  Bytes out;
  Append(out, kDomainPrefix);
  Append(out, label);
  return out;
}

std::array<uint8_t, kStampSize> EncodeStamp(const Stamp& stamp) noexcept {
  std::array<uint8_t, kStampSize> out{};
  std::copy(stamp.machine.begin(), stamp.machine.end(), out.begin());
  for (int i = 0; i < 8; ++i) {
    out[16 + i] = static_cast<uint8_t>(stamp.sequence >> (56 - 8 * i));
    out[24 + i] = static_cast<uint8_t>(stamp.time >> (56 - 8 * i));
  }
  return out;
}

std::optional<Stamp> DecodeStamp(View bytes) noexcept {
  if (bytes.size() != kStampSize) return std::nullopt;
  Stamp stamp;
  std::copy(bytes.begin(), bytes.begin() + 16, stamp.machine.begin());
  for (int i = 0; i < 8; ++i) {
    stamp.sequence = stamp.sequence << 8 | bytes[16 + static_cast<size_t>(i)];
    stamp.time = stamp.time << 8 | bytes[24 + static_cast<size_t>(i)];
  }
  return stamp;
}

Bytes EncodeStamped(const StampedSignature& stamped) {
  const auto stamp = EncodeStamp(stamped.stamp);
  Bytes out(stamp.begin(), stamp.end());
  out.insert(out.end(), stamped.signature.begin(), stamped.signature.end());
  return out;
}

std::optional<StampedSignature> DecodeStamped(View bytes) {
  if (bytes.size() <= kStampSize) return std::nullopt;
  const auto stamp = DecodeStamp(bytes.first(kStampSize));
  if (!stamp) return std::nullopt;
  return StampedSignature{*stamp, Bytes(bytes.begin() + kStampSize, bytes.end())};
}

Bytes MlDsa87AppMessage(const Stamp& stamp, View message) {
  const auto encoded = EncodeStamp(stamp);
  Bytes out(encoded.begin(), encoded.end());
  out.insert(out.end(), message.begin(), message.end());
  return out;
}

Bytes SqiSignAppMessage(std::string_view label, const Stamp& stamp, View message) {
  return Tagged(kSqiTag, label, MlDsa87AppMessage(stamp, message));
}

std::array<uint8_t, 32> Secp256k1AppDigest(std::string_view label, const Stamp& stamp, View message) {
  const auto input = Tagged(kSecp256k1Tag, label, MlDsa87AppMessage(stamp, message));
  std::array<uint8_t, 32> digest{};
  (void)mbedtls_sha256(input.data(), input.size(), digest.data(), 0);
  return digest;
}

bool Verify(Algorithm algorithm, View public_key, std::string_view label, View message, const Stamp& stamp,
            View signature) noexcept {
  if (!ValidLabel(label) || message.size() > kMessageMax) return false;
  try {
    switch (algorithm) {
      case Algorithm::MlDsa87:
        return primitives::MlDsa87Verify(signature, MlDsa87AppMessage(stamp, message), Domain(label), public_key);
      case Algorithm::SqiSignV:
        return primitives::SqiSignVVerify(signature, SqiSignAppMessage(label, stamp, message), public_key);
      case Algorithm::Secp256k1:
        return primitives::Secp256k1VerifyDigest(signature, Secp256k1AppDigest(label, stamp, message), public_key);
    }
  } catch (...) {
    // Only allocation can throw here; an unverifiable signature is not a valid one.
    return false;
  }
  return false;
}

bool Verify(Algorithm algorithm, View public_key, std::string_view label, View message, View stamped) noexcept {
  try {
    const auto decoded = DecodeStamped(stamped);
    return decoded && Verify(algorithm, public_key, label, message, decoded->stamp, decoded->signature);
  } catch (...) { return false; }
}

namespace primitives {
Bytes SignLabelled(Algorithm algorithm, View secret_key, std::string_view label, const Stamp& stamp, View message) {
  switch (algorithm) {
    case Algorithm::MlDsa87: {
      Bytes sig(kMlDsa87Sizes.signature);
      if (!MlDsa87Sign(std::span<uint8_t, 4627>(sig), MlDsa87AppMessage(stamp, message), Domain(label), secret_key))
        return {};
      return sig;
    }
    case Algorithm::SqiSignV: {
      Bytes sig(kSqiSignVSizes.signature);
      if (!SqiSignVSign(std::span<uint8_t, 406>(sig), SqiSignAppMessage(label, stamp, message), secret_key)) return {};
      return sig;
    }
    case Algorithm::Secp256k1: {
      Bytes sig(72);
      sig.resize(
          Secp256k1SignDigest(std::span<uint8_t, 72>(sig), Secp256k1AppDigest(label, stamp, message), secret_key));
      return sig;
    }
  }
  return {};
}
}  // namespace primitives
}  // namespace fortis::keys
