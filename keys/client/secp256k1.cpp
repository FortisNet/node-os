// secp256k1 ECDSA through Mbed TLS, which this repository already builds.
//
// Signatures are deterministic (RFC 6979), have a low s (s <= n/2, as
// Ethereum and the identity prototype require) and are strict DER. Mbed TLS
// does neither the low s nor the DER checks itself, so they are done here.
#include "key_algorithms.h"

#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/platform_util.h>

#include <cstring>

namespace fortis::keys::primitives {
namespace {
int Random(void*, unsigned char* output, size_t length) {
  FillRandom({output, length});
  return 0;
}

// Owners for the Mbed TLS objects, so every path frees and wipes them.
struct Group {
  mbedtls_ecp_group value;
  Group() { mbedtls_ecp_group_init(&value); }
  ~Group() { mbedtls_ecp_group_free(&value); }
  Group(const Group&) = delete;
  Group& operator=(const Group&) = delete;
  bool Load() { return mbedtls_ecp_group_load(&value, MBEDTLS_ECP_DP_SECP256K1) == 0; }
};
struct Number {
  mbedtls_mpi value;
  Number() { mbedtls_mpi_init(&value); }
  ~Number() { mbedtls_mpi_free(&value); }  // mbedtls_mpi_free wipes the limbs
  Number(const Number&) = delete;
  Number& operator=(const Number&) = delete;
};
struct Point {
  mbedtls_ecp_point value;
  Point() { mbedtls_ecp_point_init(&value); }
  ~Point() { mbedtls_ecp_point_free(&value); }
  Point(const Point&) = delete;
  Point& operator=(const Point&) = delete;
};

// One DER INTEGER holding a positive value of at most 32 bytes, minimally encoded.
size_t WriteInteger(uint8_t* out, const std::array<uint8_t, 32>& value) {
  size_t first = 0;
  while (first < 31 && value[first] == 0) ++first;
  const bool pad = value[first] & 0x80;
  const size_t length = 32 - first + (pad ? 1 : 0);
  out[0] = 0x02;
  out[1] = static_cast<uint8_t>(length);
  size_t at = 2;
  if (pad) out[at++] = 0;
  std::memcpy(out + at, value.data() + first, 32 - first);
  return 2 + length;
}

// Reads one strict DER INTEGER: positive, minimal, at most 32 value bytes.
bool ReadInteger(View in, size_t& at, std::array<uint8_t, 32>& value) {
  if (at + 2 > in.size() || in[at] != 0x02) return false;
  const size_t length = in[at + 1];
  at += 2;
  if (length == 0 || length > 33 || at + length > in.size()) return false;
  const uint8_t* bytes = in.data() + at;
  if (bytes[0] & 0x80) return false;                                    // negative
  if (length > 1 && bytes[0] == 0 && !(bytes[1] & 0x80)) return false;  // not minimal
  size_t skip = bytes[0] == 0 && length > 1 ? 1 : 0;
  if (length - skip > 32) return false;
  value.fill(0);
  std::memcpy(value.data() + 32 - (length - skip), bytes + skip, length - skip);
  at += length;
  return true;
}

bool LowS(const Group& group, const mbedtls_mpi& s) {
  Number half;
  return mbedtls_mpi_copy(&half.value, &group.value.N) == 0 && mbedtls_mpi_shift_r(&half.value, 1) == 0 &&
         mbedtls_mpi_cmp_mpi(&s, &half.value) <= 0;
}
}  // namespace

bool Secp256k1PublicKey(std::span<uint8_t, 65> public_key, View secret_key) noexcept {
  if (secret_key.size() != 32) return false;
  Group group;
  Number d;
  Point q;
  size_t length = 0;
  return group.Load() && mbedtls_mpi_read_binary(&d.value, secret_key.data(), 32) == 0 &&
         mbedtls_ecp_check_privkey(&group.value, &d.value) == 0 &&
         mbedtls_ecp_mul(&group.value, &q.value, &d.value, &group.value.G, Random, nullptr) == 0 &&
         mbedtls_ecp_point_write_binary(&group.value, &q.value, MBEDTLS_ECP_PF_UNCOMPRESSED, &length, public_key.data(),
                                        public_key.size()) == 0 &&
         length == 65;
}

bool Secp256k1KeyPair(std::span<uint8_t, 65> public_key, std::span<uint8_t, 32> secret_key) noexcept {
  Group group;
  Number d;
  if (!group.Load() || mbedtls_ecp_gen_privkey(&group.value, &d.value, Random, nullptr) != 0 ||
      mbedtls_mpi_write_binary(&d.value, secret_key.data(), secret_key.size()) != 0) {
    mbedtls_platform_zeroize(secret_key.data(), secret_key.size());
    return false;
  }
  if (Secp256k1PublicKey(public_key, secret_key)) return true;
  mbedtls_platform_zeroize(secret_key.data(), secret_key.size());
  return false;
}

size_t Secp256k1SignDigest(std::span<uint8_t, 72> signature, View digest, View secret_key) noexcept {
  if (digest.size() != 32 || secret_key.size() != 32) return 0;
  Group group;
  Number d, r, s;
  if (!group.Load() || mbedtls_mpi_read_binary(&d.value, secret_key.data(), 32) != 0 ||
      mbedtls_ecp_check_privkey(&group.value, &d.value) != 0 ||
      mbedtls_ecdsa_sign_det_ext(&group.value, &r.value, &s.value, &d.value, digest.data(), digest.size(),
                                 MBEDTLS_MD_SHA256, Random, nullptr) != 0)
    return 0;
  // Ethereum and the identity prototype accept only s <= n/2: use n - s otherwise.
  if (!LowS(group, s.value) && mbedtls_mpi_sub_mpi(&s.value, &group.value.N, &s.value) != 0) return 0;
  std::array<uint8_t, 32> rb{}, sb{};
  if (mbedtls_mpi_write_binary(&r.value, rb.data(), 32) != 0 || mbedtls_mpi_write_binary(&s.value, sb.data(), 32) != 0)
    return 0;
  uint8_t body[70];
  size_t length = WriteInteger(body, rb);
  length += WriteInteger(body + length, sb);
  signature[0] = 0x30;
  signature[1] = static_cast<uint8_t>(length);
  std::memcpy(signature.data() + 2, body, length);
  return 2 + length;
}

bool Secp256k1VerifyDigest(View signature, View digest, View public_key) noexcept {
  if (digest.size() != 32 || public_key.size() != 65 || public_key[0] != 0x04) return false;
  if (signature.size() < 8 || signature.size() > 72 || signature[0] != 0x30 || signature[1] != signature.size() - 2)
    return false;
  size_t at = 2;
  std::array<uint8_t, 32> rb{}, sb{};
  if (!ReadInteger(signature, at, rb) || !ReadInteger(signature, at, sb) || at != signature.size()) return false;
  Group group;
  Number r, s;
  Point q;
  return group.Load() && mbedtls_ecp_point_read_binary(&group.value, &q.value, public_key.data(), 65) == 0 &&
         mbedtls_ecp_check_pubkey(&group.value, &q.value) == 0 &&
         mbedtls_mpi_read_binary(&r.value, rb.data(), 32) == 0 &&
         mbedtls_mpi_read_binary(&s.value, sb.data(), 32) == 0 && LowS(group, s.value) &&
         mbedtls_ecdsa_verify(&group.value, digest.data(), 32, &q.value, &r.value, &s.value) == 0;
}
}  // namespace fortis::keys::primitives
