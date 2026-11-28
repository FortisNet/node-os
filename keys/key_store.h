#pragma once
// The keys a host holds, and the files they rest in (docs/fortis-did.md,
// sections 7 and 13.3). Only fortis-keyd uses this.
#include "key_algorithms.h"
#include "key_log.h"
#include "file_descriptor.h"
#include "secret_memory.h"

#include <cstdint>
#include <filesystem>
#include <string>

namespace fortis::keys {
struct KeyPair {
  Algorithm algorithm = Algorithm::MlDsa87;
  Bytes public_key;
  SecretBytes secret_key;
};

/// The node identity, in the pq2 format of the identity prototype: a 32-byte
/// master from which the ML-DSA-87 root and the secp256k1 account key are
/// derived, an independently random SQIsign root, and the runtime keys.
struct Identity {
  SecretBytes master;
  KeyPair update_root;   // ML-DSA-87, in the manifest; never used for the node
  KeyPair network_root;  // SQIsign-V, in the manifest; never used for the node
  KeyPair account;       // secp256k1, in the manifest
  KeyPair runtime_mldsa;
  KeyPair runtime_sqisign;
  int64_t runtime_issued = 0;  // Unix seconds when the runtime keys were made
  Bytes manifest;              // the canonical public manifest, "FDM2"
  std::string did;             // did:fortis:pq2:<SHA-512 of the manifest, hex>

  /// The key a labelled request with this algorithm is signed with.
  const KeyPair& ForNode(Algorithm algorithm) const noexcept;
};

/// The machine key: made once per installation, never exported.
struct Machine {
  KeyPair key;                         // ML-DSA-87
  std::string id;                      // first 16 bytes of SHA-512 of the public key, hex
  std::array<uint8_t, 16> id_bytes{};  // the same 16 bytes
};

/// The ML-DSA-87 root the master derives: its key generation seed is
/// HKDF(master, "pq2:did-update:ML-DSA-87"), as in the identity prototype.
KeyPair DeriveUpdateRoot(View master);
/// The account key the master derives: the first HKDF(master,
/// "evm:secp256k1:i") that is a valid scalar, as in the identity prototype.
KeyPair DeriveAccount(View master);
/// HKDF-SHA-512 with the identity prototype's salt, 32 bytes out.
void Derive(std::span<const uint8_t> master, std::string_view label, std::span<uint8_t, 32> out);
/// The pq2 public manifest of these three root public keys.
Bytes Manifest(View account, View network_root, View update_root);
std::string Hex(View bytes);

class KeyStore {
 public:
  /// Opens the store in this folder and holds a lock on it while it lives.
  /// On the first start, when the folder holds nothing, creates the machine
  /// key and the identity. A machine key without an identity is refused, so
  /// a lost identity is never silently replaced by a new DID. The folder must
  /// belong to this user and be mode 0700; it is created so if missing.
  /// Throws std::runtime_error.
  static KeyStore Open(const std::filesystem::path& folder);

  const Identity& identity() const noexcept { return identity_; }
  const Machine& machine() const noexcept { return machine_; }
  /// Whether this Open created the identity: the first start.
  bool created() const noexcept { return created_; }
  /// Whether this Open created the machine key.
  bool new_machine() const noexcept { return new_machine_; }

 private:
  base::FileDescriptor lock_;
  Identity identity_;
  Machine machine_;
  bool created_ = false;
  bool new_machine_ = false;
};
}  // namespace fortis::keys
