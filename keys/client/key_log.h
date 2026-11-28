#pragma once
// The signing log, as other nodes check it (docs/fortis-did.md, section 11).
//
// The key service writes one entry for every labelled signature before it
// makes it, chains the entries with SHA-256, and signs checkpoints of the
// chain with the machine key. Nothing here needs a secret: a node relays the
// log of its own key service, and any peer can check
//  - that a signature it holds is in that machine's log (an entry missing from
//    a log that covers its sequence number means the keys were used outside
//    the key service, so they were stolen);
//  - that two signatures, or two checkpoints, prove a cloned machine;
//  - how many signatures a machine has made, and when.
#include "key_algorithms.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace fortis::keys {
using Hash = std::array<uint8_t, 32>;

/// The public keys of a pq2 manifest (identity prototype, docs/THREE-ROLE-PQ2.md).
struct ManifestKeys {
  Bytes account;       // secp256k1, 65 bytes
  Bytes network_root;  // SQIsign-V, 169 bytes
  Bytes update_root;   // ML-DSA-87, 2,592 bytes
};
/// The keys of a canonical "FDM2" manifest: fixed roles, algorithms and order, no trailing bytes.
std::optional<ManifestKeys> ParseManifest(View manifest) noexcept;
/// did:fortis:pq2:<SHA-512 of the manifest, 128 lowercase hex characters>.
std::string DidOf(View manifest);

/// What the log records of one signature. The message itself is not kept, only its SHA-256.
struct LogEntry {
  uint64_t sequence = 0;
  uint64_t time = 0;
  Algorithm algorithm = Algorithm::MlDsa87;
  std::string label;
  Hash message{};  // SHA-256 of the signed message
  bool operator==(const LogEntry&) const = default;
};

/// seq u64 || time u64 || algorithm u8 || len(label) u8 || label || SHA-256(message)
Bytes EncodeEntry(const LogEntry& entry);
/// The head after this entry: SHA-256("FORTIS-SIGNING-LOG-v1" 0x00 || previous head || entry).
/// The head before the first entry (sequence 1) is 32 zero bytes.
Hash NextHead(const Hash& previous, const LogEntry& entry);
/// The entry a labelled request makes.
LogEntry EntryFor(const Stamp& stamp, Algorithm algorithm, std::string_view label, View message);

/** A machine statement: "machine X, with this machine key, holds DID d",
 * signed by the identity's ML-DSA-87 root (context "fortis/machine-statement"),
 * whose public key is in the DID's manifest. It is what ties a machine, and so
 * its checkpoints and log, to the identity: someone with stolen runtime keys
 * cannot make one, so cannot pass a log of their own off as the identity's. */
struct MachineStatement {
  std::string did;
  std::array<uint8_t, 16> machine{};
  Bytes machine_public_key;
  uint64_t time = 0;  // when it was signed
};
/// field("FORTIS-MACHINE-STATEMENT-v1") field(did) machine[16] field(machine public key) time u64
Bytes StatementBody(const MachineStatement& statement);
/// A statement as the key service returns it: its body, then the 4,627-byte
/// signature. Checks the signature with `update_root` (the manifest's ML-DSA-87
/// key, which the caller trusts because the manifest hashes to the DID), that
/// it names `did`, and that the machine ID is the hash of the machine key.
std::optional<MachineStatement> VerifyStatement(View bytes, View update_root, std::string_view did) noexcept;

/// A checkpoint: the head of a machine's log after a given entry, signed with
/// the machine key (ML-DSA-87, context "fortis/signing-log").
struct Checkpoint {
  std::array<uint8_t, 16> machine{};
  uint64_t sequence = 0;  // the last entry it covers; 0 for an empty log
  uint64_t time = 0;      // when the key service signed it
  Hash head{};
  Bytes machine_public_key;
};
/// The bytes a checkpoint signature covers:
/// field("FORTIS-LOG-CHECKPOINT-v1") machine[16] sequence u64 time u64 head[32] field(public key),
/// where field(x) is u32 length || x. It starts with 0x00, like every protocol message (section 11).
Bytes CheckpointBody(const Checkpoint& checkpoint);
/// A checkpoint as the key service returns it: its body, then the 4,627-byte
/// signature. Checks the signature and that the machine ID is the hash of the
/// public key. On its own this proves only that some machine key signed it:
/// the overload with a statement also ties it to the identity.
std::optional<Checkpoint> VerifyCheckpoint(View bytes) noexcept;
/// The checkpoint, if it is valid and made by the machine of this verified statement.
std::optional<Checkpoint> VerifyCheckpoint(View bytes, const MachineStatement& statement) noexcept;

/// A run of entries as the key service returns it:
/// head before the first entry [32] || count u16 || entries.
struct LogSegment {
  Hash previous{};
  std::vector<LogEntry> entries;
};
Bytes EncodeSegment(const LogSegment& segment);
std::optional<LogSegment> DecodeSegment(View bytes) noexcept;
/// True when the entries follow each other and end exactly at the
/// checkpoint's sequence number with its head: then every entry in the
/// segment is in that machine's log as it was when the checkpoint was signed.
bool SegmentMatches(const LogSegment& segment, const Checkpoint& checkpoint) noexcept;
/// Whether the log, as verified up to `checkpoint` by `segment`, records this
/// signature. A false answer with stamp.sequence inside the segment means the
/// signature was made outside the key service.
bool Records(const LogSegment& segment, const Checkpoint& checkpoint, Algorithm algorithm, std::string_view label,
             View message, const Stamp& stamp) noexcept;

/// A labelled signature with everything needed to check it.
struct SignedRecord {
  Algorithm algorithm = Algorithm::MlDsa87;
  Bytes public_key;
  std::string label;
  Bytes message;
  Bytes stamped;  // EncodeStamped(...)
};
/** Proof that two key services share one machine's keys: both signatures are
 * valid, carry the same machine ID and sequence number, and are not the same
 * signature. An honest key service never gives a sequence number twice.
 * The public keys must be the identity's, as the caller knows them (the
 * manifest's account key, or certified runtime keys): this checks only the
 * signatures, and anyone can sign a stamp with a key of their own. */
bool ProvesClone(const SignedRecord& a, const SignedRecord& b) noexcept;
/// The same proof from two valid checkpoints of one machine at one sequence
/// number with different heads. Only the machine key can sign a checkpoint for
/// its machine ID, so this needs no trusted key.
bool ProvesClone(View checkpoint_a, View checkpoint_b) noexcept;
}  // namespace fortis::keys
