#include "key_log.h"

#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

#include <cstring>

namespace fortis::keys {
namespace {
constexpr std::string_view kHeadTag = "FORTIS-SIGNING-LOG-v1";
constexpr std::string_view kCheckpointTag = "FORTIS-LOG-CHECKPOINT-v1";
constexpr std::string_view kCheckpointContext = "fortis/signing-log";
constexpr std::string_view kStatementTag = "FORTIS-MACHINE-STATEMENT-v1";
constexpr std::string_view kStatementContext = "fortis/machine-statement";
constexpr size_t kCheckpointSignature = kMlDsa87Sizes.signature;

void U32(Bytes& out, uint32_t v) {
  for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(v >> shift));
}
void U64(Bytes& out, uint64_t v) {
  for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(v >> shift));
}
void Field(Bytes& out, View v) {
  U32(out, static_cast<uint32_t>(v.size()));
  out.insert(out.end(), v.begin(), v.end());
}
View Text(std::string_view text) { return {reinterpret_cast<const uint8_t*>(text.data()), text.size()}; }

struct Reader {
  View data;
  size_t at = 0;
  bool ok = true;
  View Take(size_t n) {
    if (!ok || n > data.size() - at) {
      ok = false;
      return {};
    }
    auto out = data.subspan(at, n);
    at += n;
    return out;
  }
  uint64_t Number(int bytes) {
    uint64_t v = 0;
    for (const auto b : Take(static_cast<size_t>(bytes))) v = v << 8 | b;
    return v;
  }
};

bool MachineMatches(View key, const std::array<uint8_t, 16>& machine) {
  // The machine ID is the first 16 bytes of SHA-512 of the machine's public key.
  std::array<uint8_t, 64> digest{};
  (void)mbedtls_sha512(key.data(), key.size(), digest.data(), 0);
  return std::memcmp(digest.data(), machine.data(), 16) == 0;
}

bool TagIs(Reader& in, std::string_view tag) {
  const auto got = in.Take(static_cast<size_t>(in.Number(4)));
  return in.ok && std::string_view(reinterpret_cast<const char*>(got.data()), got.size()) == tag;
}

bool ReadEntry(Reader& in, LogEntry& entry) {
  entry.sequence = in.Number(8);
  entry.time = in.Number(8);
  const auto algorithm = AlgorithmFrom(static_cast<uint8_t>(in.Number(1)));
  const auto label = in.Take(static_cast<size_t>(in.Number(1)));
  const auto message = in.Take(32);
  if (!in.ok || !algorithm) return false;
  entry.algorithm = *algorithm;
  entry.label.assign(label.begin(), label.end());
  std::memcpy(entry.message.data(), message.data(), 32);
  return ValidLabel(entry.label);
}
}  // namespace

std::optional<ManifestKeys> ParseManifest(View manifest) noexcept {
  try {
    Reader in{manifest};
    const auto magic = in.Take(4);
    if (!in.ok || std::memcmp(magic.data(), "FDM2", 4) != 0) return std::nullopt;
    ManifestKeys keys;
    auto role = [&in](std::string_view name, Algorithm algorithm, Bytes& key) {
      if (!TagIs(in, name) || !TagIs(in, Name(algorithm))) return false;
      const auto value = in.Take(static_cast<size_t>(in.Number(4)));
      if (!in.ok || value.size() != SizesOf(algorithm).public_key) return false;
      key.assign(value.begin(), value.end());
      return true;
    };
    if (!role("evm-account", Algorithm::Secp256k1, keys.account) ||
        !role("fortisnet-network", Algorithm::SqiSignV, keys.network_root) ||
        !role("did-update", Algorithm::MlDsa87, keys.update_root) || in.at != manifest.size() ||
        keys.account[0] != 0x04)
      return std::nullopt;
    return keys;
  } catch (...) { return std::nullopt; }
}

std::string DidOf(View manifest) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::array<uint8_t, 64> digest{};
  (void)mbedtls_sha512(manifest.data(), manifest.size(), digest.data(), 0);
  std::string out = "did:fortis:pq2:";
  for (const auto b : digest) {
    out.push_back(kDigits[b >> 4]);
    out.push_back(kDigits[b & 15]);
  }
  return out;
}

Bytes EncodeEntry(const LogEntry& entry) {
  Bytes out;
  out.reserve(18 + entry.label.size() + 32);
  U64(out, entry.sequence);
  U64(out, entry.time);
  out.push_back(static_cast<uint8_t>(entry.algorithm));
  out.push_back(static_cast<uint8_t>(entry.label.size()));
  out.insert(out.end(), entry.label.begin(), entry.label.end());
  out.insert(out.end(), entry.message.begin(), entry.message.end());
  return out;
}

Hash NextHead(const Hash& previous, const LogEntry& entry) {
  Bytes input(kHeadTag.begin(), kHeadTag.end());
  input.push_back(0);
  input.insert(input.end(), previous.begin(), previous.end());
  const auto encoded = EncodeEntry(entry);
  input.insert(input.end(), encoded.begin(), encoded.end());
  Hash out{};
  (void)mbedtls_sha256(input.data(), input.size(), out.data(), 0);
  return out;
}

LogEntry EntryFor(const Stamp& stamp, Algorithm algorithm, std::string_view label, View message) {
  LogEntry entry{stamp.sequence, stamp.time, algorithm, std::string(label), {}};
  (void)mbedtls_sha256(message.data(), message.size(), entry.message.data(), 0);
  return entry;
}

Bytes StatementBody(const MachineStatement& statement) {
  Bytes out;
  Field(out, Text(kStatementTag));
  Field(out, Text(statement.did));
  out.insert(out.end(), statement.machine.begin(), statement.machine.end());
  Field(out, statement.machine_public_key);
  U64(out, statement.time);
  return out;
}

std::optional<MachineStatement> VerifyStatement(View bytes, View update_root, std::string_view did) noexcept {
  try {
    if (bytes.size() <= kCheckpointSignature) return std::nullopt;
    const auto body = bytes.first(bytes.size() - kCheckpointSignature);
    Reader in{body};
    if (!TagIs(in, kStatementTag)) return std::nullopt;
    MachineStatement statement;
    const auto named = in.Take(static_cast<size_t>(in.Number(4)));
    const auto machine = in.Take(16);
    const auto key = in.Take(static_cast<size_t>(in.Number(4)));
    statement.time = in.Number(8);
    if (!in.ok || in.at != body.size() || key.size() != kMlDsa87Sizes.public_key) return std::nullopt;
    statement.did.assign(named.begin(), named.end());
    std::memcpy(statement.machine.data(), machine.data(), 16);
    statement.machine_public_key.assign(key.begin(), key.end());
    if (statement.did != did || !MachineMatches(key, statement.machine)) return std::nullopt;
    if (!primitives::MlDsa87Verify(bytes.last(kCheckpointSignature), body, Text(kStatementContext), update_root))
      return std::nullopt;
    return statement;
  } catch (...) { return std::nullopt; }
}

Bytes CheckpointBody(const Checkpoint& checkpoint) {
  Bytes out;
  Field(out, Text(kCheckpointTag));
  out.insert(out.end(), checkpoint.machine.begin(), checkpoint.machine.end());
  U64(out, checkpoint.sequence);
  U64(out, checkpoint.time);
  out.insert(out.end(), checkpoint.head.begin(), checkpoint.head.end());
  Field(out, checkpoint.machine_public_key);
  return out;
}

std::optional<Checkpoint> VerifyCheckpoint(View bytes) noexcept {
  try {
    if (bytes.size() <= kCheckpointSignature) return std::nullopt;
    const auto body = bytes.first(bytes.size() - kCheckpointSignature);
    const auto signature = bytes.last(kCheckpointSignature);
    Reader in{body};
    if (!TagIs(in, kCheckpointTag)) return std::nullopt;
    Checkpoint checkpoint;
    const auto machine = in.Take(16);
    checkpoint.sequence = in.Number(8);
    checkpoint.time = in.Number(8);
    const auto head = in.Take(32);
    const auto key = in.Take(static_cast<size_t>(in.Number(4)));
    if (!in.ok || in.at != body.size() || key.size() != kMlDsa87Sizes.public_key) return std::nullopt;
    std::memcpy(checkpoint.machine.data(), machine.data(), 16);
    std::memcpy(checkpoint.head.data(), head.data(), 32);
    checkpoint.machine_public_key.assign(key.begin(), key.end());
    if (!MachineMatches(key, checkpoint.machine)) return std::nullopt;
    if (!primitives::MlDsa87Verify(signature, body, Text(kCheckpointContext), key)) return std::nullopt;
    return checkpoint;
  } catch (...) { return std::nullopt; }
}

std::optional<Checkpoint> VerifyCheckpoint(View bytes, const MachineStatement& statement) noexcept {
  auto checkpoint = VerifyCheckpoint(bytes);
  if (!checkpoint || checkpoint->machine != statement.machine ||
      checkpoint->machine_public_key != statement.machine_public_key)
    return std::nullopt;
  return checkpoint;
}

Bytes EncodeSegment(const LogSegment& segment) {
  Bytes out(segment.previous.begin(), segment.previous.end());
  out.push_back(static_cast<uint8_t>(segment.entries.size() >> 8));
  out.push_back(static_cast<uint8_t>(segment.entries.size()));
  for (const auto& entry : segment.entries) {
    const auto encoded = EncodeEntry(entry);
    out.insert(out.end(), encoded.begin(), encoded.end());
  }
  return out;
}

std::optional<LogSegment> DecodeSegment(View bytes) noexcept {
  try {
    Reader in{bytes};
    LogSegment segment;
    const auto previous = in.Take(32);
    const auto count = in.Number(2);
    if (!in.ok) return std::nullopt;
    std::memcpy(segment.previous.data(), previous.data(), 32);
    segment.entries.reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
      LogEntry entry;
      if (!ReadEntry(in, entry)) return std::nullopt;
      segment.entries.push_back(std::move(entry));
    }
    if (in.at != bytes.size()) return std::nullopt;
    return segment;
  } catch (...) { return std::nullopt; }
}

bool SegmentMatches(const LogSegment& segment, const Checkpoint& checkpoint) noexcept {
  try {
    if (segment.entries.empty()) return false;
    Hash head = segment.previous;
    uint64_t expected = segment.entries.front().sequence;
    if (expected == 0) return false;
    for (const auto& entry : segment.entries) {
      if (entry.sequence != expected++) return false;
      head = NextHead(head, entry);
    }
    return segment.entries.back().sequence == checkpoint.sequence && head == checkpoint.head;
  } catch (...) { return false; }
}

bool Records(const LogSegment& segment, const Checkpoint& checkpoint, Algorithm algorithm, std::string_view label,
             View message, const Stamp& stamp) noexcept {
  try {
    if (stamp.machine != checkpoint.machine || !SegmentMatches(segment, checkpoint)) return false;
    const auto wanted = EntryFor(stamp, algorithm, label, message);
    for (const auto& entry : segment.entries)
      if (entry.sequence == stamp.sequence) return entry == wanted;
    return false;
  } catch (...) { return false; }
}

bool ProvesClone(const SignedRecord& a, const SignedRecord& b) noexcept {
  try {
    const auto sa = DecodeStamped(a.stamped);
    const auto sb = DecodeStamped(b.stamped);
    if (!sa || !sb || sa->stamp.machine != sb->stamp.machine || sa->stamp.sequence != sb->stamp.sequence) return false;
    if (a.stamped == b.stamped && a.algorithm == b.algorithm && a.label == b.label && a.message == b.message)
      return false;  // the same signature, shown twice
    return Verify(a.algorithm, a.public_key, a.label, a.message, a.stamped) &&
           Verify(b.algorithm, b.public_key, b.label, b.message, b.stamped);
  } catch (...) { return false; }
}

bool ProvesClone(View checkpoint_a, View checkpoint_b) noexcept {
  const auto a = VerifyCheckpoint(checkpoint_a);
  const auto b = VerifyCheckpoint(checkpoint_b);
  return a && b && a->machine == b->machine && a->sequence == b->sequence && a->head != b->head;
}
}  // namespace fortis::keys
