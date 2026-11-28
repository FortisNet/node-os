// Tests of the key algorithms (docs/fortis-did.md, sections 6 and 11).
//
//   keys_test            the unit tests below
//   keys_test vectors    known-answer cases on standard input, one per line,
//                        from tests/crypto_vectors_test.py:
//     K seed pk sk                  ML-DSA-87 key generation from a seed
//     S rnd sk context message sig  ML-DSA-87 signing with given randomness
//     V pk context message sig 1|0  ML-DSA-87 verification and its verdict
//     Q pk message sig 1|0          SQIsign-V verification and its verdict
//   Fields are hex; "-" is empty.
#include "key_algorithms.h"
#include "key_store.h"
#include "signing_log.h"

#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace fortis::keys;
namespace p = fortis::keys::primitives;

namespace {
int failures = 0;

void Expect(bool condition, const char* what) {
  if (!condition) {
    std::fprintf(stderr, "FAILED: %s\n", what);
    ++failures;
  }
}

Bytes Hex(std::string_view text) {
  if (text == "-") return {};
  Bytes out;
  if (text.size() % 2) std::abort();
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    std::abort();
  };
  for (size_t i = 0; i < text.size(); i += 2)
    out.push_back(static_cast<uint8_t>(nibble(text[i]) << 4 | nibble(text[i + 1])));
  return out;
}

View Text(std::string_view text) { return {reinterpret_cast<const uint8_t*>(text.data()), text.size()}; }

// A stamp as the key service would make one.
const Stamp kStamp{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, 42, 1764000000};

// A labelled signature made exactly as the key service makes it.
Bytes SignLabelled(Algorithm algorithm, View secret, std::string_view label, View message,
                   const Stamp& stamp = kStamp) {
  return p::SignLabelled(algorithm, secret, label, stamp, message);
}

struct Pair {
  Bytes pub, secret;
};
Pair Generate(Algorithm algorithm) {
  const auto sizes = SizesOf(algorithm);
  Pair pair{Bytes(sizes.public_key), Bytes(sizes.secret_key)};
  bool ok = false;
  switch (algorithm) {
    case Algorithm::MlDsa87:
      ok = p::MlDsa87KeyPair(std::span<uint8_t, 2592>(pair.pub), std::span<uint8_t, 4896>(pair.secret));
      break;
    case Algorithm::SqiSignV:
      ok = p::SqiSignVKeyPair(std::span<uint8_t, 169>(pair.pub), std::span<uint8_t, 549>(pair.secret));
      break;
    case Algorithm::Secp256k1:
      ok = p::Secp256k1KeyPair(std::span<uint8_t, 65>(pair.pub), std::span<uint8_t, 32>(pair.secret));
      break;
  }
  Expect(ok, "key generation");
  return pair;
}

void Labels() {
  Expect(ValidLabel("gossip"), "plain label");
  Expect(ValidLabel("a.b_c-9"), "label with punctuation");
  Expect(ValidLabel(std::string(64, 'x')), "64-byte label");
  Expect(!ValidLabel(""), "empty label refused");
  Expect(!ValidLabel(std::string(65, 'x')), "65-byte label refused");
  Expect(!ValidLabel("Gossip"), "upper case refused");
  Expect(!ValidLabel("a/b"), "slash refused");
  Expect(!ValidLabel(std::string_view("a\0b", 3)), "NUL refused");
  const auto domain = Domain("gossip");
  Expect(std::string(domain.begin(), domain.end()) == "fortis/app/gossip", "domain string");
  // The length prefix keeps (label, message) pairs apart: "ab"+"c" is not "a"+"bc".
  Expect(SqiSignAppMessage("ab", kStamp, Text("c")) != SqiSignAppMessage("a", kStamp, Text("bc")), "SQIsign framing");
  Expect(Secp256k1AppDigest("ab", kStamp, Text("c")) != Secp256k1AppDigest("a", kStamp, Text("bc")),
         "secp256k1 framing");
  // The stamp: 32 bytes, machine, then sequence and time big-endian, and back.
  const auto encoded = EncodeStamp(kStamp);
  Expect(encoded[16 + 7] == 42 && encoded[15] == 16, "stamp layout");
  Expect(DecodeStamp(encoded) == kStamp, "stamp round trip");
  Expect(!DecodeStamp(View(encoded).first(31)), "short stamp refused");
  const StampedSignature stamped{kStamp, Bytes{9, 8, 7}};
  const auto travelled = DecodeStamped(EncodeStamped(stamped));
  Expect(travelled && travelled->stamp == kStamp && travelled->signature == stamped.signature,
         "stamped signature round trip");
  Expect(!DecodeStamped(View(encoded)), "a stamp alone is not a stamped signature");
  Expect(AlgorithmFrom(1) == Algorithm::MlDsa87 && AlgorithmFrom(3) == Algorithm::Secp256k1, "wire numbers");
  Expect(!AlgorithmFrom(0) && !AlgorithmFrom(4), "unknown wire numbers");
}

void RoundTrips() {
  const auto message = Text("block 1042 received");
  for (const auto algorithm : kAlgorithms) {
    const std::string name(Name(algorithm));
    const auto pair = Generate(algorithm);
    const auto sig = SignLabelled(algorithm, pair.secret, "gossip", message);
    Expect(!sig.empty(), (name + ": signs").c_str());
    Expect(Verify(algorithm, pair.pub, "gossip", message, kStamp, sig), (name + ": verifies").c_str());
    Expect(Verify(algorithm, pair.pub, "gossip", message, EncodeStamped({kStamp, sig})),
           (name + ": verifies as it travels").c_str());
    for (const auto& changed :
         {Stamp{kStamp.machine, kStamp.sequence + 1, kStamp.time},
          Stamp{kStamp.machine, kStamp.sequence, kStamp.time + 1}, Stamp{{}, kStamp.sequence, kStamp.time}})
      Expect(!Verify(algorithm, pair.pub, "gossip", message, changed, sig), (name + ": changed stamp refused").c_str());
    Expect(!Verify(algorithm, pair.pub, "gossip2", message, kStamp, sig), (name + ": other label refused").c_str());
    Expect(!Verify(algorithm, pair.pub, "gossip", Text("block 1043 received"), kStamp, sig),
           (name + ": other message refused").c_str());
    Expect(!Verify(algorithm, pair.pub, "Bad label", message, kStamp, sig), (name + ": invalid label refused").c_str());
    auto bent = sig;
    bent[bent.size() / 2] ^= 1;
    Expect(!Verify(algorithm, pair.pub, "gossip", message, kStamp, bent),
           (name + ": changed signature refused").c_str());
    const auto other = Generate(algorithm);
    Expect(!Verify(algorithm, other.pub, "gossip", message, kStamp, sig), (name + ": other key refused").c_str());
    Expect(!Verify(algorithm, pair.pub, "gossip", message, kStamp, View(sig).first(sig.size() - 1)),
           (name + ": short signature refused").c_str());
  }
}

// An unlabelled signature, the kind the protocol messages use, is never a valid labelled one.
void DomainSeparation() {
  const auto message = Text("FORTIS-FIVE-SIGNATURE-HELLO-v1 transcript");
  const auto ml = Generate(Algorithm::MlDsa87);
  Bytes raw(kMlDsa87Sizes.signature);
  Expect(p::MlDsa87Sign(std::span<uint8_t, 4627>(raw), message, {}, ml.secret), "ML-DSA empty-context signature");
  Expect(p::MlDsa87Verify(raw, message, {}, ml.pub), "ML-DSA empty context verifies raw");
  Expect(!Verify(Algorithm::MlDsa87, ml.pub, "x", message, kStamp, raw), "ML-DSA raw is not labelled");
  const auto labelled = SignLabelled(Algorithm::MlDsa87, ml.secret, "x", message);
  Expect(!p::MlDsa87Verify(labelled, message, {}, ml.pub), "ML-DSA labelled is not raw");

  const auto k1 = Generate(Algorithm::Secp256k1);
  std::array<uint8_t, 32> digest{};
  digest.fill(0x42);
  Bytes sig(72);
  sig.resize(p::Secp256k1SignDigest(std::span<uint8_t, 72>(sig), digest, k1.secret));
  Expect(p::Secp256k1VerifyDigest(sig, digest, k1.pub), "secp256k1 raw digest verifies");
  Expect(!Verify(Algorithm::Secp256k1, k1.pub, "x", digest, kStamp, sig), "secp256k1 raw digest is not labelled");
}

void Secp256k1Vectors() {
  // The secret scalar 1 has the generator as its public point.
  const auto one = Hex("0000000000000000000000000000000000000000000000000000000000000001");
  Bytes pub(65);
  Expect(p::Secp256k1PublicKey(std::span<uint8_t, 65>(pub), one), "public key of 1");
  Expect(pub == Hex("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
                    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
         "public key of 1 is the generator");
  Expect(!p::Secp256k1PublicKey(std::span<uint8_t, 65>(pub), Bytes(32, 0)), "zero secret refused");
  Expect(!p::Secp256k1PublicKey(std::span<uint8_t, 65>(pub),
                                Hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")),  // n itself
         "secret n refused");

  // RFC 6979 with SHA-256, the widely published case: secret 1, message "Satoshi Nakamoto".
  Bytes digest(32);
  {
    const auto m = Text("Satoshi Nakamoto");
    (void)mbedtls_sha256(m.data(), m.size(), digest.data(), 0);
  }
  Bytes sig(72);
  sig.resize(p::Secp256k1SignDigest(std::span<uint8_t, 72>(sig), digest, one));
  // r has its top bit set, so DER gives it a leading zero byte; s does not.
  const auto expected =
      Hex("3045"
          "022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
          "02202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5");
  Expect(sig == expected, "RFC 6979 signature of \"Satoshi Nakamoto\" with secret 1");
  const auto g =
      Hex("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
          "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
  Expect(p::Secp256k1VerifyDigest(expected, digest, g), "it verifies");

  // The same signature with a high s (n - s) is valid ECDSA, and refused.
  const auto high =
      Hex("3046"
          "022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
          "022100dbbd3162d46e9f9bef7feb87c16dc13b4f6568a87f4e83f728e2443ba586675c");
  Expect(!p::Secp256k1VerifyDigest(high, digest, g), "high s refused");
  // Not minimal: a zero byte before s, whose top bit is clear.
  const auto padded =
      Hex("3046"
          "022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
          "0221002442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5");
  Expect(!p::Secp256k1VerifyDigest(padded, digest, g), "non-minimal integer refused");
  // Negative: r without its leading zero byte.
  const auto negative =
      Hex("3044"
          "0220934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
          "02202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5");
  Expect(!p::Secp256k1VerifyDigest(negative, digest, g), "negative integer refused");
  auto trailing = expected;
  trailing.push_back(0);
  Expect(!p::Secp256k1VerifyDigest(trailing, digest, g), "trailing byte refused");
  auto compressed = g;
  compressed[0] = 0x02;
  Expect(!p::Secp256k1VerifyDigest(expected, digest, compressed), "compressed public key refused");
}

// The pq2 identity of the identity prototype, from a fixed master. The
// expected values were computed independently of this code: the ML-DSA-87
// key with OpenSSL 3.6 from the derived seed, HKDF and secp256k1 in plain
// Python, and the manifest and DID by the prototype's format
// (docs/THREE-ROLE-PQ2.md). The SQIsign root is random in a real identity, so
// a fixed stand-in (169 bytes of 0x5a) takes its place here.
void Pq2Compatibility() {
  Bytes master(32);
  for (size_t i = 0; i < 32; ++i) master[i] = static_cast<uint8_t>(7 * i + 1);
  std::array<uint8_t, 32> seed{};
  Derive(master, "pq2:did-update:ML-DSA-87", seed);
  Expect(Bytes(seed.begin(), seed.end()) == Hex("331718734d78c81d228b4013990f908f58e41126380e39f331339e35dbc42fa9"),
         "pq2: ML-DSA-87 seed from the master");
  const auto update = DeriveUpdateRoot(master);
  std::array<uint8_t, 32> digest{};
  (void)mbedtls_sha256(update.public_key.data(), update.public_key.size(), digest.data(), 0);
  Expect(Bytes(digest.begin(), digest.end()) == Hex("f65a37c16a1b0fe22e5cc10cfab6982ffd002d89660bd4b32c4ae27db7e3e0fc"),
         "pq2: ML-DSA-87 root is the one OpenSSL makes from that seed");
  const auto account = DeriveAccount(master);
  Expect(account.public_key == Hex("04ace2ae158fdb66c6680fd68f7e9d13286ea29c6b6e8d6dc75eded0701c6cf4dd"
                                   "65f0d6dd9882029ba511fdccb103024516f76fb7be33f052e065ca3991686b56"),
         "pq2: secp256k1 account key from the master");
  const Bytes sqisign(169, 0x5a);
  const auto manifest = Manifest(account.public_key, sqisign, update.public_key);
  const auto parsed = ParseManifest(manifest);
  Expect(parsed && parsed->update_root == update.public_key && parsed->account == account.public_key &&
             parsed->network_root == sqisign,
         "pq2: the manifest parses back to its keys");
  auto trailing = manifest;
  trailing.push_back(0);
  Expect(!ParseManifest(trailing), "pq2: a manifest with trailing bytes is refused");
  Expect(DidOf(Manifest(account.public_key, sqisign, update.public_key)) ==
             "did:fortis:pq2:fd0f984a85b4aa7dc58f8b8bfdc964af964b82753af89cbe4b9c5fe83890134144db7ecbaa0f4cc9bf"
             "2351c430e15a1ed6e81577e2c5fc36b8cfa0d5c4db62f0",
         "pq2: manifest and DID");
}

// A checkpoint signed as the key service signs it, with this machine key.
Bytes SignCheckpoint(const Pair& machine, const Checkpoint& checkpoint) {
  auto out = CheckpointBody(checkpoint);
  Bytes sig(kMlDsa87Sizes.signature);
  const std::string_view context = "fortis/signing-log";
  Expect(p::MlDsa87Sign(std::span<uint8_t, 4627>(sig), out, Text(context), machine.secret), "checkpoint signs");
  out.insert(out.end(), sig.begin(), sig.end());
  return out;
}

std::array<uint8_t, 16> MachineId(View public_key) {
  std::array<uint8_t, 64> digest{};
  (void)mbedtls_sha512(public_key.data(), public_key.size(), digest.data(), 0);
  std::array<uint8_t, 16> id{};
  std::copy(digest.begin(), digest.begin() + 16, id.begin());
  return id;
}

// The signing log: what the key service writes, and what other nodes check (section 11).
void SigningLogs() {
  char folder_template[] = "/tmp/fortis-keys-test-XXXXXX";
  const char* made = ::mkdtemp(folder_template);
  Expect(made != nullptr, "temporary folder");
  if (!made) return;
  const std::filesystem::path folder = made;
  const auto machine = Generate(Algorithm::MlDsa87);
  const auto id = MachineId(machine.pub);
  const auto messages = {Text("first"), Text("second"), Text("third"), Text("fourth")};
  std::vector<Stamp> stamps;
  {
    SigningLog log(folder, id);
    Expect(log.Last() == 0 && log.HeadAt(0) == Hash{}, "a new log is empty");
    for (const auto message : messages) {
      const auto stamp = log.Record(Algorithm::SqiSignV, "gossip", message);
      Expect(stamp && stamp->machine == id, "an entry is recorded");
      if (stamp) stamps.push_back(*stamp);
    }
    Expect(stamps.size() == 4 && stamps[0].sequence == 1 && stamps[3].sequence == 4, "sequence numbers 1 to 4");
  }
  {
    SigningLog log(folder, id);  // reopened: it continues, and never reuses a number
    Expect(log.Last() == 4, "a reopened log keeps its entries");
    const auto stamp = log.Record(Algorithm::Secp256k1, "account-ping", Text("fifth"));
    Expect(stamp && stamp->sequence == 5, "a reopened log continues at 5");
    const auto all = log.Read(1, 100);
    Expect(all && all->entries.size() == 5 && all->previous == Hash{}, "all five entries are read");
    const auto head = log.HeadAt(5);
    Expect(head.has_value(), "the head after entry 5");
    const Checkpoint at5{id, 5, 1764000000, head.value_or(Hash{}), machine.pub};
    Expect(all && SegmentMatches(*all, at5), "the entries chain to the head");
    const auto tail = log.Read(3, 100);  // a peer checking only entries 3 to 5
    Expect(tail && tail->entries.size() == 3 && SegmentMatches(*tail, at5), "a later run of entries chains too");
    Expect(tail && Records(*tail, at5, Algorithm::SqiSignV, "gossip", Text("third"), stamps[2]),
           "the log records the third signature");
    Expect(tail && !Records(*tail, at5, Algorithm::SqiSignV, "gossip", Text("changed"), stamps[2]),
           "but not another message under its number");
    Expect(tail && !Records(*tail, at5, Algorithm::MlDsa87, "gossip", Text("third"), stamps[2]),
           "nor another algorithm");
    Expect(tail && !Records(*tail, at5, Algorithm::SqiSignV, "gossip", Text("first"), stamps[0]),
           "an entry outside the run is not shown recorded");
    if (tail) {
      auto forged = *tail;
      forged.entries[1].label = "other";
      Expect(!SegmentMatches(forged, at5), "a changed entry no longer chains to the head");
      auto shortened = *tail;
      shortened.entries.pop_back();
      Expect(!SegmentMatches(shortened, at5), "a run that stops short of the checkpoint does not match");
      const auto decoded = DecodeSegment(EncodeSegment(*tail));
      Expect(decoded && decoded->entries == tail->entries && decoded->previous == tail->previous,
             "a run of entries survives the wire");
    }
    Expect(!log.Read(6, 1) && !log.HeadAt(6), "nothing beyond the last entry");

    // Checkpoints: signed by the machine key; two at one number with different heads prove a clone.
    const auto signed5 = SignCheckpoint(machine, at5);
    const auto verified = VerifyCheckpoint(signed5);
    Expect(verified && verified->sequence == 5 && verified->head == at5.head, "a checkpoint verifies");
    auto bent = signed5;
    bent[40] ^= 1;
    Expect(!VerifyCheckpoint(bent), "a changed checkpoint is refused");
    auto other = at5;
    other.head[0] ^= 1;
    Expect(ProvesClone(signed5, SignCheckpoint(machine, other)), "two heads at one number prove a clone");
    Expect(!ProvesClone(signed5, signed5), "one checkpoint twice proves nothing");
    const auto stranger = Generate(Algorithm::MlDsa87);
    auto foreign = at5;
    foreign.machine_public_key = stranger.pub;  // someone else's key, claiming this machine ID
    Expect(!VerifyCheckpoint(SignCheckpoint(stranger, foreign)), "only the machine key signs for its machine ID");
  }
  // A record cut short by a crash is removed; a damaged one refuses the log.
  {
    std::ofstream(folder / "signing.log", std::ios::app | std::ios::binary) << "partial";
    SigningLog log(folder, id);
    Expect(log.Last() == 5, "a record cut short is removed");
    Expect(std::filesystem::file_size(folder / "signing.log") == 5 * SigningLog::kRecordSize, "and the file trimmed");
  }
  {
    std::fstream file(folder / "signing.log", std::ios::in | std::ios::out | std::ios::binary);
    file.seekp(2 * SigningLog::kRecordSize + 20);
    file.put('X');
  }
  bool refused = false;
  try {
    SigningLog log(folder, id);
  } catch (const std::exception&) { refused = true; }
  Expect(refused, "a damaged entry refuses the log");
  std::filesystem::remove_all(folder);
}

// The evidence other nodes can make from signatures alone.
void CloneEvidence() {
  const auto k1 = Generate(Algorithm::Secp256k1);
  auto record = [&k1](std::string_view message, const Stamp& stamp) {
    const Bytes m(message.begin(), message.end());
    return SignedRecord{Algorithm::Secp256k1, k1.pub, "vote", m,
                        EncodeStamped({stamp, SignLabelled(Algorithm::Secp256k1, k1.secret, "vote", m, stamp)})};
  };
  const auto a = record("block 7 is A", kStamp);
  const auto b = record("block 7 is B", kStamp);
  Expect(ProvesClone(a, b), "two signatures with one sequence number prove a clone");
  Expect(!ProvesClone(a, a), "one signature twice proves nothing");
  Expect(!ProvesClone(a, record("block 7 is B", Stamp{kStamp.machine, kStamp.sequence + 1, kStamp.time})),
         "different sequence numbers prove nothing");
  auto forged = b;
  forged.message.back() ^= 1;
  Expect(!ProvesClone(a, forged), "an invalid signature proves nothing");

  // Machine statements: the identity's ML-DSA-87 root vouches for a machine key.
  const auto root = Generate(Algorithm::MlDsa87);
  const auto machine = Generate(Algorithm::MlDsa87);
  const std::string did = "did:fortis:pq2:" + std::string(128, 'a');
  const MachineStatement statement{did, MachineId(machine.pub), machine.pub, 1764000000};
  auto signed_statement = StatementBody(statement);
  Bytes sig(kMlDsa87Sizes.signature);
  Expect(p::MlDsa87Sign(std::span<uint8_t, 4627>(sig), signed_statement, Text("fortis/machine-statement"), root.secret),
         "statement signs");
  signed_statement.insert(signed_statement.end(), sig.begin(), sig.end());
  const auto verified = VerifyStatement(signed_statement, root.pub, did);
  Expect(verified && verified->machine == statement.machine, "a machine statement verifies");
  Expect(!VerifyStatement(signed_statement, machine.pub, did), "only the identity's root makes one");
  Expect(!VerifyStatement(signed_statement, root.pub, "did:fortis:pq2:" + std::string(128, 'b')), "it names one DID");
  const Checkpoint checkpoint{statement.machine, 0, 1764000000, Hash{}, machine.pub};
  Expect(verified && VerifyCheckpoint(SignCheckpoint(machine, checkpoint), *verified).has_value(),
         "a checkpoint of the stated machine is tied to the identity");
  const auto stranger = Generate(Algorithm::MlDsa87);
  const Checkpoint foreign{MachineId(stranger.pub), 0, 1764000000, Hash{}, stranger.pub};
  Expect(verified && !VerifyCheckpoint(SignCheckpoint(stranger, foreign), *verified),
         "a checkpoint of another machine is not");
}

int Vectors() {
  std::string line;
  size_t number = 0, passed = 0;
  while (std::getline(std::cin, line)) {
    ++number;
    std::istringstream in(line);
    std::string kind;
    in >> kind;
    std::vector<std::string> f;
    for (std::string field; in >> field;) f.push_back(field);
    bool ok = false;
    if (kind == "K" && f.size() == 3) {
      const auto seed = Hex(f[0]);
      std::array<uint8_t, 32> s{};
      std::copy(seed.begin(), seed.end(), s.begin());
      Bytes pub(2592), secret(4896);
      ok = seed.size() == 32 &&
           p::MlDsa87KeyPair(std::span<uint8_t, 2592>(pub), std::span<uint8_t, 4896>(secret), &s) && pub == Hex(f[1]) &&
           secret == Hex(f[2]);
    } else if (kind == "S" && f.size() == 5) {
      const auto rnd = Hex(f[0]);
      std::array<uint8_t, 32> r{};
      std::copy(rnd.begin(), rnd.end(), r.begin());
      Bytes sig(4627);
      ok = rnd.size() == 32 && p::MlDsa87SignWith(r, std::span<uint8_t, 4627>(sig), Hex(f[3]), Hex(f[2]), Hex(f[1])) &&
           sig == Hex(f[4]);
    } else if (kind == "V" && f.size() == 5) {
      ok = p::MlDsa87Verify(Hex(f[3]), Hex(f[2]), Hex(f[1]), Hex(f[0])) == (f[4] == "1");
    } else if (kind == "Q" && f.size() == 4) {
      ok = p::SqiSignVVerify(Hex(f[2]), Hex(f[1]), Hex(f[0])) == (f[3] == "1");
    }
    if (ok) {
      ++passed;
    } else {
      std::fprintf(stderr, "FAILED: vector line %zu (%s)\n", number, kind.c_str());
    }
  }
  std::printf("%zu of %zu known-answer cases passed\n", passed, number);
  return passed == number && number > 0 ? 0 : 1;
}
}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "vectors") return Vectors();
    Labels();
    RoundTrips();
    DomainSeparation();
    Secp256k1Vectors();
    Pq2Compatibility();
    SigningLogs();
    CloneEvidence();
  } catch (const std::exception& e) {
    std::fprintf(stderr, "keys_test: %s\n", e.what());
    return 1;
  }
  if (failures) {
    std::fprintf(stderr, "keys_test: %d failed\n", failures);
    return 1;
  }
  std::printf("keys_test: all passed\n");
  return 0;
}
