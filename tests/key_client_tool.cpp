// A stand-in for the node in tests/key_service_test.py: it reaches the key
// service only through FORTIS_KEYS_FD and the client library, as the node does.
//
//   key_client_tool info        the DID, machine ID and algorithms
//   key_client_tool roundtrip   for each algorithm: public key, sign, verify,
//                               and a wrong label, message or key refused
//   key_client_tool parallel N  N threads, each on its own channel, sign at once
//   key_client_tool badlabel    a request with an invalid label is refused
//   key_client_tool audit       what a peer checks: from the manifest and the
//                               DID to the machine statement, a checkpoint and
//                               the log, and each signature found in it
#include "key_algorithms.h"
#include "key_client.h"
#include "key_log.h"

#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace fortis::keys;

namespace {
View Text(std::string_view text) { return {reinterpret_cast<const uint8_t*>(text.data()), text.size()}; }

int Check(bool condition, const char* what) {
  if (!condition) std::fprintf(stderr, "FAILED: %s\n", what);
  return condition ? 0 : 1;
}

int Info(Client& keys) {
  const auto info = keys.Info();
  std::printf("ready=%d\ndid=%s\nmachine=%s\nalgorithms=", info.ready ? 1 : 0, info.did.c_str(),
              info.machine_id.c_str());
  for (const auto algorithm : info.algorithms) std::printf("%d", static_cast<int>(algorithm));
  std::printf("\n");
  return 0;
}

int RoundTrip(Client& keys) {
  int failed = 0;
  const auto message = Text("block 1042 received");
  for (const auto algorithm : kAlgorithms) {
    const auto pub = keys.PublicKey(algorithm);
    const auto stamped = keys.Sign(algorithm, "test-roundtrip", message);
    const auto sig = EncodeStamped(stamped);
    const std::string name(Name(algorithm));
    failed += Check(pub.size() == SizesOf(algorithm).public_key, (name + " public key size").c_str());
    failed += Check(Verify(algorithm, pub, "test-roundtrip", message, sig), (name + " verifies").c_str());
    failed += Check(!Verify(algorithm, pub, "test-other", message, sig), (name + " other label refused").c_str());
    failed += Check(!Verify(algorithm, pub, "test-roundtrip", Text("block 1043"), sig),
                    (name + " other message refused").c_str());
    std::printf("%s public=%zu signature=%zu sequence=%llu ok\n", name.c_str(), pub.size(), stamped.signature.size(),
                static_cast<unsigned long long>(stamped.stamp.sequence));
  }
  return failed;
}

int Parallel(Client& keys, int count) {
  const auto pub = keys.PublicKey(Algorithm::SqiSignV);
  std::vector<Client> channels;
  channels.reserve(static_cast<size_t>(count));
  for (int i = 0; i < count; ++i) channels.push_back(keys.OpenChannel());
  std::vector<int> ok(static_cast<size_t>(count), 0);
  const auto start = std::chrono::steady_clock::now();
  std::vector<std::thread> threads;
  threads.reserve(static_cast<size_t>(count));
  for (int i = 0; i < count; ++i)
    threads.emplace_back([&, i] {
      try {
        const std::string text = "parallel " + std::to_string(i);
        const auto sig = channels[static_cast<size_t>(i)].Sign(Algorithm::SqiSignV, "test-parallel", Text(text));
        ok[static_cast<size_t>(i)] =
            Verify(Algorithm::SqiSignV, pub, "test-parallel", Text(text), sig.stamp, sig.signature) ? 1 : 0;
      } catch (const std::exception& e) { std::fprintf(stderr, "thread %d: %s\n", i, e.what()); }
    });
  for (auto& thread : threads) thread.join();
  const auto ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
  int good = 0;
  for (const int v : ok) good += v;
  std::printf("parallel signatures=%d verified=%d milliseconds=%lld\n", count, good, static_cast<long long>(ms));
  return Check(good == count, "every parallel signature verifies");
}

int Audit(Client& keys) {
  int failed = 0;
  // What a peer is given, and what it trusts: only the DID it expects.
  const auto expected_did = keys.Info().did;
  const auto manifest = keys.Manifest();
  failed += Check(DidOf(manifest) == expected_did, "the manifest hashes to the DID");
  const auto roots = ParseManifest(manifest);
  failed += Check(roots.has_value(), "the manifest parses");
  if (!roots) return failed;
  const auto statement = VerifyStatement(keys.MachineStatement(), roots->update_root, expected_did);
  failed += Check(statement.has_value(), "the machine statement is signed by the identity's root");
  if (!statement) return failed;

  // Three signatures, then a checkpoint that covers the last of them.
  struct Made {
    Algorithm algorithm;
    std::string message;
    StampedSignature stamped;
  };
  std::vector<Made> made;
  for (const auto algorithm : kAlgorithms) {
    const std::string message = "audited " + std::string(Name(algorithm));
    made.push_back({algorithm, message, keys.Sign(algorithm, "test-audit", Text(message))});
  }
  for (size_t i = 1; i < made.size(); ++i)
    failed += Check(made[i].stamped.stamp.sequence == made[i - 1].stamped.stamp.sequence + 1,
                    "sequence numbers follow each other");
  for (const auto& m : made)
    failed += Check(m.stamped.stamp.machine == statement->machine, "stamped with this machine");
  const uint64_t first = made.front().stamped.stamp.sequence, last = made.back().stamped.stamp.sequence;
  const auto checkpoint = VerifyCheckpoint(keys.Checkpoint(last), *statement);
  failed += Check(checkpoint && checkpoint->sequence == last, "the checkpoint is signed by the stated machine");
  const auto segment = DecodeSegment(keys.LogEntries(first, static_cast<uint16_t>(last - first + 1)));
  failed +=
      Check(segment && checkpoint && SegmentMatches(*segment, *checkpoint), "the entries chain to the checkpoint");
  if (!segment || !checkpoint) return failed;
  for (const auto& m : made)
    failed += Check(Records(*segment, *checkpoint, m.algorithm, "test-audit", Text(m.message), m.stamped.stamp),
                    "each signature is in the log");
  failed += Check(
      !Records(*segment, *checkpoint, made[0].algorithm, "test-audit", Text("never signed"), made[0].stamped.stamp),
      "a message never signed is not");
  const auto latest = VerifyCheckpoint(keys.Checkpoint(), *statement);
  failed += Check(latest && latest->sequence >= last, "the latest checkpoint covers them");
  std::printf("audit first=%llu last=%llu machine=%s ok\n", static_cast<unsigned long long>(first),
              static_cast<unsigned long long>(last), keys.Info().machine_id.c_str());
  return failed;
}

int BadLabel(Client& keys) {
  try {
    (void)keys.Sign(Algorithm::Secp256k1, "Not Valid", Text("x"));
  } catch (const std::exception&) {
    std::printf("refused\n");
    return 0;
  }
  return Check(false, "an invalid label is refused");
}
}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) return 2;
  try {
    Client keys = Client::FromEnvironment();
    const std::string_view command = argv[1];
    if (command == "info") return Info(keys);
    if (command == "roundtrip") return RoundTrip(keys);
    if (command == "parallel" && argc == 3) {
      int count = 0;
      const std::string_view text = argv[2];
      const auto parsed = std::from_chars(text.data(), text.data() + text.size(), count);
      if (parsed.ec != std::errc() || parsed.ptr != text.data() + text.size() || count < 1 || count > 64) return 2;
      return Parallel(keys, count);
    }
    if (command == "badlabel") return BadLabel(keys);
    if (command == "audit") return Audit(keys);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "key_client_tool: %s\n", e.what());
    return 1;
  }
  return 2;
}
