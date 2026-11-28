#pragma once
// The node's side of the key service (docs/fortis-did.md, section 12).
//
// A Client owns one connection. Requests on one connection are answered one
// at a time, so a Client is not shared between threads: a thread that signs
// takes its own with OpenChannel(). Every failure, including a refusal, throws
// std::runtime_error; nothing is retried here. A refusal (busy, bad request)
// leaves the channel usable; a failure of the stream itself closes it, and
// every later call on it fails: open a new channel then.
//
// Verify() keeps large values on the stack: ML-DSA-87 and SQIsign-V
// verification crash with a 64 KiB stack and were measured to work with
// 128 KiB. Call it from threads with at least 256 KiB of stack.
#include "key_algorithms.h"
#include "key_log.h"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace fortis::keys {
struct ServiceInfo {
  bool ready = false;
  std::string did;
  std::string machine_id;
  std::vector<Algorithm> algorithms;
};

class Client {
 public:
  /// The connection named by the environment variable FORTIS_KEYS_FD.
  static Client FromEnvironment();
  /// Take ownership of a connected Unix stream socket.
  explicit Client(int descriptor);
  ~Client();
  Client(Client&& other) noexcept;
  Client& operator=(Client&& other) noexcept;
  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;

  ServiceInfo Info();
  /// The public key requests with this algorithm are signed with.
  Bytes PublicKey(Algorithm algorithm);
  /// A signature for this purpose, with the stamp the key service put on it
  /// (which machine, which signature number, when). Send both: EncodeStamped().
  /// Check it with Verify() and the same label.
  StampedSignature Sign(Algorithm algorithm, std::string_view label, View message);
  StampedSignature Sign(Algorithm algorithm, std::string_view label, std::span<const std::byte> message) {
    return Sign(algorithm, label, View(reinterpret_cast<const uint8_t*>(message.data()), message.size()));
  }

  // What the node relays to peers so they can check its signatures (section 11.5).
  // All of it is public; check it with the functions of key_log.h.
  /// The identity's public manifest: it hashes to the DID.
  Bytes Manifest();
  /// This machine's statement, signed by the identity's ML-DSA-87 root.
  Bytes MachineStatement();
  /// A checkpoint of the signing log after entry `at`; 0 for the latest.
  Bytes Checkpoint(uint64_t at = 0);
  /// Up to 256 log entries from `from`, with the head before them.
  Bytes LogEntries(uint64_t from, uint16_t count);
  /// A second, independent connection, for another thread.
  Client OpenChannel();

 private:
  Bytes Call(uint8_t operation, View body, int* received_descriptor = nullptr);
  void Drop() noexcept;
  int fd_ = -1;
  uint32_t next_id_ = 0;
};
}  // namespace fortis::keys
