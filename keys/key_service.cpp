// fortis-keyd: the key service (docs/fortis-did.md).
//
//   fortis-keyd STORE_FOLDER SOCKET_FOLDER
//
// Opens (on the first start, creates) the keys in STORE_FOLDER and serves
// node channels on SOCKET_FOLDER/node.sock. The orchestrator connects there and
// hands each connection to the node; a node channel can ask for public keys
// and labelled signatures, and for another channel, never for a key.
//
// Runs as its own user, which owns both folders (mode 0700). Only that user
// and root may connect.
#include "key_policy.h"
#include "key_store.h"
#include "signing_log.h"
#include "key_wire.h"
#include "log.h"
#include "socket_io.h"

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <new>
#include <pthread.h>
#include <chrono>
#include <fcntl.h>
#include <filesystem>
#include <semaphore>
#include <string>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

namespace {
namespace fs = std::filesystem;
using namespace fortis::keys;
using fortis::base::LogError;
using fortis::base::LogInfo;
using fortis::base::LogWarn;
namespace p = fortis::keys::primitives;

// A node cannot hold more channels than this, so it cannot use up the service's threads.
constexpr int kChannelMax = 64;
// How long a signature waits for a free core before the answer is Busy.
constexpr auto kSigningWait = std::chrono::seconds(30);
constexpr int kSendTimeoutSeconds = 60;

std::atomic<int> g_channels{0};
// At most as many signatures at once as there are cores.
std::counting_semaphore<1024> g_signers{1};

struct Reply {
  wire::Result result = wire::Result::Ok;
  Bytes body;
  int attach = -1;  // a descriptor to send with the reply
};

Reply Refuse(wire::Result result) { return Reply{result, {}, -1}; }

bool PeerAllowed(int fd) {
#if defined(__linux__)
  ucred peer{};
  socklen_t size = sizeof(peer);
  if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0 || size != sizeof(peer)) return false;
  const uid_t user = peer.uid;
#else
  uid_t user = 0;
  gid_t group = 0;
  if (::getpeereid(fd, &user, &group) != 0) return false;
#endif
  return user == 0 || user == ::geteuid();
}

// What every channel thread shares. Built once at start, then only read,
// except the signing log, which has its own lock.
struct Service {
  const KeyStore& store;
  SigningLog& log;
  Bytes statement;  // this machine's statement, signed by the identity's ML-DSA-87 root
};

Reply Info(const Service& service) {
  const auto& identity = service.store.identity();
  Reply reply;
  auto text = [&reply](const std::string& value) {
    reply.body.push_back(static_cast<uint8_t>(value.size()));
    reply.body.insert(reply.body.end(), value.begin(), value.end());
  };
  reply.body.push_back(0);  // ready
  text(identity.did);
  text(service.store.machine().id);
  reply.body.push_back(static_cast<uint8_t>(kAlgorithms.size()));
  for (const auto algorithm : kAlgorithms) reply.body.push_back(static_cast<uint8_t>(algorithm));
  return reply;
}

uint64_t Number(View bytes) {
  uint64_t v = 0;
  for (const auto b : bytes) v = v << 8 | b;
  return v;
}

uint64_t Now() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

// Signed with the ML-DSA-87 root, so it ties this machine to the identity (section 11.4).
Bytes MachineStatementOf(const KeyStore& store) {
  const auto& identity = store.identity();
  const auto& machine = store.machine();
  const MachineStatement statement{identity.did, machine.id_bytes, machine.key.public_key, Now()};
  auto out = StatementBody(statement);
  Bytes signature(kMlDsa87Sizes.signature);
  static constexpr std::string_view kContext = "fortis/machine-statement";
  if (!p::MlDsa87Sign(std::span<uint8_t, 4627>(signature), out,
                      View(reinterpret_cast<const uint8_t*>(kContext.data()), kContext.size()),
                      identity.update_root.secret_key.Bytes()))
    throw std::runtime_error("cannot sign the machine statement");
  out.insert(out.end(), signature.begin(), signature.end());
  return out;
}

Reply MakeCheckpoint(const Service& service, uint64_t at) {
  const uint64_t last = service.log.Last();
  if (at == 0) at = last;
  if (at > last) return Refuse(wire::Result::BadRequest);
  const auto head = service.log.HeadAt(at);
  if (!head) return Refuse(wire::Result::Failed);
  const auto& machine = service.store.machine();
  const Checkpoint checkpoint{machine.id_bytes, at, Now(), *head, machine.key.public_key};
  auto out = CheckpointBody(checkpoint);
  Bytes signature(kMlDsa87Sizes.signature);
  static constexpr std::string_view kContext = "fortis/signing-log";
  if (!p::MlDsa87Sign(std::span<uint8_t, 4627>(signature), out,
                      View(reinterpret_cast<const uint8_t*>(kContext.data()), kContext.size()),
                      machine.key.secret_key.Bytes()))
    return Refuse(wire::Result::Failed);
  out.insert(out.end(), signature.begin(), signature.end());
  return Reply{wire::Result::Ok, std::move(out), -1};
}

void Serve(const Service* service, int fd);

// Take one of the kChannelMax places, atomically, or none.
bool TakeChannel() {
  if (g_channels.fetch_add(1) < kChannelMax) return true;
  --g_channels;
  return false;
}

// Every channel thread gets this much stack, whatever the C library's
// default: SQIsign signing needs more than musl's 128 KiB (kSigningStack,
// measured by tests/keys_test.cpp).
constexpr size_t kThreadStack = kSigningStack;

struct Channel {
  const Service* service;
  int fd;
};

void* RunChannel(void* argument) {
  const Channel channel = *static_cast<Channel*>(argument);
  delete static_cast<Channel*>(argument);
  Serve(channel.service, channel.fd);
  return nullptr;
}

// Serve fd on its own detached thread. On failure the caller still owns fd
// and the channel place.
bool StartChannel(const Service& service, int fd) {
  pthread_attr_t attributes;
  if (::pthread_attr_init(&attributes) != 0) return false;
  auto* channel = new (std::nothrow) Channel{&service, fd};
  pthread_t thread;
  const bool started = channel && ::pthread_attr_setstacksize(&attributes, kThreadStack) == 0 &&
                       ::pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) == 0 &&
                       ::pthread_create(&thread, &attributes, RunChannel, channel) == 0;
  (void)::pthread_attr_destroy(&attributes);
  if (!started) delete channel;
  return started;
}

// A new channel: one end is served here, the other goes back to the node.
Reply OpenChannel(const Service& service) {
  if (!TakeChannel()) return Refuse(wire::Result::Busy);
  int pair[2];
  if (::socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
    --g_channels;
    return Refuse(wire::Result::Unavailable);
  }
  for (const int fd : pair) (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
  if (!StartChannel(service, pair[0])) {
    --g_channels;
    (void)::close(pair[0]);
    (void)::close(pair[1]);
    return Refuse(wire::Result::Unavailable);
  }
  return Reply{wire::Result::Ok, {}, pair[1]};
}

Reply Dispatch(const Service& service, wire::Operation operation, View body) {
  const auto& identity = service.store.identity();
  switch (operation) {
    case wire::Operation::Info: return Info(service);
    case wire::Operation::PublicKey: {
      const auto algorithm = body.size() == 1 ? AlgorithmFrom(body[0]) : std::nullopt;
      if (!algorithm) return Refuse(wire::Result::BadRequest);
      return Reply{wire::Result::Ok, identity.ForNode(*algorithm).public_key, -1};
    }
    case wire::Operation::Sign: {
      if (body.size() < 2) return Refuse(wire::Result::BadRequest);
      const auto algorithm = AlgorithmFrom(body[0]);
      const size_t label_size = body[1];
      if (!algorithm || body.size() < 2 + label_size) return Refuse(wire::Result::BadRequest);
      const std::string_view label(reinterpret_cast<const char*>(body.data() + 2), label_size);
      const auto message = body.subspan(2 + label_size);
      if (!ValidLabel(label) || message.size() > kMessageMax) return Refuse(wire::Result::BadRequest);
      if (!g_signers.try_acquire_for(kSigningWait)) return Refuse(wire::Result::Busy);
      StampedSignature stamped;
      try {
        // Recorded on disk first: nothing is signed that the log does not show.
        if (const auto stamp = service.log.Record(*algorithm, label, message)) {
          stamped.stamp = *stamp;
          stamped.signature =
              p::SignLabelled(*algorithm, identity.ForNode(*algorithm).secret_key.Bytes(), label, *stamp, message);
        }
      } catch (...) { stamped.signature.clear(); }
      g_signers.release();
      if (stamped.signature.empty()) return Refuse(wire::Result::Failed);
      return Reply{wire::Result::Ok, EncodeStamped(stamped), -1};
    }
    case wire::Operation::OpenChannel: return OpenChannel(service);
    case wire::Operation::Manifest: return Reply{wire::Result::Ok, identity.manifest, -1};
    case wire::Operation::MachineStatement: return Reply{wire::Result::Ok, service.statement, -1};
    case wire::Operation::Checkpoint:
      if (body.size() != 8) return Refuse(wire::Result::BadRequest);
      return MakeCheckpoint(service, Number(body));
    case wire::Operation::LogEntries: {
      if (body.size() != 10) return Refuse(wire::Result::BadRequest);
      const auto segment = service.log.Read(Number(body.first(8)), static_cast<size_t>(Number(body.subspan(8))));
      if (!segment) return Refuse(wire::Result::BadRequest);
      return Reply{wire::Result::Ok, EncodeSegment(*segment), -1};
    }
  }
  return Refuse(wire::Result::BadRequest);
}

// One channel: requests are answered in order until the node closes it.
void Serve(const Service* service, int fd) {
  (void)fortis::keys::io::SetTimeouts(fd, kSendTimeoutSeconds);
  // Waiting for the next request may take as long as the node likes; once a
  // header has come, its body must follow within kSendTimeoutSeconds, so a
  // stalled request cannot hold a thread and its buffer for ever.
  const timeval forever{0, 0}, body_limit{kSendTimeoutSeconds, 0};
  Bytes body;
  for (;;) {
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &forever, sizeof(forever));
    wire::Header header{};
    if (!io::ReceiveExact(fd, header)) break;
    const auto request = wire::Decode(header, wire::Direction::Request);
    if (!request) break;  // not this protocol, or too long: nothing more can be trusted on this stream
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &body_limit, sizeof(body_limit));
    try {
      body.resize(request->length);
    } catch (const std::bad_alloc&) { break; }
    if (!io::ReceiveExact(fd, body)) break;
    Reply reply;
    try {
      reply = Dispatch(*service, static_cast<wire::Operation>(request->code), body);
    } catch (...) { reply = Refuse(wire::Result::Failed); }
    if (reply.body.size() > wire::kReplyMax) reply = Refuse(wire::Result::Failed);
    const auto out = wire::Encode(wire::Direction::Reply, static_cast<uint8_t>(reply.result), request->id,
                                  static_cast<uint32_t>(reply.body.size()));
    const bool sent = io::SendAll(fd, out, reply.attach) && io::SendAll(fd, reply.body);
    if (reply.attach >= 0) (void)::close(reply.attach);
    Wipe(body);  // the node's messages are its business, not ours to keep
    if (!sent) break;
  }
  (void)::close(fd);
  --g_channels;
}

void PrepareSocketFolder(const fs::path& folder) {
  if (::mkdir(folder.c_str(), 0700) != 0 && errno != EEXIST)
    throw std::runtime_error("cannot create the socket folder");
  struct stat st {};
  if (::lstat(folder.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != ::geteuid() || (st.st_mode & 077))
    throw std::runtime_error("the socket folder must be this user's, mode 0700");
}

int Listen(const fs::path& path) {
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  const auto text = path.string();
  if (text.size() >= sizeof(address.sun_path)) throw std::runtime_error("socket path too long");
  std::memcpy(address.sun_path, text.c_str(), text.size() + 1);
  (void)::unlink(text.c_str());  // a socket file left by an earlier run
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) throw std::runtime_error("cannot create the socket");
  (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
  if (::bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
      ::chmod(text.c_str(), 0600) != 0 || ::listen(fd, 16) != 0) {
    (void)::close(fd);
    throw std::runtime_error("cannot listen on " + text);
  }
  return fd;
}

int Run(const fs::path& store_folder, const fs::path& socket_folder) {
  if (!ProtectProcess()) LogWarn("keys", "core dumps could not be switched off");
  const bool all_locked = LockAllMemory();
  ::umask(077);
  (void)std::signal(SIGPIPE, SIG_IGN);
  const unsigned cores = std::thread::hardware_concurrency();
  const auto signers = static_cast<std::ptrdiff_t>(cores == 0 ? 1 : (cores > 1024 ? 1024 : cores));
  g_signers.release(signers - 1);  // it starts with one

  // The first start makes and checks keys on this thread, whose stack is the
  // process's limit (ulimit -s), not kThreadStack: refuse a limit that is too small.
  if (rlimit stack{};
      ::getrlimit(RLIMIT_STACK, &stack) == 0 && stack.rlim_cur != RLIM_INFINITY && stack.rlim_cur < kSigningStack)
    throw std::runtime_error("the stack limit (ulimit -s) is below " + std::to_string(kSigningStack / 1024) +
                             " KiB, which key generation needs");
  const auto store = KeyStore::Open(store_folder);
  const auto& identity = store.identity();
  if (store.new_machine()) LogInfo("keys", "created machine key %s", store.machine().id.c_str());
  LogInfo("keys", "%s identity %s on machine %s", store.created() ? "created" : "opened", identity.did.c_str(),
          store.machine().id.c_str());
  if (all_locked) {
    LogInfo("keys", "all memory is locked: nothing reaches swap");
  } else if (!identity.runtime_sqisign.secret_key.Locked() || !identity.master.Locked()) {
    LogWarn("keys", "secret keys could not be locked in memory (RLIMIT_MEMLOCK); they may reach swap");
  } else {
    LogWarn("keys", "only the key buffers are locked; copies on stacks may reach swap (RLIMIT_MEMLOCK is limited)");
  }
  LogInfo("keys", "runtime certificates last %lld seconds; up to %td signatures at once",
          static_cast<long long>(kRuntimeCertificateLifetime.count()), signers);
  SigningLog log(store_folder, store.machine().id_bytes);
  LogInfo("keys", "signing log has %llu entries", static_cast<unsigned long long>(log.Last()));
  const Service service{store, log, MachineStatementOf(store)};

  PrepareSocketFolder(socket_folder);
  const int listener = Listen(socket_folder / "node.sock");
  LogInfo("keys", "serving node channels on %s", (socket_folder / "node.sock").c_str());
  for (;;) {
    const int fd = ::accept(listener, nullptr, nullptr);
    if (fd < 0) {
      if (errno == EINTR || errno == ECONNABORTED) continue;
      // Out of descriptors or memory, for now: wait, the channels will end.
      if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM) {
        LogWarn("keys", "accept failed for now: errno=%d", errno);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        continue;
      }
      // Channel threads still use the store: leave without destroying it.
      LogError("keys", "accept failed: errno=%d", errno);
      std::_Exit(1);
    }
    (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (!PeerAllowed(fd) || !TakeChannel()) {
      (void)::close(fd);
      continue;
    }
    if (!StartChannel(service, fd)) {
      --g_channels;
      (void)::close(fd);
    }
  }
}
}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: fortis-keyd STORE_FOLDER SOCKET_FOLDER\n");
    return 2;
  }
  try {
    return Run(argv[1], argv[2]);
  } catch (const std::exception& e) {
    // These messages name a file or a check, never a key.
    LogError("keys", "the key service stopped: %s", e.what());
    return 1;
  }
}
