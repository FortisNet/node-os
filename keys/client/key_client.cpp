#include "key_client.h"

#include "key_wire.h"
#include "socket_io.h"

#include <cerrno>
#include <fcntl.h>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace fortis::keys {
namespace {
// SQIsign signing on a slow processor, while every core is busy, can take
// seconds. A key service that does not answer in this time is not working.
constexpr int kTimeoutSeconds = 60;

[[noreturn]] void Fail(const std::string& what) { throw std::runtime_error("key service: " + what); }

const char* ResultName(uint8_t code) {
  switch (static_cast<wire::Result>(code)) {
    case wire::Result::Ok: return "ok";
    case wire::Result::BadRequest: return "bad request";
    case wire::Result::Denied: return "denied";
    case wire::Result::Busy: return "busy";
    case wire::Result::Unavailable: return "unavailable";
    case wire::Result::Failed: return "failed";
  }
  return "unknown result";
}

bool IsUnixStream(int fd) {
  struct stat st {};
  int type = 0;
  sockaddr_storage address{};
  socklen_t size = sizeof(type), address_size = sizeof(address);
  return ::fstat(fd, &st) == 0 && S_ISSOCK(st.st_mode) && ::getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) == 0 &&
         type == SOCK_STREAM && ::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &address_size) == 0 &&
         address.ss_family == AF_UNIX;
}
}  // namespace

Client Client::FromEnvironment() {
  const char* text = std::getenv("FORTIS_KEYS_FD");
  if (!text || !*text) Fail("FORTIS_KEYS_FD is not set");
  int fd = -1;
  const auto end = text + std::strlen(text);
  const auto parsed = std::from_chars(text, end, fd);
  if (parsed.ec != std::errc() || parsed.ptr != end || fd < 3) Fail("FORTIS_KEYS_FD is not a descriptor number");
  return Client(fd);
}

Client::Client(int descriptor) : fd_(descriptor) {
  // A signing channel is never inherited by a program the node starts.
  const bool usable =
      fd_ >= 0 && IsUnixStream(fd_) && ::fcntl(fd_, F_SETFD, FD_CLOEXEC) == 0 && io::SetTimeouts(fd_, kTimeoutSeconds);
  if (!usable) {
    Drop();
    Fail("the descriptor is not a usable Unix stream socket");
  }
}

void Client::Drop() noexcept {
  if (fd_ >= 0) (void)::close(fd_);
  fd_ = -1;
}

Client::~Client() { Drop(); }
Client::Client(Client&& other) noexcept : fd_(std::exchange(other.fd_, -1)), next_id_(other.next_id_) {}
Client& Client::operator=(Client&& other) noexcept {
  if (this != &other) {
    if (fd_ >= 0) (void)::close(fd_);
    fd_ = std::exchange(other.fd_, -1);
    next_id_ = other.next_id_;
  }
  return *this;
}

Bytes Client::Call(uint8_t operation, View body, int* received_descriptor) {
  if (fd_ < 0) Fail("not connected: an earlier request on this channel failed");
  // After any failure of the stream itself, the next bytes on it could belong
  // to an old reply: the channel is closed, and later calls fail at once.
  auto broken = [this, received_descriptor](const char* what) {
    if (received_descriptor && *received_descriptor >= 0) (void)::close(std::exchange(*received_descriptor, -1));
    Drop();
    Fail(what);
  };
  const uint32_t id = ++next_id_;
  const auto header = wire::Encode(wire::Direction::Request, operation, id, static_cast<uint32_t>(body.size()));
  if (!io::SendAll(fd_, header) || !io::SendAll(fd_, body)) broken("cannot send the request");
  wire::Header reply{};
  if (!io::ReceiveExact(fd_, reply, received_descriptor)) broken("no reply");
  const auto parsed = wire::Decode(reply, wire::Direction::Reply);
  if (!parsed || parsed->id != id) broken("malformed reply");
  Bytes out(parsed->length);
  if (!io::ReceiveExact(fd_, out)) broken("reply cut short");
  // A refusal is a whole, well-formed reply: the channel stays usable.
  if (parsed->code != static_cast<uint8_t>(wire::Result::Ok)) {
    if (received_descriptor && *received_descriptor >= 0) (void)::close(std::exchange(*received_descriptor, -1));
    Fail(ResultName(parsed->code));
  }
  return out;
}

ServiceInfo Client::Info() {
  const auto body = Call(static_cast<uint8_t>(wire::Operation::Info), {});
  ServiceInfo info;
  size_t at = 0;
  auto byte = [&]() -> uint8_t {
    if (at >= body.size()) Fail("malformed information");
    return body[at++];
  };
  auto text = [&]() {
    const size_t length = byte();
    if (at + length > body.size()) Fail("malformed information");
    std::string out(body.begin() + static_cast<std::ptrdiff_t>(at),
                    body.begin() + static_cast<std::ptrdiff_t>(at + length));
    at += length;
    return out;
  };
  info.ready = byte() == 0;
  info.did = text();
  info.machine_id = text();
  for (size_t count = byte(); count > 0; --count) {
    const auto algorithm = AlgorithmFrom(byte());
    if (!algorithm) Fail("unknown algorithm in information");
    info.algorithms.push_back(*algorithm);
  }
  if (at != body.size()) Fail("malformed information");
  return info;
}

Bytes Client::PublicKey(Algorithm algorithm) {
  const uint8_t body[1] = {static_cast<uint8_t>(algorithm)};
  auto key = Call(static_cast<uint8_t>(wire::Operation::PublicKey), body);
  if (key.size() != SizesOf(algorithm).public_key) Fail("public key of the wrong size");
  return key;
}

StampedSignature Client::Sign(Algorithm algorithm, std::string_view label, View message) {
  if (!ValidLabel(label)) Fail("invalid label");
  if (message.size() > kMessageMax) Fail("message too long");
  Bytes body;
  body.reserve(2 + label.size() + message.size());
  body.push_back(static_cast<uint8_t>(algorithm));
  body.push_back(static_cast<uint8_t>(label.size()));
  body.insert(body.end(), label.begin(), label.end());
  body.insert(body.end(), message.begin(), message.end());
  const auto reply = Call(static_cast<uint8_t>(wire::Operation::Sign), body);
  auto stamped = DecodeStamped(reply);
  if (!stamped) Fail("malformed signature");
  return std::move(*stamped);
}

Bytes Client::Manifest() { return Call(static_cast<uint8_t>(wire::Operation::Manifest), {}); }
Bytes Client::MachineStatement() { return Call(static_cast<uint8_t>(wire::Operation::MachineStatement), {}); }

Bytes Client::Checkpoint(uint64_t at) {
  uint8_t body[8];
  for (int i = 0; i < 8; ++i) body[i] = static_cast<uint8_t>(at >> (56 - 8 * i));
  return Call(static_cast<uint8_t>(wire::Operation::Checkpoint), body);
}

Bytes Client::LogEntries(uint64_t from, uint16_t count) {
  uint8_t body[10];
  for (int i = 0; i < 8; ++i) body[i] = static_cast<uint8_t>(from >> (56 - 8 * i));
  body[8] = static_cast<uint8_t>(count >> 8);
  body[9] = static_cast<uint8_t>(count);
  return Call(static_cast<uint8_t>(wire::Operation::LogEntries), body);
}

Client Client::OpenChannel() {
  int received = -1;
  (void)Call(static_cast<uint8_t>(wire::Operation::OpenChannel), {}, &received);
  if (received < 0) Fail("no channel was attached");
  return Client(received);
}
}  // namespace fortis::keys
