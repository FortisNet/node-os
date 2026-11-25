#include "sandbox_socket.h"
#include "bounded_json.h"
#include <stdexcept>
#include <vector>
#if defined(__linux__) && !defined(FORTIS_UNIKRAFT)
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace fortis::compat::sandbox {
namespace {
void Require(bool condition) {
  if (!condition) throw std::runtime_error("local sandbox channel unavailable");
}
#if defined(__linux__) && !defined(FORTIS_UNIKRAFT)
void Wait(int fd, short events, Deadline deadline) {
  for (;;) {
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
    Require(remaining > 0 && remaining <= 60000);
    pollfd poller{fd, events, 0};
    const int result = poll(&poller, 1, static_cast<int>(remaining));
    if (result < 0 && errno == EINTR) continue;
    Require(result > 0 && !(poller.revents & POLLNVAL));
    return;
  }
}
void Transfer(int fd, void* output, const void* input, size_t size, Deadline deadline) {
  auto* destination = static_cast<unsigned char*>(output);
  const auto* source = static_cast<const unsigned char*>(input);
  while (size) {
    Wait(fd, output ? POLLIN : POLLOUT, deadline);
    const ssize_t count =
        output ? recv(fd, destination, size, MSG_DONTWAIT) : send(fd, source, size, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    Require(count > 0);
    const auto done = static_cast<size_t>(count);
    if (output) destination += done;
    else source += done;
    size -= done;
  }
}
#endif
}  // namespace
void Receive(int fd, void* output, size_t size, Deadline deadline) {
#if defined(__linux__) && !defined(FORTIS_UNIKRAFT)
  Require(output || !size);
  Transfer(fd, output, nullptr, size, deadline);
#else
  (void)fd;
  (void)output;
  (void)size;
  (void)deadline;
  Require(false);
#endif
}
void Transmit(int fd, const void* input, size_t size, Deadline deadline) {
#if defined(__linux__) && !defined(FORTIS_UNIKRAFT)
  Require(input || !size);
  Transfer(fd, nullptr, input, size, deadline);
#else
  (void)fd;
  (void)input;
  (void)size;
  (void)deadline;
  Require(false);
#endif
}
void EndOfMessage(int fd, Deadline deadline) {
#if defined(__linux__) && !defined(FORTIS_UNIKRAFT)
  for (;;) {
    Wait(fd, POLLIN, deadline);
    char extra = 0;
    const ssize_t n = recv(fd, &extra, 1, MSG_DONTWAIT);
    if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    Require(n == 0);
    return;
  }
#else
  (void)fd;
  (void)deadline;
  Require(false);
#endif
}
uint32_t PeerUid(int fd) {
#if defined(__linux__) && !defined(FORTIS_UNIKRAFT)
  ucred peer{};
  socklen_t size = sizeof(peer);
  Require(getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0 && size == sizeof(peer));
  return peer.uid;
#else
  (void)fd;
  Require(false);
  return 0;
#endif
}
base::FileDescriptor Connect(std::string_view path, Deadline deadline) {
#if defined(__linux__) && !defined(FORTIS_UNIKRAFT)
  namespace fs = std::filesystem;
  sockaddr_un address{};
  Require(path.size() > 1 && path.size() < sizeof(address.sun_path) && path.front() == '/' &&
          path.find('\0') == std::string_view::npos);
  const fs::path endpoint{std::string(path)};
  Require(endpoint.lexically_normal() == endpoint);
  fs::path at = "/";
  struct stat info {};
  Require(lstat("/", &info) == 0 && info.st_uid == 0 && !(info.st_mode & 0022));
  for (const auto& part : endpoint.parent_path().relative_path()) {
    at /= part;
    Require(lstat(at.c_str(), &info) == 0 && S_ISDIR(info.st_mode) && info.st_uid == 0 && !(info.st_mode & 0022));
  }
  Require(lstat(endpoint.c_str(), &info) == 0 && S_ISSOCK(info.st_mode) && info.st_uid == geteuid() &&
          (info.st_mode & 0777) == 0600);
  base::FileDescriptor socket(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
  Require(socket.get() >= 0);
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, path.data(), path.size());
  if (connect(socket.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0) {
    Require(errno == EINPROGRESS);
    Wait(socket.get(), POLLOUT, deadline);
    int error = 0;
    socklen_t length = sizeof(error);
    Require(getsockopt(socket.get(), SOL_SOCKET, SO_ERROR, &error, &length) == 0 && length == sizeof(error) &&
            error == 0);
  }
  Require(PeerUid(socket.get()) == 0);
  return socket;
#else
  (void)path;
  (void)deadline;
  Require(false);
  return base::FileDescriptor{};
#endif
}
Reply Request(std::string_view socket, codec::sandbox::Operation operation, std::string_view payload) {
  using namespace codec::sandbox;
  Require(!payload.empty() && payload.size() <= kRequestLimit);
  auto header = Encode(false, static_cast<uint8_t>(operation), static_cast<uint32_t>(payload.size()));
  uint8_t code = 0;
  uint32_t length = 0;
  Require(Decode(header, false, code, length));
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  auto channel = Connect(socket, deadline);
  Transmit(channel.get(), header.data(), header.size(), deadline);
  Transmit(channel.get(), payload.data(), payload.size(), deadline);
#if defined(__linux__) && !defined(FORTIS_UNIKRAFT)
  Require(shutdown(channel.get(), SHUT_WR) == 0);
#endif
  Receive(channel.get(), header.data(), header.size(), deadline);
  Require(Decode(header, true, code, length));
  Reply result{static_cast<ReplyCode>(code), std::string(length, '\0')};
  Receive(channel.get(), result.payload.data(), result.payload.size(), deadline);
  EndOfMessage(channel.get(), deadline);
  std::vector<codec::BoundedJsonToken> tokens(1024);
  codec::BoundedJsonDocument json;
  codec::BoundedJsonError error{};
  Require(json.Parse(reinterpret_cast<const unsigned char*>(result.payload.data()), result.payload.size(),
                     tokens.data(), tokens.size(), &error));
  const auto* root = json.token(json.root());
  Require(root && root->type == codec::BoundedJsonType::kObject);
  return result;
}
}  // namespace fortis::compat::sandbox
