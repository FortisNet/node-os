#include "socket_io.h"

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace fortis::keys::io {
namespace {
#if defined(MSG_NOSIGNAL)
constexpr int kNoSignal = MSG_NOSIGNAL;
#else
constexpr int kNoSignal = 0;  // macOS: the socket has SO_NOSIGPIPE instead (SetTimeouts)
#endif
#if defined(MSG_CMSG_CLOEXEC)
constexpr int kReceiveFlags = MSG_CMSG_CLOEXEC;  // a received descriptor is never inherited by accident
#else
constexpr int kReceiveFlags = 0;
#endif

// Close every descriptor carried by a received message, except one we keep.
void Collect(msghdr& message, int* keep) noexcept {
  for (cmsghdr* c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
    if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
    const size_t count = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    for (size_t i = 0; i < count; ++i) {
      int fd = -1;
      std::memcpy(&fd, CMSG_DATA(c) + i * sizeof(int), sizeof(int));
      if (keep && *keep < 0) {
        *keep = fd;
      } else {
        (void)::close(fd);
      }
    }
  }
}
}  // namespace

bool SendAll(int fd, std::span<const uint8_t> data, int attach) noexcept {
  size_t done = 0;
  while (done < data.size()) {
    iovec part{const_cast<uint8_t*>(data.data() + done), data.size() - done};
    msghdr message{};
    message.msg_iov = &part;
    message.msg_iovlen = 1;
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))] = {};
    if (attach >= 0 && done == 0) {
      message.msg_control = control;
      message.msg_controllen = sizeof(control);
      cmsghdr* c = CMSG_FIRSTHDR(&message);
      c->cmsg_level = SOL_SOCKET;
      c->cmsg_type = SCM_RIGHTS;
      c->cmsg_len = CMSG_LEN(sizeof(int));
      std::memcpy(CMSG_DATA(c), &attach, sizeof(int));
    }
    const ssize_t sent = ::sendmsg(fd, &message, kNoSignal);
    if (sent < 0 && errno == EINTR) continue;
    if (sent <= 0) return false;
    done += static_cast<size_t>(sent);
  }
  return true;
}

bool ReceiveExact(int fd, std::span<uint8_t> output, int* received) noexcept {
  if (received) *received = -1;
  size_t done = 0;
  while (done < output.size()) {
    iovec part{output.data() + done, output.size() - done};
    msghdr message{};
    message.msg_iov = &part;
    message.msg_iovlen = 1;
    alignas(cmsghdr) char control[CMSG_SPACE(4 * sizeof(int))] = {};
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    const ssize_t got = ::recvmsg(fd, &message, kReceiveFlags);
    if (got < 0 && errno == EINTR) continue;
    if (got > 0) Collect(message, received);
    if (got <= 0 || (message.msg_flags & MSG_CTRUNC)) {
      if (received && *received >= 0) {
        (void)::close(*received);
        *received = -1;
      }
      return false;
    }
    done += static_cast<size_t>(got);
  }
  return true;
}

bool SetTimeouts(int fd, int seconds) noexcept {
  timeval limit{seconds, 0};
  bool ok = ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit)) == 0 &&
            ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit)) == 0;
#if defined(SO_NOSIGPIPE)
  const int on = 1;
  ok = ok && ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)) == 0;
#endif
  return ok;
}
}  // namespace fortis::keys::io
