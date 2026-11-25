#include "page_server.h"
#include "native_control_support.h"
#include "pages.h"
#include <cstdlib>
#include <sys/socket.h>

namespace fortis::host::updates {
namespace {
constexpr size_t kConnections = 64, kRequestBytes = 4096, kChallengeBytes = 4096, kPageBytes = 1024 * 1024;
constexpr auto kPatience = std::chrono::seconds(10);
constexpr std::string_view kChallengePrefix = "/.well-known/acme-challenge/";
constexpr std::string_view kNotice = "FortisNet node: not available right now. See https://blockchain.fortisnet.io\n";

struct Connection {
  FileDescriptor socket;
  std::string request, reply;
  size_t sent = 0;
  SteadyClock::time_point deadline;
};
int InheritedListener() {
  const char* map = std::getenv("FORTIS_LISTEN_FDS");
  Require(map != nullptr, "no inherited listener");
  const std::string_view text = map;
  constexpr std::string_view key = "8082=";
  const auto at = text.find(key);
  Require(at != std::string_view::npos, "no inherited HTTP listener");
  const auto value = text.substr(at + key.size(), text.find(',', at) - at - key.size());
  return static_cast<int>(Integer(value, 1023));
}
bool SafeToken(std::string_view token) {
  return !token.empty() && token.size() <= 128 && std::all_of(token.begin(), token.end(), [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
  });
}
std::string Response(int status, std::string_view type, std::string_view body, bool head) {
  const char* reason = status == 200   ? "OK"
                       : status == 400 ? "Bad Request"
                       : status == 404 ? "Not Found"
                       : status == 405 ? "Method Not Allowed"
                                       : "Service Unavailable";
  std::string out = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\nContent-Type: " + std::string(type) +
                    "\r\nContent-Length: " + std::to_string(body.size()) +
                    "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n";
  if (!head) out += body;
  return out;
}
std::string Text(int status, std::string_view body, bool head) {
  return Response(status, "text/plain; charset=utf-8", body, head);
}
/** One regular file from an opened directory, bounded; empty when absent. */
std::string File(int directory, const char* name, size_t limit) {
  const FileDescriptor file(openat(directory, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
  struct stat info {};
  if (file.get() < 0 || fstat(file.get(), &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0 ||
      static_cast<size_t>(info.st_size) > limit)
    return {};
  std::string body(static_cast<size_t>(info.st_size), '\0');
  size_t have = 0;
  while (have < body.size()) {
    const ssize_t count = ::read(file.get(), body.data() + have, body.size() - have);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return {};
    have += static_cast<size_t>(count);
  }
  return body;
}
/** The status the health report states, or 503 when it is missing, unreadable
 * or older than a report may be. */
int ReportedStatus(int pages) {
  const auto line = File(pages, kHealthStatusFile, 64);
  const auto space = line.find(' ');
  if (space == std::string::npos || line.empty() || line.back() != '\n') return 503;
  try {
    const auto status = Integer(std::string_view(line).substr(0, space), 599);
    const auto written = Integer(std::string_view(line).substr(space + 1, line.size() - space - 2));
    const auto now = NowMs();
    return status == 200 && now >= written && now - written <= kHealthFreshMs ? 200 : 503;
  } catch (const std::runtime_error&) { return 503; }
}
std::string Answer(int challenges, int pages, std::string_view request) {
  const auto line = request.substr(0, request.find("\r\n"));
  const auto first = line.find(' '), last = line.rfind(' ');
  if (first == std::string_view::npos || last == first) return Text(400, "Bad request\n", false);
  const auto method = line.substr(0, first);
  auto target = line.substr(first + 1, last - first - 1);
  if (method != "GET" && method != "HEAD") return Text(405, "Method not allowed\n", false);
  const bool head = method == "HEAD";
  if (target.starts_with(kChallengePrefix)) {
    const auto token = std::string(target.substr(kChallengePrefix.size()));
    const auto body = SafeToken(token) ? File(challenges, token.c_str(), kChallengeBytes) : std::string();
    return body.empty() ? Text(404, "Not found\n", head) : Text(200, body, head);
  }
  target = target.substr(0, target.find('?'));
  if (pages >= 0) {
    if (target == "/") {
      const auto body = File(pages, kFirstPageFile, kPageBytes);
      if (!body.empty()) return Response(200, "text/html; charset=utf-8", body, head);
    } else if (target == "/health" || target == "/health.json") {
      const bool json = target == "/health.json";
      const auto body = File(pages, json ? kHealthJsonFile : kHealthPageFile, kPageBytes);
      if (!body.empty())
        return Response(ReportedStatus(pages), json ? "application/json" : "text/html; charset=utf-8", body, head);
    }
  }
  return Text(503, kNotice, head);
}
}  // namespace

int RunPageServer(const std::filesystem::path& challenges, const std::filesystem::path& pages) {
  const int listener = InheritedListener();
  Check(fcntl(listener, F_SETFL, fcntl(listener, F_GETFL) | O_NONBLOCK), "nonblocking listener");
  const FileDescriptor challenge_directory(
      Check(::open(challenges.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), "open challenge directory"));
  FileDescriptor page_directory;
  if (!pages.empty())
    page_directory.reset(
        Check(::open(pages.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), "open page directory"));
  std::vector<Connection> connections;
  while (!interrupted) {
    std::vector<pollfd> watched{{listener, static_cast<short>(connections.size() < kConnections ? POLLIN : 0), 0}};
    for (const auto& connection : connections)
      watched.push_back({connection.socket.get(), static_cast<short>(connection.reply.empty() ? POLLIN : POLLOUT), 0});
    (void)poll(watched.data(), watched.size(), 250);
    const auto now = SteadyClock::now();
    for (size_t i = connections.size(); i-- > 0;) {
      auto& connection = connections[i];
      bool finished = now >= connection.deadline || (watched[i + 1].revents & (POLLERR | POLLNVAL)) != 0;
      if (!finished && connection.reply.empty() && (watched[i + 1].revents & (POLLIN | POLLHUP))) {
        std::array<char, 1024> buffer{};
        const ssize_t count = ::recv(connection.socket.get(), buffer.data(), buffer.size(), MSG_DONTWAIT);
        if (count > 0) connection.request.append(buffer.data(), static_cast<size_t>(count));
        else if (count == 0 || (errno != EAGAIN && errno != EINTR)) finished = true;
        if (!finished && connection.request.find("\r\n\r\n") != std::string::npos)
          connection.reply = Answer(challenge_directory.get(), page_directory.get(), connection.request);
        else if (connection.request.size() > kRequestBytes) finished = true;
      }
      // A page is larger than a socket's buffer: send what fits and wait.
      if (!finished && !connection.reply.empty()) {
        const ssize_t count = ::send(connection.socket.get(), connection.reply.data() + connection.sent,
                                     connection.reply.size() - connection.sent, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (count > 0) connection.sent += static_cast<size_t>(count);
        else if (count < 0 && errno != EAGAIN && errno != EINTR) finished = true;
        if (connection.sent == connection.reply.size()) finished = true;
      }
      if (finished) connections.erase(connections.begin() + static_cast<std::ptrdiff_t>(i));
    }
    if (watched[0].revents & POLLIN) {
      FileDescriptor accepted(accept4(listener, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC));
      if (accepted.get() >= 0) connections.push_back({std::move(accepted), {}, {}, 0, now + kPatience});
    }
  }
  return 0;
}

}  // namespace fortis::host::updates
