#include "first_boot.h"
#include <arpa/inet.h>
#include <fstream>
#include <iterator>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/timex.h>

namespace fortis::host::updates {
namespace {
void Folder(const fs::path& path, mode_t mode, bool for_node = false) {
  Directory(path, mode);
  // Only an administrator can hand a folder to the node's user; an
  // unprivileged run (tests) leaves ownership alone.
  if (for_node && geteuid() == 0) Check(chown(path.c_str(), 10001, 10001), "folder owner");
}
}  // namespace

std::string_view HostKind() {
  // The markers container runtimes leave: Docker's file, Podman's file, and
  // the "container" variable most runtimes give the first process.
  std::error_code ignored;
  if (fs::exists("/.dockerenv", ignored) || fs::exists("/run/.containerenv", ignored)) return "container";
  // Without the administrator's rights the first process cannot be looked
  // at; such a run (tests) is then taken to be on a machine.
  std::ifstream first("/proc/1/environ", std::ios::binary);
  const std::string environment((std::istreambuf_iterator<char>(first)), std::istreambuf_iterator<char>());
  if (environment.starts_with("container=") || environment.find(std::string("\0container=", 11)) != std::string::npos)
    return "container";
  return "machine";
}

std::string RoutedAddress() {
  // Connecting a datagram socket only asks the kernel which route and source
  // address it would use. Nothing is sent to the address named here.
  const FileDescriptor probe(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
  if (probe.get() < 0) return {};
  sockaddr_in target{};
  target.sin_family = AF_INET;
  target.sin_port = htons(53);
  if (inet_pton(AF_INET, "1.1.1.1", &target.sin_addr) != 1 ||
      connect(probe.get(), reinterpret_cast<const sockaddr*>(&target), sizeof(target)) != 0)
    return {};
  sockaddr_in local{};
  socklen_t size = sizeof(local);
  if (getsockname(probe.get(), reinterpret_cast<sockaddr*>(&local), &size) != 0) return {};
  std::array<char, INET_ADDRSTRLEN> text{};
  return inet_ntop(AF_INET, &local.sin_addr, text.data(), text.size()) ? std::string(text.data()) : std::string();
}

bool PublicAddress(std::string_view address) {
  in_addr parsed{};
  if (inet_pton(AF_INET, std::string(address).c_str(), &parsed) != 1) return false;
  const uint32_t ip = ntohl(parsed.s_addr);
  const auto within = [ip](uint32_t network, unsigned bits) { return (ip >> (32 - bits)) == (network >> (32 - bits)); };
  return !(within(0x00000000, 8) || within(0x0A000000, 8) || within(0x64400000, 10) || within(0x7F000000, 8) ||
           within(0xA9FE0000, 16) || within(0xAC100000, 12) || within(0xC0000000, 24) || within(0xC0000200, 24) ||
           within(0xC0A80000, 16) || within(0xC6120000, 15) || within(0xC6336400, 24) || within(0xCB007100, 24) ||
           within(0xE0000000, 3));
}

bool ClockSynchronised() {
  struct timex state {};
  return adjtimex(&state) != TIME_ERROR && (state.status & STA_UNSYNC) == 0;
}

bool FirstBoot(const fs::path& config, const fs::path& prefix) {
  if (fs::exists(config)) return false;
  const auto at = [&prefix](const char* path) {
    return prefix.empty() ? fs::path(path) : prefix / fs::path(path).relative_path();
  };
  const auto share = at("/usr/share/fortis"), var = at("/var/lib/fortis"), etc = at("/etc/fortis");
  Require(fs::is_regular_file(share / "release-public.pem"), "the image has no release key");
  // Settings layered on the defaults: nothing is required of the operator.
  std::map<std::string, std::string> overrides;
  if (fs::exists(etc / "first-boot.conf")) overrides = KeyValues(Read(etc / "first-boot.conf", 16 * 1024));
  const auto take = [&overrides](const std::string& key, const std::string& fallback) {
    const auto found = overrides.find(key);
    if (found == overrides.end()) return fallback;
    auto value = found->second;
    overrides.erase(found);
    return value;
  };
  const auto address = take("FORTIS_HTTPS_IP", RoutedAddress());
  in_addr parsed{};
  Require(inet_pton(AF_INET, address.c_str(), &parsed) == 1, "this machine has no network address yet");

  // A real host already has /var, /var/lib and /etc. Under a prefix they are
  // created here, open to traversal as they are on a real host: the
  // unprivileged certificate and fetch processes must reach their folders.
  if (!prefix.empty())
    for (const char* system : {"/var", "/var/lib", "/etc"}) Folder(at(system), 0755);
  Folder(var, 0755);
  Folder(var / "state", 0700);
  Folder(var / "data", 0755);
  Folder(var / "data/kv", 0700, true);
  Folder(var / "data/backups", 0700);
  Folder(var / "certificates", 0755);
  Folder(var / "challenges", 0755);
  Folder(etc, 0755);

  std::map<std::string, std::string> node{{"NODE_ENV", "development"},
                                          {"FORTIS_HEALTH_PORT", "8081"},
                                          {"FORTIS_HTTPS_CERT_DIR", "/certificates"},
                                          {"FORTIS_ACME_CHALLENGE_DIR", "/acme"},
                                          {"FORTIS_HTTP_REDIRECT_PORT", "8082"},
                                          {"FORTIS_HTTPS_IP", address}};
  std::map<std::string, std::string> host{{"FORTIS_NATIVE_ROOT", (var / "state").string()},
                                          {"FORTIS_NATIVE_DATA", (var / "data/kv").string()},
                                          {"FORTIS_NATIVE_BACKUPS", (var / "data/backups").string()},
                                          {"FORTIS_NATIVE_ENV", (etc / "node.env").string()},
                                          {"FORTIS_NATIVE_PUBLIC_KEY", (share / "release-public.pem").string()},
                                          {"FORTIS_NATIVE_BAKED_RELEASE", (share / "node-release").string()},
                                          {"FORTIS_NATIVE_NAME", "fortis-node"},
                                          {"FORTIS_NATIVE_HTTPS", "1"},
                                          {"FORTIS_NATIVE_PORT", "443"},
                                          {"FORTIS_NATIVE_HTTP_PORT", "80"},
                                          {"FORTIS_NATIVE_HEALTH_HOST_PORT", "8081"},
                                          {"FORTIS_NATIVE_CERTIFICATES", (var / "certificates").string()},
                                          {"FORTIS_NATIVE_ACME_CHALLENGES", (var / "challenges").string()},
                                          {"FORTIS_NATIVE_ACME_STATE", (var / "acme").string()},
                                          {"FORTIS_NATIVE_FETCH_STATE", (var / "fetch").string()},
                                          // The database is on the machine's own disk in this stage, so there is
                                          // no separate mount to insist on.
                                          {"FORTIS_NATIVE_REQUIRE_MOUNT", "0"},
                                          {"FORTIS_NATIVE_REQUIRE_CLOCK", "1"},
                                          // Until the orchestrator can supply its own checks, an update on a node
                                          // nobody uses yet must not wait for requests that will never come.
                                          {"FORTIS_NATIVE_OBSERVE_SECONDS", "30"},
                                          {"FORTIS_NATIVE_MIN_REQUESTS", "0"}};
  if (fs::is_regular_file(share / "recovery-public.pem"))
    host["FORTIS_NATIVE_RECOVERY_KEY"] = (share / "recovery-public.pem").string();
  // What is left in the settings file replaces a default of the same name:
  // the orchestrator's own settings are the FORTIS_NATIVE_ ones, everything
  // else belongs to the node.
  for (const auto& [key, value] : overrides) {
    Require(Token(key, 100) && value.find('\n') == std::string::npos && value.size() <= 2048,
            "invalid first-boot setting");
    (key.starts_with("FORTIS_NATIVE_") ? host : node)[key] = value;
  }
  const auto text = [](const std::map<std::string, std::string>& values) {
    std::string out;
    for (const auto& [key, value] : values) out.append(key).append("=").append(value).append("\n");
    return out;
  };
  AtomicFile(etc / "node.env", text(node), 0600);
  // The configuration is written last: its presence is what says the host is
  // configured, so an interrupted first boot simply runs again.
  AtomicFile(config, text(host), 0600);
  return true;
}

}  // namespace fortis::host::updates
