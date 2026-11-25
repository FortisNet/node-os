#include "outbound_https.h"
#include "acme_client.h"
#include "backup.h"
#include "first_boot.h"
#include "node_keeper.h"
#include "page_server.h"
#include "pages.h"
#include "release_fetch.h"
#include "release_ledger.h"
#include <fstream>
#include <iostream>
#include <grp.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <unistd.h>

namespace fortis::host::updates {
namespace {
// The node's own writer lock inside its database folder.
constexpr char kDatabaseLock[] = "fortis.kv.lock";
// Absolute path of this executable; the keeper is the same program.
std::string self_path;
struct IncidentCount {
  uint64_t count = 0, first_ms = 0;
};
using IncidentCounts = std::map<std::string, IncidentCount>;
struct Release {
  std::string version, digest, source;
  uint64_t bytes = 0;
  bool metadata = false;
};
struct Settings {
  std::map<std::string, std::string> values, environment;
  fs::path config, root, data, backups, env, key, proc, sandbox_control, runtime_state;
  fs::path certificates, challenges, acme_state, recovery_key, fetch_state, baked_release;
  // Services asked for this host's public address when its own interface
  // shows a private one. Empty when switched off.
  std::vector<std::string> address_lookup;
  bool require_clock = false;
  std::string store;
  unsigned fetch_user = 10004;
  bool store_loopback = false;
  std::string name, domain, address, ca, acme_directory, acme_contact;
  unsigned acme_user = 10002;
  bool acme_loopback = false;
  unsigned port = 8080, health = 8080, http = 80, attempts = 30, observation = 30, samples = 10,
           observation_timeout = 120;
  bool https = false, require_mount = true, preflight = true, verify_pid = true, emulated_fixture = false;
  std::string Value(const char* field, const std::string& fallback = {}) const {
    const auto found = values.find(field);
    return found == values.end() ? fallback : found->second;
  }
  std::string Environment(const char* field) const {
    const auto found = environment.find(field);
    return found == environment.end() ? "" : found->second;
  }
};
void PrivateFile(const fs::path& path) {
  struct stat info {};
  Require(lstat(path.c_str(), &info) == 0 && S_ISREG(info.st_mode) && (info.st_mode & 0777) == 0600 &&
              info.st_uid == geteuid(),
          "private administrator-owned configuration required");
}
void SafePath(const fs::path& path) {
  const auto text = path.string();
  Require(path.is_absolute() && text.size() <= 1024 && text != "/" && path.lexically_normal() == path,
          "absolute canonical path required");
  Require(std::all_of(text.begin(), text.end(),
                      [](char c) {
                        return c == '/' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                               c == '_' || c == '-' || c == '.';
                      }),
          "unsafe configured path");
}
bool Within(const fs::path& child, const fs::path& parent) {
  auto c = child.begin(), p = parent.begin();
  for (; p != parent.end(); ++p, ++c)
    if (c == child.end() || *p != *c) return false;
  return true;
}
Settings Configure(const fs::path& path, bool stopping) {
  PrivateFile(path);
  Settings c{};
  c.config = path;
  c.values = KeyValues(Read(path, 16384), true);
  c.root = c.Value("FORTIS_NATIVE_ROOT");
  c.data = c.Value("FORTIS_NATIVE_DATA");
  c.env = c.Value("FORTIS_NATIVE_ENV");
  c.key = c.Value("FORTIS_NATIVE_PUBLIC_KEY");
  c.backups = c.Value("FORTIS_NATIVE_BACKUPS", (c.root / "backups").string());
  c.proc = c.Value("FORTIS_NATIVE_PROC_ROOT", "/proc");
  c.name = c.Value("FORTIS_NATIVE_NAME", "fortis-node");
  c.runtime_state = c.Value("FORTIS_NATIVE_RUNTIME_STATE", "/run/fortis-node");
  for (const auto& p : {c.root, c.data, c.env, c.key, c.backups, c.proc, c.runtime_state}) SafePath(p);
  Require(!Within(c.root, c.data) && !Within(c.data, c.root), "release state and database must be disjoint");
  Require(!Within(c.backups, c.data) && !Within(c.data, c.backups), "backup and database must be disjoint");
  PrivateFile(c.env);
  c.environment = KeyValues(Read(c.env, 128 * 1024), true);
  Require(fs::is_regular_file(fs::symlink_status(c.key)), "public verification key absent");
  // The name, with "-preflight-<number>" added, becomes a container's host
  // name, which the kernel limits to 64 characters.
  Require(Token(c.name, 44), "invalid runtime identity");
  // A second key that may sign releases and the release index, kept offline,
  // so a lost release key can be replaced without reinstalling the host.
  c.recovery_key = c.Value("FORTIS_NATIVE_RECOVERY_KEY");
  if (!c.recovery_key.empty()) {
    SafePath(c.recovery_key);
    Require(fs::is_regular_file(fs::symlink_status(c.recovery_key)), "recovery verification key absent");
  }
  // A node release that came with the image: installed by the supervisor
  // when nothing is installed yet.
  c.baked_release = c.Value("FORTIS_NATIVE_BAKED_RELEASE");
  if (!c.baked_release.empty()) SafePath(c.baked_release);
  // Certificates and signatures carry dates: on a real host nothing is
  // installed until the time service has set the clock.
  c.require_clock = Integer(c.Value("FORTIS_NATIVE_REQUIRE_CLOCK", "0"), 1) != 0;
  // A host behind address translation (a container, and machines on some
  // clouds) cannot see its public address on its own interface. These
  // services are then asked for it; "off" asks nobody.
  {
    std::istringstream services(
        c.Value("FORTIS_NATIVE_ADDRESS_LOOKUP", "https://checkip.amazonaws.com https://icanhazip.com"));
    for (std::string service; services >> service;) {
      if (service == "off") break;
      Require(service.starts_with("https://") && service.size() <= 1000 && c.address_lookup.size() < 4,
              "invalid address lookup service");
      c.address_lookup.push_back(service);
    }
  }
  // The release store is optional: without it, releases arrive as folders.
  c.store = c.Value("FORTIS_NATIVE_RELEASE_STORE");
  c.fetch_state = c.Value("FORTIS_NATIVE_FETCH_STATE", "/var/lib/fortis-fetch");
  SafePath(c.fetch_state);
  c.fetch_user = static_cast<unsigned>(Integer(c.Value("FORTIS_NATIVE_FETCH_USER", "10004"), 65534));
  c.store_loopback = Integer(c.Value("FORTIS_NATIVE_RELEASE_STORE_LOOPBACK", "0"), 1) != 0;
  Require(c.fetch_user >= 1000 && c.fetch_user != 10001 &&
              (c.store.empty() || (c.store.starts_with("https://") && c.store.back() != '/' && c.store.size() <= 1000)),
          "invalid release store settings");
  c.port = static_cast<unsigned>(Integer(c.Value("FORTIS_NATIVE_PORT", "8080"), 65535));
  const auto forwarded = static_cast<unsigned>(Integer(c.Value("FORTIS_NATIVE_HEALTH_HOST_PORT", "0"), 65535));
  Require(c.port && forwarded != c.port, "invalid health forwarding");
  c.health = forwarded ? forwarded : c.port;
  c.https = Integer(c.Value("FORTIS_NATIVE_HTTPS", "0"), 1) != 0;
  c.require_mount = Integer(c.Value("FORTIS_NATIVE_REQUIRE_MOUNT", "1"), 1) != 0;
  Require(!c.require_mount || c.runtime_state == "/run/fortis-node",
          "production container state must use its dedicated runtime directory");
  c.attempts = static_cast<unsigned>(Integer(c.Value("FORTIS_NATIVE_HEALTH_ATTEMPTS", "30"), 120));
  c.observation = static_cast<unsigned>(Integer(c.Value("FORTIS_NATIVE_OBSERVE_SECONDS", "30"), 600));
  c.samples = static_cast<unsigned>(Integer(c.Value("FORTIS_NATIVE_MIN_REQUESTS", "10"), 100000));
  c.observation_timeout = static_cast<unsigned>(Integer(
      c.Value("FORTIS_NATIVE_OBSERVE_TIMEOUT_SECONDS", std::to_string(std::max(120U, c.observation * 3))), 1800));
  Require(c.observation_timeout > c.observation, "observation deadline must exceed observation duration");
  c.preflight = Integer(c.Value("FORTIS_NATIVE_PREFLIGHT", "1"), 1) != 0;
  c.verify_pid = Integer(c.Value("FORTIS_NATIVE_VERIFY_PID", "1"), 1) != 0;
  c.emulated_fixture = Integer(c.Value("FORTIS_NATIVE_EMULATED_FIXTURE", "0"), 1) != 0;
  Require(!c.emulated_fixture || !c.require_mount, "emulated identity is restricted to isolated fixtures");
  Require(c.attempts && (!c.require_mount || (c.observation >= 10 && c.samples >= 1 && c.preflight && c.verify_pid)),
          "production admission requires preflight, identity and observation");
  if (forwarded) Require(c.Environment("FORTIS_HEALTH_PORT") == "8081", "dedicated health environment mismatch");
  c.sandbox_control = c.Value("FORTIS_NATIVE_SANDBOX_CONTROL");
  if (!c.sandbox_control.empty()) {
    SafePath(c.sandbox_control);
    Require(!c.require_mount || c.sandbox_control == "/run/fortis-sandbox",
            "production sandbox control must use its dedicated runtime directory");
    if (!stopping) {
      Require(fs::is_directory(c.sandbox_control) && fs::canonical(c.sandbox_control) == c.sandbox_control,
              "sandbox control directory absent or symlinked");
      struct stat control {};
      Check(lstat(c.sandbox_control.c_str(), &control), "inspect sandbox control directory");
      Require(control.st_uid == geteuid() && !(control.st_mode & 0022), "unsafe sandbox control directory");
      if (c.require_mount) {
        for (const auto& parent : {fs::path("/"), fs::path("/run")}) {
          Check(lstat(parent.c_str(), &control), "inspect sandbox control parent");
          Require(S_ISDIR(control.st_mode) && control.st_uid == 0 && !(control.st_mode & 0022),
                  "unsafe sandbox control parent");
        }
      }
    }
  }
  c.domain = c.Environment("FORTIS_HTTPS_DOMAIN");
  c.ca = c.Value("FORTIS_NATIVE_TLS_CA", "/etc/ssl/certs/ca-certificates.crt");
  if (c.https) {
    c.http = static_cast<unsigned>(Integer(c.Value("FORTIS_NATIVE_HTTP_PORT", "80"), 65535));
    Require(forwarded && c.http && c.http != c.health && c.http != c.port && c.domain.size() <= 253 &&
                std::all_of(c.domain.begin(), c.domain.end(),
                            [](char ch) {
                              return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-';
                            }),
            "invalid direct TLS configuration");
    for (const char* name : {"FORTIS_NATIVE_CERTIFICATES", "FORTIS_NATIVE_ACME_CHALLENGES"}) {
      const fs::path mount = c.Value(name);
      SafePath(mount);
      Require(
          fs::is_directory(mount) && fs::canonical(mount) == mount && !Within(c.data, mount) && !Within(mount, c.data),
          "unsafe TLS mount");
    }
    c.certificates = c.Value("FORTIS_NATIVE_CERTIFICATES");
    c.challenges = c.Value("FORTIS_NATIVE_ACME_CHALLENGES");
    c.address = c.Environment("FORTIS_HTTPS_IP");
    // The certificate process is unprivileged and cannot enter the
    // administrator's own directory, so its account and staging live apart.
    c.acme_state = c.Value("FORTIS_NATIVE_ACME_STATE", "/var/lib/fortis-acme");
    SafePath(c.acme_state);
    c.acme_directory = c.Value("FORTIS_NATIVE_ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory");
    c.acme_contact = c.Value("FORTIS_NATIVE_ACME_CONTACT");
    c.acme_user = static_cast<unsigned>(Integer(c.Value("FORTIS_NATIVE_ACME_USER", "10002"), 65534));
    c.acme_loopback = Integer(c.Value("FORTIS_NATIVE_ACME_LOOPBACK", "0"), 1) != 0;
    Require(c.acme_user >= 1000 && c.acme_user != 10001 && (!c.acme_loopback || !c.require_mount),
            "invalid certificate process settings");
    Require(c.Environment("FORTIS_HTTPS_CERT_DIR") == "/certificates" &&
                c.Environment("FORTIS_ACME_CHALLENGE_DIR") == "/acme" &&
                c.Environment("FORTIS_HTTP_REDIRECT_PORT") == "8082" && !c.Environment("FORTIS_HTTPS_IP").empty() &&
                fs::is_regular_file(c.ca),
            "direct HTTPS environment and mounts disagree");
  } else Require(c.Environment("FORTIS_HTTPS_CERT_DIR").empty(), "TLS environment requires direct ingress");
  if (!stopping)
    Require(fs::is_directory(c.data) && fs::canonical(c.data) == c.data,
            "persistent data directory absent or symlinked");
  if (!stopping && c.require_mount) {
    Require(MountPoint(c.data.parent_path()) && c.backups.parent_path() == c.data.parent_path(),
            "persistent parent mount and sibling backups required");
  }
  Directory(c.root, 0700);
  Require(fs::canonical(c.root) == c.root, "release root must be canonical");
  struct stat owner {};
  Check(stat(c.root.c_str(), &owner), "stat release root");
  Require(owner.st_uid == geteuid(), "release root must belong to administrator");
  return c;
}
/** True when the configured name has a certificate in the selected generation. */
bool DomainServed(const Settings& c) {
  return c.https && !c.domain.empty() && fs::is_regular_file(c.certificates / "current" / "domain.pem");
}
/** The name this machine's node answers to over TLS right now. */
std::string ServedName(const Settings& c) { return DomainServed(c) ? c.domain : c.address; }
NodeMount Bound(std::string destination, const fs::path& source, bool writable, bool executable = false) {
  std::vector<std::string> options{"rbind", writable ? "rw" : "ro", "nosuid", "nodev"};
  if (!executable) options.emplace_back("noexec");
  return {std::move(destination), "bind", source.string(), std::move(options)};
}
std::vector<NodeMount> BaseMounts(const Settings& c) {
  std::vector<NodeMount> mounts{{"/proc", "proc", "proc", {"nosuid", "noexec", "nodev"}},
                                {"/dev", "tmpfs", "tmpfs", {"nosuid", "noexec", "strictatime", "mode=755", "size=64k"}},
                                {"/tmp", "tmpfs", "tmpfs", {"nosuid", "noexec", "nodev", "mode=1777", "size=16m"}}};
  if (fs::is_regular_file(c.ca)) mounts.push_back(Bound("/etc/ssl/certs/ca-certificates.crt", c.ca, false));
  return mounts;
}
// The serving node: the same restrictions it had as a Docker container, with
// the host's network and nothing to bind (the keeper hands it its sockets).
NodeContainer NodeRuntime(const Settings& c) {
  NodeContainer node;
  node.args = {"/app/current/fortis-node", "8080"};
  auto environment = c.environment;
  environment["FORTIS_KV_DIR"] = "/data";
  environment["FORTIS_KV_LOCK_MODE"] = "native";
  environment.try_emplace("FORTIS_CA_BUNDLE_PATH", "/etc/ssl/certs/ca-certificates.crt");
  // A name without its certificate would stop the node from starting, so the
  // node serves the address alone until the name's certificate exists.
  if (c.https && !DomainServed(c)) environment.erase("FORTIS_HTTPS_DOMAIN");
  node.env.reserve(environment.size());
  for (const auto& [key, value] : environment) {
    std::string entry = key;
    entry += '=';
    entry += value;
    node.env.push_back(std::move(entry));
  }
  node.mounts = BaseMounts(c);
  for (const char* file : {"/etc/resolv.conf", "/etc/hosts"})
    if (fs::is_regular_file(file)) node.mounts.push_back(Bound(file, file, false));
  node.mounts.push_back(Bound("/app", c.root / "app", false, true));
  node.mounts.push_back(Bound("/data", c.data, true));
  node.mounts.push_back(Bound("/deployment", c.root / "deployment/public", false));
  if (!c.sandbox_control.empty()) node.mounts.push_back(Bound("/run/fortis-sandbox", c.sandbox_control, false));
  if (c.https) {
    node.mounts.push_back(Bound("/certificates", c.Value("FORTIS_NATIVE_CERTIFICATES"), false));
    node.mounts.push_back(Bound("/acme", c.Value("FORTIS_NATIVE_ACME_CHALLENGES"), false));
  }
  node.seccomp = !c.emulated_fixture;
  return node;
}
// A candidate under test: temporary data, no secrets, no configuration and an
// empty network namespace. Only the keeper's loopback socket reaches it.
NodeContainer PreflightRuntime(const Settings& c, const fs::path& release) {
  Require(fs::is_directory(release) && !fs::is_symlink(fs::symlink_status(release)), "preflight release absent");
  NodeContainer node;
  node.args = {"/app/current/fortis-node", "8080"};
  node.env = {"NODE_ENV=development", "FORTIS_KV_DIR=/data",
              "FORTIS_CA_BUNDLE_PATH=/etc/ssl/certs/ca-certificates.crt"};
  node.mounts = BaseMounts(c);
  node.mounts.push_back(
      {"/data", "tmpfs", "tmpfs", {"nosuid", "noexec", "nodev", "uid=10001", "gid=10001", "mode=0700", "size=64m"}});
  node.mounts.push_back(Bound("/app/current", release, false, true));
  node.tasks = 256;
  node.host_network = false;
  node.seccomp = !c.emulated_fixture;
  return node;
}
// Ports 80 and 443 (or the configured ones) belong to the keeper, so nothing
// unprivileged can take them and connections wait while the node restarts.
std::vector<NodeListener> Listeners(const Settings& c) {
  std::vector<NodeListener> listeners{{c.https ? "0.0.0.0" : "127.0.0.1", c.port, 8080}};
  if (c.https) listeners.push_back({"0.0.0.0", c.http, 8082});
  if (c.health != c.port) listeners.push_back({"127.0.0.1", c.health, 8081});
  return listeners;
}
// The stand-in for the public HTTP port while no node serves: this same
// program, alone in a container with the challenge directory and no network
// of its own. It holds one socket and can read nothing else.
NodeContainer PageRuntime(const Settings& c) {
  Require(c.https, "the page server needs a public HTTP port");
  NodeContainer page;
  page.args = {"/page/native-controller", "/acme", "page-server", "/pages"};
  page.mounts = {{"/proc", "proc", "proc", {"nosuid", "noexec", "nodev"}},
                 {"/dev", "tmpfs", "tmpfs", {"nosuid", "noexec", "strictatime", "mode=755", "size=64k"}}};
  page.mounts.push_back(Bound("/page/native-controller", self_path, false, true));
  page.mounts.push_back(Bound("/acme", c.challenges, false));
  // The first page and health, written by the orchestrator; read-only here.
  page.mounts.push_back(Bound("/pages", c.root / "deployment/public", false));
  page.memory_bytes = 64ULL * 1024 * 1024;
  page.tasks = 16;
  page.user = 10003;
  page.host_network = false;
  page.seccomp = !c.emulated_fixture;
  return page;
}
// Read the configuration again for every start: a change applies without
// restarting the keeper.
std::vector<NodeListener> PlannedListeners(const fs::path& config) { return Listeners(Configure(config, true)); }
NodeContainer PlannedNode(const fs::path& config) { return NodeRuntime(Configure(config, false)); }
NodeContainer PlannedPage(const fs::path& config) { return PageRuntime(Configure(config, true)); }
NodeContainer PlannedPreflight(const fs::path& config, const fs::path& release) {
  return PreflightRuntime(Configure(config, false), release);
}
struct Reply {
  int status = 0;
  std::string body;
};
bool LoopbackOnly(void*, uint32_t address) { return (address >> 24) == 127; }
/** One GET to this machine's own node on loopback. `host` is the name the
 * node answers to: with `ca` the connection is TLS, and the certificate must
 * be valid for that name under that trust file. No answer within the time
 * limit, a refused connection or a failed handshake gives no value. */
std::optional<Reply> Fetch(const std::string& host, unsigned port, const std::string& path, const char* ca,
                           uint32_t timeout_ms) {
  const auto port_text = std::to_string(port);
  http::OutboundRequest request;
  request.host = host.c_str();
  request.port = port_text.c_str();
  request.path = path.c_str();
  request.ca_file = ca;
  request.plaintext = ca == nullptr;
  request.connect_ipv4 = 0x7f000001;
  request.allow_address = LoopbackOnly;
  request.timeout_ms = timeout_ms;
  request.user_agent = "FortisNet-Orchestrator";
  std::vector<unsigned char> body(request.max_response_bytes);
  const auto response = http::OutboundHttpsRequest(request, body.data(), body.size());
  if (response.error != http::OutboundError::kNone) return std::nullopt;
  return Reply{response.status, std::string(reinterpret_cast<const char*>(body.data()), response.body_length)};
}
bool Answers(unsigned port, const std::string& path) {
  const auto reply = Fetch("127.0.0.1", port, path, nullptr, 2000);
  return reply && reply->status >= 200 && reply->status < 300;
}
KeeperPlan Plan(const fs::path& config) {
  const auto initial = Configure(config, true);
  KeeperPlan plan;
  plan.root = initial.root;
  plan.runtime_state = initial.runtime_state;
  plan.name = initial.name;
  plan.config = config;
  plan.listeners = PlannedListeners;
  plan.node = PlannedNode;
  plan.preflight = PlannedPreflight;
  plan.page = PlannedPage;
  return plan;
}
uint64_t Little(std::string_view bytes, size_t at, size_t count) {
  Require(at <= bytes.size() && count <= bytes.size() - at && count <= 8, "ELF field out of bounds");
  uint64_t value = 0;
  for (size_t i = 0; i < count; ++i)
    value |= static_cast<uint64_t>(static_cast<unsigned char>(bytes[at + i])) << (8 * i);
  return value;
}
/** Signed by the release key, or by the recovery key when one is installed. */
bool Signed(const Settings& c, std::string_view message, std::string_view signature) {
  return SignatureValid(c.key, message, signature) ||
         (!c.recovery_key.empty() && SignatureValid(c.recovery_key, message, signature));
}
Release Verify(const Settings& c, const fs::path& directory) {
  SafePath(directory);
  Require(fs::is_directory(directory) && !fs::is_symlink(fs::symlink_status(directory)),
          "release directory absent or symlinked");
  const auto manifest = Read(directory / "manifest", 1024);
  Require(Signed(c, manifest, Read(directory / "manifest.sig", 16384)), "release signature verification failed");
  const auto fields = KeyValues(manifest);
  Require(fields.size() == 7 || fields.size() == 9, "manifest field count mismatch");
  const auto get = [&](const char* name) -> std::string {
    const auto it = fields.find(name);
    Require(it != fields.end(), "manifest field absent");
    return it->second;
  };
  const auto format = get("format");
  Require((format == "1" && fields.size() == 7) || (format == "2" && fields.size() == 9),
          "unsupported release manifest");
  Release release{get("version"), get("sha256"), "", Integer(get("bytes"), 134217728)};
  if (get("architecture") != kArchitecture)
    throw std::runtime_error("this release is built for another processor architecture; this host is " +
                             std::string(kArchitecture));
  Require(Token(release.version) && Hex(release.digest) && release.bytes >= 64 &&
              get("runtime") == "linux-musl-static-v1" && get("storage_epoch") == "1",
          "release identity or compatibility refused");
  if (format == "2") {
    release.metadata = true;
    release.source = get("source_commit");
    if (release.source == "unknown") release.source.clear();
    Require(
        (release.source.empty() || Hex(release.source, 40) || Hex(release.source)) && Hex(get("build_inputs_sha256")),
        "invalid source provenance");
  }
  const auto binary = Read(directory / "fortis-node", 134217728);
  Require(binary.size() == release.bytes && DigestBytes(binary) == release.digest, "executable hash mismatch");
  Require(binary.size() >= 64 &&
              std::string_view(binary).substr(0, 7) == std::string_view("\x7f"
                                                                        "ELF\x02\x01\x01",
                                                                        7) &&
              Little(binary, 18, 2) == kElfMachine && (Little(binary, 16, 2) == 2 || Little(binary, 16, 2) == 3),
          "invalid executable ELF");
  const auto offset = Little(binary, 32, 8), size = Little(binary, 54, 2), count = Little(binary, 56, 2);
  Require(size >= 56 && offset <= binary.size() && count <= (binary.size() - offset) / size,
          "invalid ELF program bounds");
  bool stack = false;
  for (uint64_t i = 0; i < count; ++i) {
    const auto at = static_cast<size_t>(offset + i * size);
    const auto kind = Little(binary, at, 4);
    Require(kind != 3, "ELF interpreter refused");
    if (kind == 0x6474e551) {
      stack = true;
      Require(!(Little(binary, at + 4, 4) & 1) && Little(binary, at + 40, 8) >= 2 * 1024 * 1024,
              "non-executable 2 MiB stack required");
    }
    if (kind == 2) {
      const auto start = Little(binary, at + 8, 8), length = Little(binary, at + 32, 8);
      Require(start <= binary.size() && length <= binary.size() - start && length % 16 == 0,
              "invalid ELF dynamic bounds");
      bool terminated = false;
      for (uint64_t position = start; position < start + length; position += 16) {
        const auto tag = Little(binary, static_cast<size_t>(position), 8);
        Require(tag != 1 && tag != 15 && tag != 29, "shared library or search path refused");
        if (!tag) terminated = true;
      }
      Require(terminated, "unterminated ELF dynamic table");
    }
  }
  Require(stack, "ELF thread stack declaration absent");
  return release;
}
std::string Target(const fs::path& link) {
  if (!fs::is_symlink(fs::symlink_status(link))) return "NONE";
  const auto value = fs::read_symlink(link).string();
  Require(value.starts_with("releases/") && Token(std::string_view(value).substr(9)), "invalid recovery target");
  return value;
}
void Select(const Settings& c, std::string_view target, std::string_view name = "current") {
  Require(target.starts_with("releases/") && Token(target.substr(9)), "invalid release selector");
  const auto temporary = c.root / "app" / (".switch-" + std::to_string(getpid()));
  fs::create_symlink(target, temporary);
  Check(::rename(temporary.c_str(), (c.root / "app" / name).c_str()), "select release");
  SyncDirectory(c.root / "app");
}

class Controller final {
 public:
  explicit Controller(Settings settings)
      : c_(std::move(settings)),
        lock_(Check(::open((c_.root / "update.lock").c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600),
                    "update lock")) {
    const char* wait_value = std::getenv("FORTIS_NATIVE_WAIT_LOCK");
    const bool wait = wait_value && std::string_view(wait_value) == "1";
    while (flock(lock_.get(), LOCK_EX | LOCK_NB) != 0) {
      Require((errno == EWOULDBLOCK || errno == EAGAIN) && wait, "another update is active");
      Pause(100);
    }
    Directory(c_.root / "app/releases", 0755);
    Check(chmod((c_.root / "app").c_str(), 0755), "app permissions");
    Directory(c_.backups, 0700);
    Require(fs::canonical(c_.backups) == c_.backups, "backup path must be canonical");
    // Keep a small physical reserve available to publish recovery metadata if
    // the host filesystem fills after the handover journal was committed.
    if (fs::exists(c_.root / "recovery.reserve") && fs::space(c_.root).available < 256 * 1024) {
      fs::remove(c_.root / "recovery.reserve");
      SyncDirectory(c_.root);
    }
    ledger_.emplace(c_.root / "deployment");
  }
  void Action(const std::string& action, const fs::path& package = {});
  bool Restarted() const { return restarted_; }

 private:
  Settings c_;
  FileDescriptor lock_;
  std::optional<ReleaseLedger> ledger_;
  bool recovering_ = false, restarted_ = false;
  IncidentCounts baseline_nodes_, baseline_providers_;
  double baseline_p95_ = 0;
  std::string expected_metadata_;
  // The keeper owns the listening sockets and is the node's parent. A missing
  // keeper means nothing is running; starting work brings one up.
  std::string Keep(std::string_view request, unsigned timeout = 30) {
    if (!KeeperPresent(c_.root)) SpawnKeeper();
    return KeeperRequest(c_.root, request, timeout);
  }
  void SpawnKeeper() const;
  std::optional<std::string> State() const {
    try {
      return KeeperRequest(c_.root, "state", 5);
    } catch (const std::runtime_error&) { return std::nullopt; }
  }
  bool Running() const {
    const auto state = State();
    return state && KeeperField(*state, "running") == 1;
  }
  // One process instance: the host PID and the keeper's start time for it.
  std::string Instance() const {
    const auto state = State();
    Require(state && KeeperField(*state, "running") == 1, "running process identity absent");
    return std::to_string(KeeperField(*state, "pid")) + "\n" + std::to_string(KeeperField(*state, "started")) + "\n";
  }
  bool Certificates(bool only_if_unusable);
  void RenewCertificates();
  HostFacts Facts(std::string_view state);
  void InstallBakedRelease();
  bool FindPublicAddress();
  void PrepareFetchFolders();
  std::string waiting_for_;
  void PublishHealth(std::string_view state = {});
  void ShowPagesWhileStopped();
  ReleaseIndex CheckReleases();
  fs::path FetchRelease(const std::string& version);
  void ListReleases();
  fs::path CopyDatabase(const std::string& label);
  FileDescriptor LockDatabase() const;
  void Backup();
  void Restore(const fs::path& folder);
  void Preflight(const fs::path& directory, uint64_t id);
  void CleanPreflight(uint64_t id);
  void Start(std::string reason, uint64_t previous = 0);
  void Stop(std::string reason);
  void Recover();
  void Update(const fs::path& package);
  void Adopt();
  void Identity(const Release& release);
  void Boot(Deployment& record, const Release& release);
  bool Healthy(std::string_view expected_digest = {}, unsigned attempts = 0, bool require_persisted = true);
  std::string Api(const std::string& path, bool status = false);
  void Observe(Deployment& record);
  void Phase(Deployment& record, const char* phase) {
    record.phase = phase;
    ledger_->Save(record);
  }
  void Quarantine(const std::string& digest, std::string_view reason) {
    Directory(c_.root / "quarantine", 0700);
    AtomicFile(c_.root / "quarantine" / digest, reason);
  }
};

void Controller::SpawnKeeper() const {
  Require(!self_path.empty(), "controller executable path unknown");
  Directory(c_.root / "log", 0700);
  FileDescriptor log(
      Check(::open((c_.root / "log/keeper.log").c_str(), O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600),
            "open keeper log"));
  std::string program = self_path, config = c_.config.string(), mode = "keeper";
  char* const argv[] = {program.data(), config.data(), mode.data(), nullptr};
  const pid_t child = fork();
  Check(child < 0 ? -1 : 0, "fork keeper");
  if (!child) {
    // Detach fully: the keeper outlives this command and any terminal.
    if (setsid() < 0 || fork() != 0) _exit(0);
    const int null = ::open("/dev/null", O_RDWR);
    if (null < 0 || dup2(null, STDIN_FILENO) < 0 || dup2(null, STDOUT_FILENO) < 0 || dup2(log.get(), STDERR_FILENO) < 0)
      _exit(126);
    for (int descriptor = 3; descriptor < 256; ++descriptor) (void)close(descriptor);
    ::execv(argv[0], argv);
    _exit(127);
  }
  int status = 0;
  while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
  for (unsigned attempt = 0; attempt < 100; ++attempt) {
    if (KeeperPresent(c_.root)) return;
    Pause(50);
  }
  throw std::runtime_error("node keeper did not start; see log/keeper.log");
}
std::string Controller::Api(const std::string& path, bool status) {
  const auto reply = c_.https ? Fetch(ServedName(c_), c_.port, path, c_.ca.c_str(), 3000)
                              : Fetch("127.0.0.1", c_.port, path, nullptr, 3000);
  Require(reply.has_value(), "node did not answer on its public port");
  if (status) return std::to_string(reply->status);
  Require(reply->status >= 200 && reply->status < 300, "node refused a status request");
  return reply->body;
}
bool Controller::Healthy(std::string_view expected_digest, unsigned attempts, bool require_persisted) {
  if (!attempts) attempts = c_.attempts;
  const auto deadline = SteadyClock::now() + std::chrono::seconds(60);
  for (unsigned attempt = 0; attempt < attempts && SteadyClock::now() < deadline; ++attempt) {
    try {
      if (Running() && Answers(c_.health, "/healthz")) {
        const Json doc(Api("/errorsz"));
        const auto operational = doc.Field(doc.Root(), "operational");
        if ((!require_persisted || doc.Is(doc.Field(operational, "persisted"), codec::BoundedJsonType::kTrue)) &&
            doc.Is(doc.Field(operational, "writeFailed"), codec::BoundedJsonType::kFalse) &&
            Api("/v1/networks", true) == "401") {
          if (!expected_digest.empty()) {
            const auto snapshot = Api("/releasesz");
            const Json metadata(snapshot);
            Require(metadata.Is(metadata.Field(metadata.Root(), "managed"), codec::BoundedJsonType::kTrue),
                    "controller metadata mount unavailable");
            if (require_persisted) {
              // Identity() already verified /proc/PID/exe. A normal restart has
              // no serving row until readiness passes: prove the exact mounted
              // snapshot instead of requiring that row prematurely.
              Require(snapshot == Read(ledger_->PublicDirectory() / "current.json"),
                      "worker metadata does not match controller snapshot");
            } else {
              // Observation tolerates the route's one-second snapshot cache.
              // The artifact identity remains unchanged across those snapshots.
              auto identity = metadata.Field(metadata.Root(), "candidate");
              if (metadata.Is(identity, codec::BoundedJsonType::kNull))
                identity = metadata.Field(metadata.Root(), "current");
              Require(metadata.String(metadata.Field(identity, "sha256")) == expected_digest,
                      "worker metadata identity mismatch");
            }
          }
          return true;
        }
      }
    } catch (const std::runtime_error&) {
      if (interrupted) throw;
    }
    if (attempt + 1 < attempts) Pause(1000);
  }
  return false;
}
void Controller::Identity(const Release& release) {
  if (!c_.verify_pid)
    return;  // Explicit isolated-fixture option; forbidden on mounted production
             // data.
  const auto instance = Instance();
  const auto pid = instance.substr(0, instance.find('\n'));
  Require(Integer(pid, INT32_MAX) > 1, "running process identity absent");
  bool exact = Digest(c_.proc / pid / "exe") == release.digest;
  if (!exact && c_.emulated_fixture) {
    // An emulated x86 fixture executes Rosetta/QEMU as /proc/PID/exe. This
    // explicit fixture mode checks the emulator command and the read-only
    // release mount instead. Production always requires the native hash.
    const auto executable = fs::read_symlink(c_.proc / pid / "exe").string();
    const auto command = Read(c_.proc / pid / "cmdline", 8192);
    const std::string argument("/app/current/fortis-node\0", 25);
    const bool emulator = executable == "/run/rosetta/rosetta" || fs::path(executable).filename() == "qemu-x86_64" ||
                          fs::path(executable).filename() == "qemu-x86_64-static";
    exact = emulator && command.find(argument) != std::string::npos &&
            Digest(c_.proc / pid / "root/app/current/fortis-node") == release.digest;
  }
  Require(exact && Instance() == instance, "running executable does not match signed candidate");
  AtomicFile(c_.root / "worker.identity", instance);
}
/** What the first page and the health report say right now. `state`, when
 * given, names what the orchestrator is doing ("updating", "recovering");
 * otherwise it is read off the host. Reads only local files and the node's
 * loopback health port. */
HostFacts Controller::Facts(std::string_view state) {
  using Health = HealthCheck::State;
  HostFacts facts;
  facts.generated_ms = NowMs();
  facts.orchestrator_version = FORTIS_ORCHESTRATOR_VERSION;
  facts.architecture = kArchitecture;
  const auto selected = Target(c_.root / "app/current");
  const bool installed = selected != "NONE", running = installed && Running();
  facts.node_state = !state.empty()                    ? std::string(state)
                     : !installed                      ? "not-installed"
                     : fs::exists(c_.root / "pending") ? "updating"
                     : running                         ? "serving"
                                                       : "stopped";
  if (installed) {
    // The manifest was verified when the release was installed.
    try {
      const auto fields = KeyValues(Read(c_.root / "app" / selected / "manifest", 1024));
      facts.node_version = fields.at("version");
      facts.node_sha256 = fields.at("sha256");
    } catch (const std::exception&) { facts.node_version = "unreadable"; }
  }
  facts.runs_in = HostKind();
  facts.orchestrator.push_back({"Orchestrator",
                                facts.runs_in == "container"
                                    ? "Supervising this host. It runs in a container."
                                    : "Supervising this host. It runs on a machine of its own.",
                                Health::kHealthy});
  facts.waiting_for = waiting_for_;
  if (!waiting_for_.empty()) facts.orchestrator.push_back({"Setup", waiting_for_, Health::kWaiting});
  if (c_.https) {
    facts.address = c_.address;
    facts.domain = c_.domain;
    HealthCheck certificate{"Certificate", "Not issued yet.", Health::kWaiting};
    try {
      const auto validity = acme::ReadValidity(Read(c_.certificates / "current/ip.pem", 64 * 1024));
      const uint64_t now = facts.generated_ms / 1000;
      const bool expired = validity.not_after <= now + 3600;
      const bool due = !expired && validity.not_after - now < (validity.not_after - validity.not_before) / 3;
      certificate.detail = (expired ? "Expired or about to: "
                            : due   ? "Renewal is due. Valid until "
                                    : "Valid until ") +
                           PageDate(validity.not_after * 1000) + ".";
      certificate.state = expired ? Health::kFailing : due ? Health::kWaiting : Health::kHealthy;
    } catch (const std::exception&) {
      // No certificate yet: the first one is requested before the node starts.
      certificate.state = Health::kWaiting;
    }
    facts.orchestrator.push_back(std::move(certificate));
  }
  facts.store_configured = !c_.store.empty();
  if (facts.store_configured) {
    HealthCheck releases{"Releases", "The release store has not been checked yet.", Health::kWaiting};
    try {
      const auto checked = Integer(std::string_view(Read(c_.root / "releases.checked", 32)).substr(0, 13));
      const bool recent = facts.generated_ms < checked + 48ULL * 3600 * 1000;
      releases.detail = "Last checked " + PageDate(checked) + (recent ? "." : ": more than two days ago.");
      releases.state = recent ? Health::kHealthy : Health::kWaiting;
      const auto index = ParseReleaseIndex(Read(c_.root / "releases.index", 256 * 1024));
      if (!index.releases.empty()) facts.newest_release = index.releases.back().version;
    } catch (const std::exception&) { releases.state = Health::kWaiting; }
    facts.orchestrator.push_back(std::move(releases));
  }
  if (fs::is_directory(c_.root / "staged"))
    for (const auto& entry : fs::directory_iterator(c_.root / "staged")) {
      const auto name = entry.path().filename().string();
      if (Token(name) && name.front() != '.' && "releases/" + name != selected) facts.staged.push_back(name);
    }
  std::sort(facts.staged.begin(), facts.staged.end());
  struct statvfs disk {};
  if (statvfs(c_.data.c_str(), &disk) == 0) {
    facts.disk_bytes = static_cast<uint64_t>(disk.f_blocks) * disk.f_frsize;
    facts.disk_free_bytes = static_cast<uint64_t>(disk.f_bavail) * disk.f_frsize;
  }
  // An update needs room for a backup and the new release.
  const bool room = facts.disk_free_bytes > 300ULL * 1024 * 1024;
  facts.orchestrator.push_back(
      {"Disk", room ? "Enough free space for an update." : "Less than 300 MB free: an update may not fit.",
       room ? Health::kHealthy : Health::kFailing});
  uint64_t newest_backup = 0;
  if (fs::is_directory(c_.backups))
    for (const auto& entry : fs::directory_iterator(c_.backups)) {
      const auto name = entry.path().filename().string();
      const auto stamp = name.substr(0, name.find('-'));
      if (stamp.size() == 13 && std::all_of(stamp.begin(), stamp.end(), [](char ch) { return ch >= '0' && ch <= '9'; }))
        newest_backup = std::max(newest_backup, Integer(stamp));
    }
  facts.orchestrator.push_back({"Backups",
                                newest_backup ? "Last backup " + PageDate(newest_backup) + ", kept on this machine."
                                              : "None yet. One is made before every update.",
                                Health::kHealthy});
  const long processors = sysconf(_SC_NPROCESSORS_ONLN), pages = sysconf(_SC_PHYS_PAGES), page = sysconf(_SC_PAGE_SIZE);
  facts.processors = processors > 0 ? static_cast<unsigned>(processors) : 0;
  facts.memory_bytes = pages > 0 && page > 0 ? static_cast<uint64_t>(pages) * static_cast<uint64_t>(page) : 0;
  if (installed) {
    if (facts.node_state == "serving") {
      const bool answers = Answers(c_.health, "/healthz");
      facts.node.push_back({"Running", "The node's process is running.", Health::kHealthy});
      facts.node.push_back(
          {"Answering", answers ? "The node answers its health check." : "The node does not answer its health check.",
           answers ? Health::kHealthy : Health::kFailing});
    } else {
      const bool busy = facts.node_state == "updating" || facts.node_state == "recovering";
      facts.node.push_back(
          {"Running",
           busy ? "Stopped for a moment while the release is changed." : "The node's process is not running.",
           busy ? Health::kWaiting : Health::kFailing});
    }
  }
  return facts;
}
/** Write the pages. A page that cannot be written never fails the work in
 * hand: the reader then sees an older report, which says how old it is. */
void Controller::PublishHealth(std::string_view state) {
  try {
    PublishPages(ledger_->PublicDirectory(), Facts(state));
  } catch (const std::exception& error) { std::cerr << "Pages not updated: " << error.what() << '\n'; }
}
/** While no node serves, the page server shows the pages on the public HTTP
 * port. The keeper stops it again when a node starts. */
void Controller::ShowPagesWhileStopped() {
  if (!c_.https) return;
  try {
    (void)Keep("page-start", 40);
  } catch (const std::exception& error) { std::cerr << "Page server not started: " << error.what() << '\n'; }
}
/** On a new host: install the node release that came with the image, once
 * everything it needs is in place. Called at every supervisor tick while
 * nothing is installed, so a host that is waiting (for the clock, for a
 * certificate) gets there by itself, and says on its first page what it is
 * waiting for. Whatever outside the release can fail is settled before the
 * release is committed to, so such a failure is never blamed on it. */
void Controller::InstallBakedRelease() {
  if (c_.baked_release.empty() || !fs::is_directory(c_.baked_release)) return;
  Release release;
  try {
    release = Verify(c_, c_.baked_release);
  } catch (const std::exception& error) {
    waiting_for_ = std::string("The node release in the image cannot be used: ") + error.what() + ".";
    return;
  }
  if (fs::exists(c_.root / "quarantine" / release.digest)) {
    waiting_for_ = "Installing the node release failed. An operator needs to look at this host.";
    return;
  }
  if (c_.require_clock && !ClockSynchronised()) {
    waiting_for_ = "Waiting for the clock to be set by the time service.";
    return;
  }
  if (c_.https) {
    // The settings are read again at the next tick, with the address found.
    if (!c_.acme_loopback && !PublicAddress(c_.address)) {
      (void)FindPublicAddress();
      return;
    }
    const auto marker = c_.root / "certificates.next";
    uint64_t not_before_ms = 0;
    try {
      if (fs::exists(marker)) not_before_ms = Integer(Read(marker, 32));
    } catch (const std::runtime_error&) { not_before_ms = 0; }
    if (NowMs() < not_before_ms) {
      waiting_for_ = "Waiting to ask for a certificate again; the last request did not succeed.";
      return;
    }
    waiting_for_ = "Asking the certificate authority for a certificate.";
    PublishHealth();
    try {
      (void)Certificates(true);
    } catch (const std::exception& error) {
      if (interrupted) throw;
      std::cerr << "First certificate not obtained: " << error.what() << '\n';
      AtomicFile(marker, std::to_string(NowMs() + 10 * 60 * 1000));
      waiting_for_ = "The certificate authority did not issue a certificate yet. Trying again in ten minutes.";
      ShowPagesWhileStopped();
      return;
    }
  }
  waiting_for_ = "Installing the node.";
  PublishHealth();
  try {
    Update(c_.baked_release);
    waiting_for_.clear();
  } catch (const std::exception& error) {
    if (interrupted) throw;
    std::cerr << "First install failed: " << error.what() << '\n';
    waiting_for_ = "Installing the node release failed. An operator needs to look at this host.";
    ShowPagesWhileStopped();
  }
}
StoreSettings Store(const Settings& c) {
  Require(!c.store.empty(), "no release store is configured (FORTIS_NATIVE_RELEASE_STORE)");
  // A store holds one tree per processor architecture; a host reads its own.
  return {c.store + "/" + std::string(kArchitecture), c.ca, "FortisNet-Orchestrator/1", c.store_loopback};
}
void Controller::PrepareFetchFolders() {
  Directory(c_.fetch_state, 0700);
  Directory(c_.fetch_state / "staging", 0700);
  if (geteuid() == 0)
    for (const auto& path : {c_.fetch_state, c_.fetch_state / "staging"})
      Check(chown(path.c_str(), c_.fetch_user, c_.fetch_user), "fetch process ownership");
}
/** A host whose own interface shows a private address (inside a container,
 * or on a cloud that translates addresses) asks the lookup services which
 * public address it is seen under, and writes the answer into the node's
 * environment as FORTIS_HTTPS_IP. The answer is only believed so far as to
 * ask for a certificate: the certificate authority then connects to that
 * address itself, and a wrong one simply gets no certificate. Every service
 * that answers must give the same public address. Returns true when the
 * address was found and saved; otherwise the first page says what to do. */
bool Controller::FindPublicAddress() {
  const std::string unknown =
      std::string(
          "This host's own network address is not a public one, and its public address could not be "
          "found, so no certificate can be issued. ") +
      (HostKind() == "container" ? "Start the container again with FORTIS_HTTPS_IP set to the server's public address."
                                 : "Set FORTIS_HTTPS_IP in " + c_.env.string() + " to its public address.");
  waiting_for_ = unknown;
  if (c_.address_lookup.empty()) return false;
  const auto marker = c_.root / "address.next";
  uint64_t not_before_ms = 0;
  try {
    if (fs::exists(marker)) not_before_ms = Integer(Read(marker, 32));
  } catch (const std::runtime_error&) { not_before_ms = 0; }
  if (NowMs() < not_before_ms) return false;
  AtomicFile(marker, std::to_string(NowMs() + 10 * 60 * 1000));
  PrepareFetchFolders();
  const auto worker = Command({self_path, c_.config.string(), "fetch-worker", "address"}, 200, 16 * 1024);
  if (!worker.output.empty()) std::cerr << worker.output;
  if (worker.exit != 0) return false;
  // Nothing the unprivileged process fetched is trusted before these checks.
  std::string found;
  for (size_t index = 0; index < c_.address_lookup.size(); ++index) {
    const auto answer = c_.fetch_state / "staging" / ("address." + std::to_string(index));
    if (!fs::exists(answer)) continue;
    auto text = Read(answer, 256);
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) text.pop_back();
    std::error_code ignored;
    fs::remove(answer, ignored);
    if (!PublicAddress(text)) {
      std::cerr << "Address service " << index << " gave no public IPv4 address\n";
      return false;
    }
    if (!found.empty() && text != found) {
      std::cerr << "The address services disagree about this host's public address\n";
      return false;
    }
    found = text;
  }
  if (found.empty()) return false;
  // Replace the one line in the node's environment; everything else stays.
  std::istringstream lines(Read(c_.env, 128 * 1024));
  std::string updated;
  for (std::string line; std::getline(lines, line);)
    if (!line.starts_with("FORTIS_HTTPS_IP=")) updated.append(line).append("\n");
  updated.append("FORTIS_HTTPS_IP=").append(found).append("\n");
  AtomicFile(c_.env, updated, 0600);
  std::error_code ignored;
  fs::remove(marker, ignored);
  std::cout << "Public address found: " << found << " (this host's own interface shows " << c_.address << ")\n"
            << std::flush;
  waiting_for_ = "Found this host's public address, " + found + ". Continuing with the setup.";
  return true;
}
/** The unprivileged half of fetching: everything that talks to the release
 * store. It gives up administrator rights first and only writes downloads
 * into its own staging folder; it decides nothing. `what` is "index" or
 * "VERSION:BYTES". */
int FetchWorker(const Settings& c, const std::string& what) {
  if (geteuid() == 0) {
    Check(setgroups(0, nullptr), "drop supplementary groups");
    Check(setgid(c.fetch_user), "drop group");
    Check(setuid(c.fetch_user), "drop user");
    Require(setuid(0) != 0, "administrator rights were not given up");
  }
  const auto staging = c.fetch_state / "staging";
  if (what == "address") {
    DownloadAddressAnswers({"", c.ca, "FortisNet-Orchestrator/1", c.store_loopback}, c.address_lookup, staging);
    return 0;
  }
  const auto store = Store(c);
  if (what == "index") {
    DownloadIndex(store, staging);
    return 0;
  }
  const auto colon = what.find(':');
  Require(colon != std::string::npos, "invalid fetch request");
  DownloadRelease(store, staging, what.substr(0, colon), Integer(std::string_view(what).substr(colon + 1)));
  return 0;
}
/** Download the release index and accept it only when it is signed by a key
 * this host trusts and is not older than one already accepted. An index with
 * the sequence already seen must be byte-for-byte the one seen. The accepted
 * index is kept, so a later check cannot be answered with an earlier list. */
ReleaseIndex Controller::CheckReleases() {
  PrepareFetchFolders();
  const auto worker = Command({self_path, c_.config.string(), "fetch-worker", "index"}, 150, 16 * 1024);
  if (worker.exit != 0)
    throw std::runtime_error(worker.output.empty() ? "release index download failed" : worker.output);
  // Nothing the unprivileged process fetched is trusted before these checks.
  const auto text = Read(c_.fetch_state / "staging/index", 256 * 1024);
  Require(Signed(c_, text, Read(c_.fetch_state / "staging/index.sig", 16384)),
          "release index signature verification failed");
  const auto index = ParseReleaseIndex(text);
  const auto accepted = c_.root / "releases.index";
  if (fs::exists(accepted)) {
    const auto previous_text = Read(accepted, 256 * 1024);
    const auto previous = ParseReleaseIndex(previous_text);
    Require(index.sequence >= previous.sequence, "the release store offers an older index than one already accepted");
    Require(index.sequence > previous.sequence || text == previous_text,
            "the release store offers a different index under a sequence already accepted");
  }
  AtomicFile(accepted, text);
  AtomicFile(c_.root / "releases.checked", std::to_string(NowMs()) + "\n");
  return index;
}
/** `releases`: check the store and say what it offers. */
void Controller::ListReleases() {
  const auto index = CheckReleases();
  const auto current = Target(c_.root / "app/current");
  std::cout << "Release index " << index.sequence << ", " << index.releases.size() << " release(s)\n";
  for (const auto& entry : index.releases) {
    const bool staged = fs::is_directory(c_.root / "staged" / entry.version);
    std::cout << "  " << entry.version << (current == "releases/" + entry.version ? "  (running)" : "")
              << (staged ? "  (staged)" : "") << '\n';
  }
}
/** `fetch VERSION`: download one release named by the accepted index and
 * stage it. The download is copied into the administrator's own folder
 * before it is verified, so what was verified cannot be swapped afterwards;
 * anything that fails is discarded. Staging does not install: the operator
 * runs `update VERSION`. Returns the staged folder. */
fs::path Controller::FetchRelease(const std::string& version) {
  Require(Token(version), "invalid release version");
  const auto index = CheckReleases();
  const auto* entry = index.Find(version);
  Require(entry != nullptr, "the release index does not list that version");
  const auto worker = Command(
      {self_path, c_.config.string(), "fetch-worker", version + ":" + std::to_string(entry->bytes)}, 900, 16 * 1024);
  if (worker.exit != 0) throw std::runtime_error(worker.output.empty() ? "release download failed" : worker.output);
  const auto downloaded = c_.fetch_state / "staging" / version;
  Directory(c_.root / "staged", 0700);
  const auto staged = c_.root / "staged" / version;
  const auto incoming = c_.root / "staged" / (".incoming-" + std::to_string(getpid()));
  fs::remove_all(incoming);
  Directory(incoming, 0700);
  try {
    for (const char* name : {"fortis-node", "manifest", "manifest.sig"})
      CopyFile(downloaded / name, incoming / name, false);
    Require(DigestBytes(Read(incoming / "manifest", 1024)) == entry->manifest_sha256,
            "the downloaded release is not the one the index names");
    const auto release = Verify(c_, incoming);
    Require(release.version == version && release.bytes == entry->bytes,
            "the downloaded release does not match its index entry");
    SyncDirectory(incoming);
    fs::remove_all(staged);
    fs::rename(incoming, staged);
    SyncDirectory(c_.root / "staged");
  } catch (...) {
    fs::remove_all(incoming);
    throw;
  }
  std::error_code ignored;
  fs::remove_all(downloaded, ignored);
  std::cout << "Staged release " << version << "; install it with: update " << version << '\n';
  return staged;
}
acme::Settings AcmeSettings(const Settings& c) {
  acme::Settings settings;
  settings.directory = c.acme_directory;
  settings.ca_file = c.ca;
  settings.contact = c.acme_contact;
  settings.user_agent = "FortisNet-Orchestrator/1";
  settings.account_key = c.acme_state / "fortisnet-account.key";
  settings.challenges = c.challenges;
  settings.allow_loopback = c.acme_loopback;
  return settings;
}
acme::Identifier CertificateFor(const Settings& c, std::string_view kind) {
  Require(kind == "ip" || (kind == "domain" && !c.domain.empty()), "unknown certificate kind");
  return kind == "ip" ? acme::Identifier{true, c.address} : acme::Identifier{false, c.domain};
}
/** The unprivileged half: everything that talks to the certificate
 * authority. It gives up administrator rights before the first network byte
 * and leaves a certificate and key in its own staging directory. */
int CertificateWorker(const Settings& c, const std::string& kind) {
  Require(c.https, "certificates need direct HTTPS to be configured");
  const auto identifier = CertificateFor(c, kind);
  const auto settings = AcmeSettings(c);
  if (geteuid() == 0) {
    Check(setgroups(0, nullptr), "drop supplementary groups");
    Check(setgid(c.acme_user), "drop group");
    Check(setuid(c.acme_user), "drop user");
    Require(setuid(0) != 0, "administrator rights were not given up");
  }
  const auto issued = acme::Issue(settings, identifier);
  const auto staging = c.acme_state / "staging";
  for (const auto& [suffix, bytes] : {std::pair{".pem", &issued.chain}, std::pair{".key", &issued.key}}) {
    std::error_code ignored;
    fs::remove(staging / (kind + suffix), ignored);
    AtomicFile(staging / (kind + suffix), *bytes, 0600);
  }
  return 0;
}
/** Obtain whatever certificate is missing or close to expiry, check it as
 * the administrator, publish a complete new generation and have the node
 * load it. With `only_if_unusable`, a certificate that still works is left
 * alone even when it is due for renewal. Returns true when one was replaced. */
bool Controller::Certificates(bool only_if_unusable) {
  const auto current = c_.certificates / "current";
  std::vector<std::string> kinds{"ip"};
  if (!c_.domain.empty()) kinds.emplace_back("domain");
  std::map<std::string, std::pair<std::string, std::string>> pairs;  // kind -> chain, key
  std::vector<std::string> wanted;
  for (const auto& kind : kinds) {
    try {
      auto chain = Read(current / (kind + ".pem"), 64 * 1024), key = Read(current / (kind + ".key"), 16 * 1024);
      const auto validity = acme::ReadValidity(chain);
      // Renew with a third of the lifetime left; "usable" means an hour.
      const uint64_t margin = only_if_unusable ? 3600 : (validity.not_after - validity.not_before) / 3;
      (void)acme::CheckCertificate(chain, key, CertificateFor(c_, kind), c_.ca, margin);
      pairs[kind] = {std::move(chain), std::move(key)};
    } catch (const std::exception&) { wanted.push_back(kind); }
  }
  if (wanted.empty()) return false;
  const bool serving = Running();
  // The certificate process owns its state and the challenge files; the node
  // and the page server only read the latter.
  Directory(c_.acme_state, 0700);
  Directory(c_.acme_state / "staging", 0700);
  if (geteuid() == 0)
    for (const auto& path : {c_.acme_state, c_.acme_state / "staging", c_.challenges})
      Check(chown(path.c_str(), c_.acme_user, c_.acme_user), "certificate process ownership");
  Check(chmod(c_.challenges.c_str(), 0755), "challenge directory permissions");
  if (!serving) (void)Keep("page-start", 40);
  std::string failure;
  bool renewed = false;
  for (const auto& kind : wanted) {
    try {
      const auto worker = Command({self_path, c_.config.string(), "certificate-worker", kind}, 240, 16 * 1024);
      if (worker.exit != 0)
        throw std::runtime_error(worker.output.empty() ? "certificate process failed" : worker.output);
      auto chain = Read(c_.acme_state / "staging" / (kind + ".pem"), 64 * 1024),
           key = Read(c_.acme_state / "staging" / (kind + ".key"), 16 * 1024);
      // Nothing the unprivileged process produced is trusted before this.
      (void)acme::CheckCertificate(chain, key, CertificateFor(c_, kind), c_.ca, 3600);
      pairs[kind] = {std::move(chain), std::move(key)};
      renewed = true;
    } catch (const std::exception& error) { failure += (failure.empty() ? "" : "; ") + kind + ": " + error.what(); }
  }
  if (!serving) {
    try {
      (void)KeeperRequest(c_.root, "page-stop", 40);
    } catch (const std::runtime_error&) {
      failure += failure.empty() ? "page server did not stop" : "; page server did not stop";
    }
  }
  if (renewed) {
    // A generation is complete or absent: the node loads every pair it is
    // configured for from one directory.
    const auto generation = "generation-" + std::to_string(NowMs());
    const auto directory = c_.certificates / generation;
    Directory(directory, 0700);
    for (const auto& [kind, pair] : pairs) {
      AtomicFile(directory / (kind + ".pem"), pair.first, 0400);
      AtomicFile(directory / (kind + ".key"), pair.second, 0400);
      if (geteuid() == 0)
        for (const char* suffix : {".pem", ".key"})
          Check(chown((directory / (kind + suffix)).c_str(), 10001, 10001), "certificate ownership");
    }
    if (geteuid() == 0) Check(chown(directory.c_str(), 10001, 10001), "certificate generation ownership");
    Check(chmod(directory.c_str(), 0500), "certificate generation permissions");
    const auto next = c_.certificates / "current.next";
    std::error_code ignored;
    fs::remove(next, ignored);
    fs::create_symlink(generation, next);
    fs::rename(next, current);
    SyncDirectory(c_.certificates);
    if (serving) {
      (void)Keep("reload", 30);
      bool loaded = false;
      for (unsigned attempt = 0; attempt < 10 && !loaded; ++attempt) {
        Pause(300);
        loaded = Fetch(ServedName(c_), c_.port, "/healthz", c_.ca.c_str(), 3000).has_value();
      }
      Require(loaded, "the node does not serve with the new certificate");
    }
  }
  // The address certificate is what the node cannot run without. A name that
  // does not resolve here yet is reported and tried again later.
  if (!failure.empty()) {
    std::cerr << "Certificate request failed: " << failure << '\n';
    Require(pairs.contains("ip"), "no usable certificate for the node's address");
  }
  return renewed;
}
/** Called from the supervisor's loop: at most one check every ten minutes,
 * and one attempt an hour after a failure. Never stops the supervisor. */
void Controller::RenewCertificates() {
  if (!c_.https) return;
  const auto marker = c_.root / "certificates.next";
  uint64_t not_before_ms = 0;
  try {
    if (fs::exists(marker)) not_before_ms = Integer(Read(marker, 32));
  } catch (const std::runtime_error&) {
    not_before_ms = 0;  // An unreadable marker only means the check runs now.
  }
  if (NowMs() < not_before_ms) return;
  uint64_t wait_ms = 10 * 60 * 1000;
  try {
    (void)Certificates(false);
    if (!c_.domain.empty() && !fs::is_regular_file(c_.certificates / "current" / "domain.pem")) wait_ms *= 6;
  } catch (const std::exception& error) {
    if (interrupted) throw;
    std::cerr << "Certificate renewal failed: " << error.what() << '\n';
    wait_ms *= 6;
  }
  AtomicFile(marker, std::to_string(NowMs() + wait_ms));
}
void Controller::CleanPreflight(uint64_t id) {
  try {
    (void)KeeperRequest(c_.root, "preflight-stop " + std::to_string(id), 40);
  } catch (const std::runtime_error&) {
    return;  // No keeper: no preflight can be alive.
  }
}
void Controller::Preflight(const fs::path& directory, uint64_t id) {
  if (!c_.preflight) return;
  // The candidate runs beside the serving node with temporary data, no
  // secrets and no network of its own. It is reached only through a loopback
  // socket the keeper opened for it.
  const auto port = static_cast<unsigned>(
      KeeperField(Keep("preflight " + std::to_string(id) + " " + directory.filename().string(), 40), "port"));
  bool ready = false;
  for (unsigned attempt = 0; attempt < 30; ++attempt) {
    if (Answers(port, "/healthz")) {
      ready = true;
      break;
    }
    Pause(200);
  }
  Require(ready, "isolated candidate preflight failed");
  const auto refusal = Fetch("127.0.0.1", port, "/v1/networks", nullptr, 2000);
  Require(refusal && refusal->status == 401, "isolated authentication preflight failed");
  CleanPreflight(id);
}
void Controller::Adopt() {
  if (ledger_->Head().active || !Running()) return;
  const auto selected = Target(c_.root / "app/current");
  Require(selected != "NONE", "running node has no selected release");
  const auto release = Verify(c_, c_.root / "app" / selected);
  Identity(release);
  Require(Healthy(release.metadata ? release.digest : ""), "existing worker is not ready for adoption");
  auto record = ledger_->New(release.version, release.digest, release.source);
  Require(ledger_->Head().instances < kMaxPublicInteger, "instance IDs exhausted");
  record.instance = ++ledger_->Head().instances;
  record.phase = "stable";
  record.outcome = "adopted";
  record.reason = "observed-existing-process";
  record.uncertain = true;
  ledger_->Head().active = record.id;
  ledger_->Save(record);
}
void Controller::Boot(Deployment& record, const Release& release) {
  Require(ledger_->Head().instances < kMaxPublicInteger, "instance IDs exhausted");
  record.instance = ++ledger_->Head().instances;
  record.started = NowMs();
  record.uncertain = true;  // These are first-confirmed observations, not an
                            // instrumented accept timestamp.
  Phase(record, "starting");
  // The node refuses to start without a usable certificate for its address.
  if (c_.https) (void)Certificates(true);
  (void)Keep("start", 60);
  Identity(release);
  expected_metadata_ = release.metadata ? release.digest : "";
  Require(Healthy(expected_metadata_), "new release readiness failed");
  record.ready = NowMs();
  record.enabled = record.ready;
  ledger_->Head().active = record.id;
  Phase(record, "observing");
}
void Controller::Stop(std::string reason) {
  const bool running = Running();
  std::optional<Deployment> record;
  if (ledger_->Head().active) {
    record = ledger_->Load(ledger_->Head().active);
    record->reason = std::move(reason);
    record->uncertain = true;
    if (running) record->disabled = NowMs();
    Phase(*record, running ? "draining" : "exited");
  }
  // Without a keeper nothing can be running and no exit was observed.
  uint64_t exit_code = 0;
  if (State()) {
    const auto stopped = KeeperRequest(c_.root, "stop 180", 240);
    Require(KeeperField(stopped, "running") == 0, "worker did not stop");
    exit_code = KeeperField(stopped, "exit");
  }
  PublishHealth(recovering_ ? "recovering" : fs::exists(c_.root / "pending") ? "updating" : "");
  ShowPagesWhileStopped();
  const bool forced = exit_code == 137, clean = exit_code == 0;
  if (record) {
    record->stopped = running ? NowMs() : 0;
    record->drained = running && clean ? record->stopped : 0;
    record->phase = "stopped";
    record->outcome = forced ? "forced-stop" : (running && clean ? "stopped" : "crashed");
    ledger_->Save(*record);
    ledger_->Head().active = 0;
    ledger_->Save(*record);
  }
  if (!recovering_)
    Require(!forced && (!running || clean),
            "unclean or forced shutdown: previous release must recover before "
            "retrying");
}
void Controller::Start(std::string reason, uint64_t previous) {
  const auto target = Target(c_.root / "app/current");
  Require(target != "NONE", "current release absent");
  const auto release = Verify(c_, c_.root / "app" / target);
  Require(Read(c_.root / "storage-epoch", 16) == "1\n", "unsupported storage epoch");
  if (Running()) {
    Identity(release);
    Require(Healthy(release.metadata ? release.digest : ""), "readiness failed");
    Adopt();
    ledger_->Publish();
    return;
  }
  restarted_ = reason == "supervised-restart";
  auto record = ledger_->New(release.version, release.digest, release.source);
  record.reason = std::move(reason);
  record.previous = previous;
  ledger_->Save(record);
  Boot(record, release);
  record.stable = NowMs();
  record.phase = "stable";
  record.outcome = previous ? "recovered" : "restarted";
  ledger_->Save(record);
}
struct Metrics {
  uint64_t successful = 0;
  IncidentCounts nodes, providers;
  double p95_ms = 0;
};
Metrics Sample(const std::string& errors, const std::string& stats) {
  Metrics result;
  const Json e(errors), s(stats);
  const auto op = e.Field(e.Root(), "operational");
  const auto records = e.Field(op, "records");
  if (e.Is(records, codec::BoundedJsonType::kArray)) {
    for (auto item = e.Get().token(records)->first_child; item != codec::kBoundedJsonNoToken;
         item = e.Get().token(item)->next_sibling) {
      const auto origin = e.Field(item, "origin");
      const bool node = e.Get().StringEquals(origin, "node"), provider = e.Get().StringEquals(origin, "third_party");
      if (!node && !provider) continue;
      std::string key;
      for (const char* field : {"service", "code", "identifier", "provider"})
        key += Quote(e.String(e.Field(item, field))) + ",";
      const auto status = e.Field(item, "httpStatus");
      key += e.Is(status, codec::BoundedJsonType::kNull) ? "null" : std::to_string(e.Unsigned(status));
      (node ? result.nodes : result.providers)[key] = {e.Unsigned(e.Field(item, "count")),
                                                       e.Unsigned(e.Field(item, "firstSeenMs"))};
    }
  }
  const auto groups = s.Field(s.Root(), "groups");
  Require(s.Is(groups, codec::BoundedJsonType::kArray), "required traffic evidence absent");
  for (auto item = s.Get().token(groups)->first_child; item != codec::kBoundedJsonNoToken;
       item = s.Get().token(item)->next_sibling) {
    const auto total = s.Unsigned(s.Field(item, "requests"));
    const auto client = s.Unsigned(s.Field(item, "errors4xx")), server = s.Unsigned(s.Field(item, "errors5xx"));
    Require(client <= total && server <= total - client &&
                total - client - server <= static_cast<uint64_t>(INT64_MAX) - result.successful,
            "invalid request evidence");
    result.successful += total - client - server;
    double p95 = 0;
    if (s.Get().Number(s.Field(item, "p95Ms"), &p95) && p95 >= 0 && p95 > result.p95_ms) result.p95_ms = p95;
  }
  return result;
}
uint64_t IncidentDelta(const IncidentCounts& current, const IncidentCounts& baseline) {
  uint64_t total = 0;
  for (const auto& [key, incident] : current) {
    const auto prior = baseline.find(key);
    const auto delta =
        prior == baseline.end() || prior->second.first_ms != incident.first_ms || incident.count < prior->second.count
            ? incident.count
            : incident.count - prior->second.count;
    total += std::min(delta, kMaxPublicInteger - total);
  }
  return total;
}
void Controller::Observe(Deployment& record) {
  if (!c_.observation && !c_.samples) {
    record.stable = NowMs();
    record.outcome = "accepted";
    record.phase = "stable";
    ledger_->Head().candidate = 0;
    ledger_->Save(record);
    return;
  }
  const auto start = SteadyClock::now(), deadline = start + std::chrono::seconds(c_.observation_timeout);
  unsigned bad_windows = 0, good_windows = 0;
  while (SteadyClock::now() < deadline) {
    Require(Healthy(expected_metadata_, 1, false), "candidate lost readiness");
    const auto now = Sample(Api("/errorsz"), Api("/statsz"));
    const auto node_events = IncidentDelta(now.nodes, baseline_nodes_);
    const auto provider_events = IncidentDelta(now.providers, baseline_providers_);
    const bool node_regression = node_events >= 3;
    // Latency alone is not causal evidence: require new node incidents and no
    // new provider incidents before using a severe cold-start-resistant limit.
    const bool latency_regression = now.successful >= 20 && node_events > 0 && provider_events == 0 &&
                                    now.p95_ms > std::max(1000.0, baseline_p95_ * 5);
    bad_windows = node_regression || latency_regression ? bad_windows + 1 : 0;
    good_windows = bad_windows ? 0 : good_windows + 1;
    Require(bad_windows < 3, "sustained node regression");
    record.request_samples = now.successful;
    record.node_events = node_events;
    record.provider_events = provider_events;
    record.p95_ms = now.p95_ms > 1000000000.0 ? 1000000000ULL : static_cast<uint64_t>(now.p95_ms);
    record.observation_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(SteadyClock::now() - start).count());
    ledger_->Save(record);
    if (good_windows >= 3 && now.successful >= c_.samples &&
        SteadyClock::now() - start >= std::chrono::seconds(c_.observation)) {
      record.stable = NowMs();
      record.outcome = "accepted";
      record.phase = "stable";
      ledger_->Head().candidate = 0;
      ledger_->Save(record);
      return;
    }
    Pause(1000);
  }
  throw std::runtime_error("observation inconclusive: insufficient required evidence");
}
/** Take the database's own writer lock; the node must be stopped. The lock
 * is released when the returned descriptor is. */
FileDescriptor Controller::LockDatabase() const {
  const auto lock_path = c_.data / kDatabaseLock;
  const bool existed = fs::exists(lock_path);
  FileDescriptor data_lock(
      Check(::open(lock_path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600), "database lock"));
  // Only an administrator can give the lock to the node; an unprivileged
  // controller (tests) could not start a real node anyway.
  if (!existed && geteuid() == 0) Check(fchown(data_lock.get(), 10001, 10001), "database lock owner");
  Require(flock(data_lock.get(), LOCK_EX | LOCK_NB) == 0, "another database writer is active");
  return data_lock;
}
/** Copy the stopped, locked database into a new backup folder and write its
 * manifest, so the folder can later be checked and restored anywhere.
 * A failed copy leaves no folder behind. Returns the folder. */
fs::path Controller::CopyDatabase(const std::string& label) {
  // A full copy must fit and still leave the database 64 MiB to grow into.
  const auto needed = TreeBytes(c_.data);
  const auto available = AvailableBytes(c_.backups);
  Require(available > needed && available - needed > 64ULL * 1024 * 1024,
          "insufficient space for backup and database reserve");
  const auto backup = c_.backups / (std::to_string(NowMs()) + "-" + label);
  Directory(backup, 0700);
  try {
    CopyTree(c_.data, backup, SteadyClock::now() + std::chrono::seconds(180));
    // The release that last wrote this data: whichever is selected now.
    const auto selected = Target(c_.root / "app/current");
    if (selected == "NONE") (void)WriteBackupManifest(backup, "none", "none");
    else {
      const auto release = Verify(c_, c_.root / "app" / selected);
      (void)WriteBackupManifest(backup, release.version, release.digest);
    }
    SyncDirectory(backup);
    SyncDirectory(c_.backups);
  } catch (const std::exception&) {
    fs::remove_all(backup);
    throw std::runtime_error("backup failed; partial copy removed");
  }
  return backup;
}
/** `backup`: a coherent copy of the database, with the node stopped for as
 * long as the copy takes and started again whatever the outcome. */
void Controller::Backup() {
  Require(fs::exists(c_.root / "storage-epoch"), "nothing is installed to back up");
  const bool serving = Running();
  if (serving) Stop("backup");
  fs::path folder;
  std::exception_ptr failure;
  try {
    const auto data_lock = LockDatabase();
    folder = CopyDatabase("manual");
  } catch (...) { failure = std::current_exception(); }
  if (serving) Start("backup");
  if (failure) std::rethrow_exception(failure);
  std::cout << "Backup written: " << folder.string() << '\n';
}
/** `restore FOLDER`: replace the database with a backup made by `backup` or
 * before an update, here or on another machine. The backup is checked in
 * full before anything is touched; the database it replaces is kept as a
 * backup of its own; and if the node does not come up healthy on the restored
 * data, the previous database is put back. */
void Controller::Restore(const fs::path& folder) {
  SafePath(folder);
  Require(fs::is_directory(folder) && fs::canonical(folder) == folder && !Within(folder, c_.data) &&
              !Within(c_.data, folder),
          "the backup must be a folder outside the database");
  const auto manifest = Read(folder / kBackupManifest, 64 * 1024 * 1024);
  const auto summary = VerifyBackup(folder);
  Require(summary.storage_epoch == "1" && Read(c_.root / "storage-epoch", 16) == "1\n",
          "the backup's storage format is not supported by this installation");
  Require(Target(c_.root / "app/current") != "NONE", "install a node release before restoring");
  // The database being replaced is moved aside, not copied, so both folders
  // must be on one filesystem; the restored copy needs room of its own.
  struct stat data_info {
  }, backups_info{};
  Check(stat(c_.data.c_str(), &data_info), "inspect database folder");
  Check(stat(c_.backups.c_str(), &backups_info), "inspect backup folder");
  Require(data_info.st_dev == backups_info.st_dev, "backups must be on the database's filesystem to restore");
  const auto available = AvailableBytes(c_.data);
  Require(available > summary.bytes && available - summary.bytes > 64ULL * 1024 * 1024,
          "insufficient space to restore and keep the database reserve");
  if (Running()) Stop("restore");
  auto data_lock = LockDatabase();
  const std::string lock_name = kDatabaseLock;
  const auto aside = c_.backups / (std::to_string(NowMs()) + "-before-restore");
  Directory(aside, 0700);
  const auto move_all = [&](const fs::path& from, const fs::path& to) {
    for (const auto& entry : fs::directory_iterator(from)) {
      const auto name = entry.path().filename().string();
      if (name == lock_name || name == kBackupManifest) continue;
      fs::rename(entry.path(), to / name);
    }
    SyncDirectory(from);
    SyncDirectory(to);
  };
  move_all(c_.data, aside);
  bool restored = false;
  try {
    const auto selected = Verify(c_, c_.root / "app" / Target(c_.root / "app/current"));
    (void)WriteBackupManifest(aside, selected.version, selected.digest);
    CopyTree(folder, c_.data, SteadyClock::now() + std::chrono::seconds(600), {lock_name, kBackupManifest});
    if (geteuid() == 0) {
      // A backup from another machine may carry other owners.
      for (const auto& entry : fs::recursive_directory_iterator(c_.data))
        Check(lchown(entry.path().c_str(), 10001, 10001), "restored file owner");
    }
    // What is now in place must be exactly what the manifest describes.
    (void)VerifyTree(c_.data, manifest, {lock_name, kBackupManifest});
    restored = true;
    data_lock.reset();
    Start("restore");
  } catch (const std::exception& failure) {
    const std::string reason = failure.what();
    interrupted = 0;  // Put the previous database back even if a signal asked to stop.
    try {
      if (restored && Running()) Stop("restore-failed");
      if (data_lock.get() < 0) data_lock = LockDatabase();
      for (const auto& entry : fs::directory_iterator(c_.data))
        if (entry.path().filename() != lock_name) fs::remove_all(entry.path());
      move_all(aside, c_.data);
      fs::remove_all(aside);
      data_lock.reset();
      Start("restore-rollback");
    } catch (const std::exception& second) {
      throw std::runtime_error("restore failed (" + reason + ") and the previous database could not be put back (" +
                               second.what() + "); it is in " + aside.string());
    }
    throw std::runtime_error("restore failed and the previous database was put back: " + reason);
  }
  std::cout << "Restored " << summary.entries << " entries from " << folder.string()
            << "; the previous database is kept in " << aside.string() << '\n';
}
void Controller::Recover() {
  const auto pending = c_.root / "pending";
  if (!fs::exists(pending)) {
    if (ledger_->Head().candidate) {
      auto abandoned = ledger_->Load(ledger_->Head().candidate);
      CleanPreflight(abandoned.id);
      abandoned.phase = "aborted";
      abandoned.outcome = "not-promoted";
      abandoned.reason = "interrupted-before-handover";
      ledger_->Head().candidate = 0;
      ledger_->Save(abandoned);
    }
    return;
  }
  auto old = Read(pending, 256);
  if (!old.empty() && old.back() == '\n') old.pop_back();
  Require(old == "NONE" || (old.starts_with("releases/") && Token(std::string_view(old).substr(9))),
          "invalid recovery target");
  recovering_ = true;
  const uint64_t failed_id = ledger_->Head().candidate ? ledger_->Head().candidate : ledger_->Head().active;
  const auto failure_reason = failed_id ? ledger_->Load(failed_id).reason : "none";
  Stop("recovery");
  if (failed_id) {
    auto failed = ledger_->Load(failed_id);
    failed.phase = "rolled-back";
    failed.outcome = "rolled-back";
    failed.reason = failure_reason == "none" ? "interrupted-update" : failure_reason;
    failed.stopped = NowMs();
    failed.uncertain = true;
    ledger_->Head().candidate = 0;
    ledger_->Save(failed);
  }
  if (old == "NONE") {
    fs::remove(c_.root / "app/current");
    SyncDirectory(c_.root / "app");
  } else {
    (void)Verify(c_, c_.root / "app" / old);
    Select(c_, old);
    Start("rollback", failed_id);
  }
  fs::remove(pending);
  SyncDirectory(c_.root);
  recovering_ = false;
  std::cout << "Recovered previous binary; database retained without restoring "
               "stale data\n";
}
void Controller::Update(const fs::path& package) {
  Require(!fs::exists(c_.root / "pending"), "interrupted update: recover first");
  Adopt();
  Release release;
  try {
    release = Verify(c_, package);
  } catch (...) {
    auto rejected = ledger_->New("unverified", "");
    rejected.verified = false;
    rejected.phase = "rejected";
    rejected.outcome = "not-promoted";
    rejected.reason = "invalid-signed-package";
    ledger_->Save(rejected);
    throw;
  }
  auto record = ledger_->New(release.version, release.digest, release.source);
  record.previous = ledger_->Head().active;
  ledger_->Head().candidate = record.id;
  ledger_->Save(record);
  const auto started = SteadyClock::now();
  bool journal = false;
  try {
    Require(!fs::exists(c_.root / "quarantine" / release.digest),
            "candidate quarantined: explicit reviewed retry required");
    const auto target = "releases/" + release.version;
    const auto installed = c_.root / "app" / target;
    Phase(record, "staging");
    if (fs::exists(installed)) {
      Require(Read(package / "manifest", 1024) == Read(installed / "manifest", 1024),
              "version already exists with different content");
      (void)Verify(c_, installed);
    } else {
      const auto staging =
          c_.root / "app/releases" / (".upload-" + std::to_string(getpid()) + "-" + std::to_string(record.id));
      Directory(staging, 0700);
      try {
        for (const char* name : {"fortis-node", "manifest", "manifest.sig"})
          CopyFile(package / name, staging / name, false);
        const auto copied = Verify(c_, staging);
        Require(copied.version == release.version && copied.digest == release.digest,
                "staged release identity changed during upload");
        Check(chmod((staging / "fortis-node").c_str(), 0555), "executable permissions");
        for (const char* name : {"manifest", "manifest.sig"})
          Check(chmod((staging / name).c_str(), 0444), "manifest permissions");
        Check(chmod(staging.c_str(), 0555), "immutable release permissions");
        SyncDirectory(staging);
        fs::rename(staging, installed);
        SyncDirectory(installed.parent_path());
      } catch (...) {
        fs::remove_all(staging);
        throw;
      }
    }
    if (fs::exists(c_.root / "storage-epoch"))
      Require(Read(c_.root / "storage-epoch", 16) == "1\n", "unsupported storage epoch");
    else {
      Require(fs::is_empty(c_.data), "existing database requires an explicit audited adoption");
      AtomicFile(c_.root / "storage-epoch", "1\n");
    }
    const auto old = Target(c_.root / "app/current");
    if (old == target && Running()) {
      record.phase = "unchanged";
      record.outcome = "already-selected";
      ledger_->Head().candidate = 0;
      ledger_->Save(record);
      return;
    }
    Phase(record, "preflight");
    Preflight(installed, record.id);
    if (old != "NONE" && (c_.observation || c_.samples)) {
      Require(Running(), "recover the current worker before requesting an update");
      const auto baseline = Sample(Api("/errorsz"), Api("/statsz"));
      baseline_nodes_ = baseline.nodes;
      baseline_providers_ = baseline.providers;
      baseline_p95_ = baseline.p95_ms;
    }
    AtomicFile(c_.root / "recovery.reserve", std::string(1024 * 1024, '\0'));
    AtomicFile(c_.root / "pending", old + "\n");
    journal = true;
    Phase(record, "draining");
    Stop("update");
    Phase(record, "backing-up");
    auto data_lock = LockDatabase();
    (void)CopyDatabase(std::to_string(record.id));
    Phase(record, "selecting");
    Select(c_, target);
    data_lock.reset();
    Boot(record, release);
    Observe(record);
    if (old != "NONE") Select(c_, old, "previous");
    record.duration_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(SteadyClock::now() - started).count());
    ledger_->Save(record);
    fs::remove(c_.root / "pending");
    SyncDirectory(c_.root);
    journal = false;
    std::cout << "Verified and accepted release " << release.version << " " << release.digest << '\n';
  } catch (...) {
    const auto error = std::current_exception();
    record.duration_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(SteadyClock::now() - started).count());
    interrupted = 0;  // Finish journal recovery even if the initiating request
                      // was interrupted.
    CleanPreflight(record.id);
    if (journal) {
      try {
        std::rethrow_exception(error);
      } catch (const std::exception& failure) {
        const std::string_view message = failure.what();
        record.reason =
            message.find("inconclusive") != std::string_view::npos ? "insufficient-evidence"
            : message.find("regression") != std::string_view::npos ? "node-regression"
            : message.find("Forced") != std::string_view::npos || message.find("forced") != std::string_view::npos
                ? "forced-shutdown"
            : message.find("readiness") != std::string_view::npos ? "readiness-failed"
                                                                  : "activation-failed";
      }
      fs::remove(c_.root / "recovery.reserve");
      SyncDirectory(c_.root);
      try {
        ledger_->Save(record);
      } catch (const std::exception&) { std::cerr << "Failure checkpoint unavailable; retaining recovery journal\n"; }
      try {
        Quarantine(release.digest, "activation-failed\n");
      } catch (const std::exception&) { std::cerr << "Quarantine checkpoint unavailable\n"; }
      try {
        Recover();
      } catch (...) { std::cerr << "Recovery incomplete; journal retained\n"; }
    } else {
      record.phase = "rejected";
      record.outcome = "not-promoted";
      record.reason = "preflight-or-admission-failed";
      ledger_->Head().candidate = 0;
      ledger_->Save(record);
    }
    std::rethrow_exception(error);
  }
}
void Controller::Action(const std::string& action, const fs::path& package) {
  if (action == "adopt") {
    Adopt();
    ledger_->Publish();
    return;
  }
  if (action == "status") {
    Adopt();
    ledger_->Publish();
    std::cout << Read(ledger_->PublicDirectory() / "current.json") << '\n';
    // The same report the health page shows, for the operator's terminal.
    std::cout << RenderHealthJson(Facts({}));
    return;
  }
  if (action == "recover") {
    Recover();
    return;
  }
  if (action == "stop") {
    Stop("operator-stop");
    return;
  }
  if (action == "releases") {
    ListReleases();
    return;
  }
  if (action == "fetch") {
    (void)FetchRelease(package.string());
    PublishHealth();
    return;
  }
  if (action == "update") {
    // A bare version names a release staged by `fetch`; a path names a folder.
    Update(package.is_absolute() ? package : c_.root / "staged" / package);
    PublishHealth();
    return;
  }
  if (action == "retry") {
    const auto release = Verify(c_, package);
    fs::remove(c_.root / "quarantine" / release.digest);
    SyncDirectory(c_.root / "quarantine");
    Update(package);
    PublishHealth();
    return;
  }
  if (action == "backup") {
    Backup();
    PublishHealth();
    return;
  }
  if (action == "restore") {
    Restore(package);
    PublishHealth();
    return;
  }
  if (action == "certificates") {
    Require(c_.https, "certificates need direct HTTPS to be configured");
    std::cout << (Certificates(false) ? "Certificates renewed\n" : "Certificates are current\n");
    return;
  }
  Require(action == "start" || action == "tick", "unknown controller action");
  Recover();
  if (action == "tick" && Running() && ledger_->Head().active) {
    if (c_.verify_pid &&
        (!fs::exists(c_.root / "worker.identity") || Read(c_.root / "worker.identity", 256) != Instance())) {
      auto previous = ledger_->Load(ledger_->Head().active);
      previous.phase = "exited";
      previous.outcome = "unobserved-restart";
      previous.uncertain = true;
      ledger_->Save(previous);
      ledger_->Head().active = 0;
      Adopt();
    }
    ledger_->Publish();
    RenewCertificates();
    PublishHealth();
    return;
  }
  if (!Running() && ledger_->Head().active) {
    auto previous = ledger_->Load(ledger_->Head().active);
    previous.phase = "exited";
    previous.outcome = "crashed";
    previous.reason = "worker-exited";
    previous.uncertain = true;
    ledger_->Save(previous);
    ledger_->Head().active = 0;
  }
  if (Target(c_.root / "app/current") == "NONE") {
    // Nothing is installed yet. Show the pages, and on a new host install the
    // release that came with the image.
    PublishHealth();
    ShowPagesWhileStopped();
    InstallBakedRelease();
    PublishHealth();
    return;
  }
  Start("supervised-restart");
  PublishHealth();
}
}  // namespace
}  // namespace fortis::host::updates

int main(int argc, char** argv) {
  using namespace fortis::host::updates;
  const rlimit no_core{0, 0};
  if (setrlimit(RLIMIT_CORE, &no_core) != 0) return 1;
  (void)signal(SIGPIPE, SIG_IGN);
  (void)signal(SIGTERM, OnSignal);
  (void)signal(SIGINT, OnSignal);
  (void)signal(SIGHUP, OnSignal);
  try {
    Require(argc >= 3 && argc <= 4,
            "usage: native-controller CONFIG "
            "start|stop|update|recover|status|adopt|"
            "retry|supervise|certificates|backup|restore|releases|fetch|first-boot|keeper "
            "[PACKAGE|FOLDER|VERSION]");
    const fs::path config = argv[1];
    const std::string action = argv[2];
    std::error_code unresolved;
    self_path = fs::read_symlink("/proc/self/exe", unresolved).string();
    if (unresolved) self_path = fs::absolute(argv[0]).string();
    if (action == "page-server") return RunPageServer(config, argc == 4 ? fs::path(argv[3]) : fs::path{});
    if (action == "first-boot") {
      // Before any configuration exists: lay the host out. The optional
      // argument is a folder to do it under, for tests.
      const bool configured = FirstBoot(config, argc == 4 ? fs::path(argv[3]) : fs::path{});
      std::cout << (configured ? "Host configured" : "Host already configured") << " (runs in: " << HostKind() << ")\n";
      return 0;
    }
    if (action == "fetch-worker") {
      Require(argc == 4, "fetch request required");
      try {
        return FetchWorker(Configure(config, true), argv[3]);
      } catch (const std::exception& error) {
        std::cout << error.what() << '\n';
        return 1;
      }
    }
    if (action == "certificate-worker") {
      Require(argc == 4, "certificate kind required");
      // The administrator's side captures standard output: say there why
      // the request failed.
      try {
        return CertificateWorker(Configure(config, true), argv[3]);
      } catch (const std::exception& error) {
        std::cout << error.what() << '\n';
        return 1;
      }
    }
    if (action == "keeper") {
      const auto plan = Plan(config);
      return RunKeeper(plan);
    }
    if (action != "supervise") {
      Controller controller(Configure(config, action == "stop"));
      controller.Action(action, argc == 4 ? fs::path(argv[3]) : fs::path{});
      return 0;
    }
    std::cout << "Orchestrator supervising; runs in: " << HostKind() << '\n' << std::flush;
    unsigned failures = 0, fast_restarts = 0;
    auto last_restart = SteadyClock::now() - std::chrono::seconds(61);
    while (!interrupted) {
      try {
        Controller controller(Configure(config, false));
        controller.Action("tick");
        failures = 0;
        if (controller.Restarted()) {
          const auto now = SteadyClock::now();
          fast_restarts = now - last_restart < std::chrono::seconds(60) ? fast_restarts + 1 : 1;
          last_restart = now;
          if (fast_restarts >= 5) throw std::runtime_error("Repeated native node crashes; operator attention required");
        }
      } catch (const std::exception&) {
        if (interrupted) break;
        if (fast_restarts >= 5 || ++failures >= 5)
          throw std::runtime_error(
              "Repeated native node crashes or controller "
              "failures; operator attention required");
      }
      try {
        Pause(Configure(config, false).require_mount ? 5000 : 1000);
      } catch (const std::runtime_error&) {
        if (!interrupted) throw;
      }
    }
    interrupted = 0;
    const auto stopping = Configure(config, true);
    Controller(stopping).Action("stop");
    // The service is stopping: release the ports as well.
    if (KeeperPresent(stopping.root)) (void)KeeperRequest(stopping.root, "shutdown", 10);
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "native-controller: " << error.what() << '\n';
    return 1;
  }
}
