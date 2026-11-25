#pragma once

#include "native_control_support.h"

namespace fortis::host::updates {

/** One mount inside the node's container; options are OCI mount options. */
struct NodeMount {
  std::string destination, type, source;
  std::vector<std::string> options;
};
/** What one container runs. The keeper adds the listener map to `env`. */
struct NodeContainer {
  std::vector<std::string> args, env;
  std::vector<NodeMount> mounts;
  uint64_t memory_bytes = 512ULL * 1024 * 1024, tasks = 512;
  unsigned user = 10001;     // UID and GID inside and outside the container
  bool host_network = true;  // false: an empty network namespace of its own
  bool seccomp = true;       // false only for emulated fixtures (foreign syscall ABI)
};
/** A listening socket the keeper owns. `inside` is the port number the node
 * believes it opens; the node adopts the descriptor instead of binding. */
struct NodeListener {
  std::string address;
  unsigned port = 0, inside = 0;
  bool operator==(const NodeListener&) const = default;
};
/** Everything the keeper needs. The functions are called again for every
 * start, so a changed configuration applies without restarting the keeper. */
struct KeeperPlan {
  fs::path root;           // administrator-owned: control socket, bundles, logs
  fs::path runtime_state;  // crun --root; a tmpfs path in production
  std::string name;        // container identifier of the node
  fs::path config;         // passed back to the three functions below
  std::vector<NodeListener> (*listeners)(const fs::path& config) = nullptr;
  NodeContainer (*node)(const fs::path& config) = nullptr;
  NodeContainer (*preflight)(const fs::path& config, const fs::path& release) = nullptr;
  // The stand-in server for the public HTTP port while no node serves.
  NodeContainer (*page)(const fs::path& config) = nullptr;
};

/** Owned OCI configuration: UID/GID 10001, no capabilities, no new privileges,
 * read-only root, bounded memory and tasks. Performs no I/O. */
std::string NodeOciConfig(const NodeContainer& container, const fs::path& rootfs, std::string_view hostname,
                          std::string_view cgroup, std::string_view listen_fds);

/** Run the keeper until `shutdown` or a termination signal: it owns the
 * public listening sockets and is the parent of every `crun run`, so exit
 * codes and logs are observed without a container daemon. Returns the process
 * exit code; returns 0 at once when another keeper holds the lock. */
int RunKeeper(const KeeperPlan& plan);

/** Send one request line to the keeper under `root` and return its reply
 * without the leading "ok". Throws runtime_error when the keeper is absent,
 * refuses the request or does not answer within `timeout_seconds`. */
std::string KeeperRequest(const fs::path& root, std::string_view request, unsigned timeout_seconds = 10);
/** True when a keeper answers under `root`. Never throws. */
bool KeeperPresent(const fs::path& root);
/** Value of `key=` in a keeper reply; throws when the field is absent. */
uint64_t KeeperField(std::string_view reply, std::string_view key);

}  // namespace fortis::host::updates
