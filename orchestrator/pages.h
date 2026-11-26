#pragma once

#include "native_control_support.h"

/** The pages this host shows about itself: the first page, health, and
 * what it runs and is doing about newer releases.
 *
 * The orchestrator is their only author. It writes them as finished files
 * whenever something changes; the page server hands them out while no node
 * serves, and the node hands out the same files while it does. Nothing here
 * reads the network, and nothing secret goes in: no paths, keys, device
 * identifiers or provider answers, and of the settings only the two that
 * say where releases come from (the store's address and the channel). */
namespace fortis::host::updates {

/** One line of the health report. */
struct HealthCheck {
  enum class State { kHealthy, kWaiting, kFailing };
  std::string name, detail;
  State state = State::kHealthy;
};
/** A release newer than the one chosen, and why it was not taken. */
struct SkippedRelease {
  std::string version, reason;
  // True when the reason is that the release needs more than this Node OS
  // offers, so the page can say that a newer Node OS would run it.
  bool needs_newer_host = false;
};
/** One past install or rollback, from the deployment ledger. */
struct ReleaseEvent {
  std::string version, sha256;
  std::string result;  // "installed", "rolled-back" or "refused"
  std::string reason;
  uint64_t at_ms = 0;
};
/** What the host is doing about node releases. */
struct UpdateFacts {
  // "off", "idle", "looking", "waiting", "downloading", "verifying",
  // "installing" or "failed".
  std::string state = "off";
  std::string message;            // one sentence for a person
  std::string candidate_version;  // empty: no release is waiting to be installed
  unsigned candidate_interface = 0;
  uint64_t candidate_bytes = 0;
  uint64_t install_at_ms = 0;                     // while waiting: when the candidate is installed
  uint64_t downloaded_bytes = 0;                  // while downloading: how much has arrived
  uint64_t last_check_ms = 0, next_check_ms = 0;  // 0: not known
  std::vector<SkippedRelease> skipped;
};
/** Everything the pages say, gathered by the administrator's side. */
struct HostFacts {
  uint64_t generated_ms = 0;
  std::string orchestrator_version;  // the release version it was built as
  std::string architecture;          // "x86_64" or "aarch64"
  std::string runs_in;               // "machine" or "container"
  // "not-installed", "serving", "stopped", "updating" or "recovering".
  std::string node_state, node_version, node_sha256;
  unsigned node_host_interface = 1;  // what the installed release needs from its host
  uint64_t node_since_ms = 0;        // when the running node's process started; 0 when it is not running
  std::vector<HealthCheck> orchestrator, node;
  unsigned processors = 0;
  uint64_t memory_bytes = 0, disk_bytes = 0, disk_free_bytes = 0;
  std::string address, domain;      // what the certificate is for; may be empty
  std::string newest_release;       // newest in the accepted release index; may be empty
  std::vector<std::string> staged;  // releases downloaded and waiting for `update`
  bool store_configured = false;
  std::string store;               // the release store as configured; empty when none is
  std::string channel;             // the release channel this host follows
  bool automatic_updates = false;  // a store is configured and the host installs from it by itself
  UpdateFacts update;
  std::vector<ReleaseEvent> history;  // newest first; the last few installs and rollbacks
  // While the host is still being set up: what it is waiting for, in one
  // plain sentence. Empty otherwise.
  std::string waiting_for;
};

/** A date as the pages show it: "25 November 2026, 04:40 UTC". */
std::string PageDate(uint64_t milliseconds);
/** 200 when every check is healthy and the node serves, 503 otherwise. */
int HealthStatus(const HostFacts& facts);
/** The health report for monitoring tools: fixed, versioned JSON. */
std::string RenderHealthJson(const HostFacts& facts);
/** What runs here, what this host can run, and what it is doing about
 * newer releases: fixed, versioned JSON for tools and for the node's own
 * pages. Unlike the health report it carries no verdict: a newer release
 * or an unreachable store does not make a host unhealthy. */
std::string RenderNodeJson(const HostFacts& facts);
/** The same report as a page in the first page's design. */
std::string RenderHealthPage(const HostFacts& facts);
/** The first page. */
std::string RenderFirstPage(const HostFacts& facts);

/** Names of the published files, shared with whoever serves them. */
inline constexpr char kFirstPageFile[] = "index.html";
inline constexpr char kHealthPageFile[] = "health.html";
inline constexpr char kHealthJsonFile[] = "health.json";
inline constexpr char kNodeJsonFile[] = "node.json";
/** One line, "STATUS GENERATED_MS": lets a server answer with the right
 * status code and notice a report nobody refreshes, without reading JSON. */
inline constexpr char kHealthStatusFile[] = "health.status";
/** A report older than this is stale and is answered with 503. */
inline constexpr uint64_t kHealthFreshMs = 60 * 1000;

/** Write the five files into `directory`, each replaced in one step so a
 * reader never sees half a file. */
void PublishPages(const fs::path& directory, const HostFacts& facts);

}  // namespace fortis::host::updates
