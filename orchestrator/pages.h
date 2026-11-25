#pragma once

#include "native_control_support.h"

/** The pages this host shows about itself: the first page and health.
 *
 * The orchestrator is their only author. It writes them as finished files
 * whenever something changes; the page server hands them out while no node
 * serves, and the node hands out the same files while it does. Nothing here
 * reads the network, and nothing secret goes in: no paths, keys, setting
 * values, device identifiers or provider answers. */
namespace fortis::host::updates {

/** One line of the health report. */
struct HealthCheck {
  enum class State { kHealthy, kWaiting, kFailing };
  std::string name, detail;
  State state = State::kHealthy;
};
/** Everything the pages say, gathered by the administrator's side. */
struct HostFacts {
  uint64_t generated_ms = 0;
  std::string orchestrator_version;  // the release version it was built as
  std::string architecture;          // "x86_64" or "aarch64"
  std::string runs_in;               // "machine" or "container"
  // "not-installed", "serving", "stopped", "updating" or "recovering".
  std::string node_state, node_version, node_sha256;
  std::vector<HealthCheck> orchestrator, node;
  unsigned processors = 0;
  uint64_t memory_bytes = 0, disk_bytes = 0, disk_free_bytes = 0;
  std::string address, domain;      // what the certificate is for; may be empty
  std::string newest_release;       // newest in the accepted release index; may be empty
  std::vector<std::string> staged;  // releases downloaded and waiting for `update`
  bool store_configured = false;
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
/** The same report as a page in the first page's design. */
std::string RenderHealthPage(const HostFacts& facts);
/** The first page. */
std::string RenderFirstPage(const HostFacts& facts);

/** Names of the published files, shared with whoever serves them. */
inline constexpr char kFirstPageFile[] = "index.html";
inline constexpr char kHealthPageFile[] = "health.html";
inline constexpr char kHealthJsonFile[] = "health.json";
/** One line, "STATUS GENERATED_MS": lets a server answer with the right
 * status code and notice a report nobody refreshes, without reading JSON. */
inline constexpr char kHealthStatusFile[] = "health.status";
/** A report older than this is stale and is answered with 503. */
inline constexpr uint64_t kHealthFreshMs = 60 * 1000;

/** Write the four files into `directory`, each replaced in one step so a
 * reader never sees half a file. */
void PublishPages(const fs::path& directory, const HostFacts& facts);

}  // namespace fortis::host::updates
