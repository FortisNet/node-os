#pragma once

#include "native_control_support.h"

/** The release store: a plain HTTPS file tree that the node host reads and
 * does not trust. Only signatures are trusted, and those are checked by the
 * administrator's side, not here.
 *
 *   BASE/index                       the list of releases, one line each
 *   BASE/index.sig                   signature over the exact index bytes
 *   BASE/releases/VERSION/manifest   as written by the release build
 *   BASE/releases/VERSION/manifest.sig
 *   BASE/releases/VERSION/fortis-node
 *
 * BASE is the store's address followed by the host's processor
 * architecture: a store holds one such tree for each.
 */
namespace fortis::host::updates {

struct ReleaseIndexEntry {
  std::string version, manifest_sha256;
  uint64_t bytes = 0;  // size of the release's executable
};
/** A parsed index. `sequence` grows by one with every publication. */
struct ReleaseIndex {
  uint64_t sequence = 0, published_ms = 0;
  std::vector<ReleaseIndexEntry> releases;  // oldest first; the last is the newest
  const ReleaseIndexEntry* Find(std::string_view version) const;
};
/** Parse index text strictly: a fixed header, then one line per release with
 * no version listed twice. The text is untrusted until its signature has
 * been verified; parsing it is bounded and has no effect. Throws
 * runtime_error on anything unexpected. */
ReleaseIndex ParseReleaseIndex(std::string_view text);

struct StoreSettings {
  std::string base_url;         // https, no trailing slash
  std::string ca_file;          // trust anchors for the store's certificate
  std::string user_agent;       // "FortisNet-Orchestrator/<version>"
  bool allow_loopback = false;  // a local test store only
};
/** Download BASE/index and BASE/index.sig into `staging` (as `index` and
 * `index.sig`). Runs unprivileged. Verifies nothing: the caller's
 * administrator side decides whether what was fetched is acceptable. */
void DownloadIndex(const StoreSettings& store, const fs::path& staging);
/** Ask each of `services` (https addresses that answer with the caller's
 * public IPv4 address as plain text) and save each answer as
 * `staging/address.N`, N counting from 0. A service that cannot be reached
 * leaves no file. `client.base_url` is not used. Runs unprivileged and
 * judges nothing: an answer is only a claim, which the administrator's side
 * checks and the certificate authority's own check then proves or refutes. */
void DownloadAddressAnswers(const StoreSettings& client, const std::vector<std::string>& services,
                            const fs::path& staging);
/** Download one release's manifest, signature and executable into
 * `staging/VERSION/`. The executable is fetched in ranges and must be
 * exactly `bytes` long. Runs unprivileged and verifies nothing else. */
void DownloadRelease(const StoreSettings& store, const fs::path& staging, const std::string& version, uint64_t bytes);

}  // namespace fortis::host::updates
