#pragma once

#include "native_control_support.h"

/** The release store: plain HTTPS files that the node host reads and does
 * not trust. Only signatures are trusted, and those are checked by the
 * administrator's side, not here. A store is laid out in one of two ways.
 *
 * As a tree (any static file host):
 *
 *   BASE/index                       the list of releases, one line each
 *   BASE/index.sig                   signature over the exact list bytes
 *   BASE/releases/VERSION/manifest   as written by the release build
 *   BASE/releases/VERSION/manifest.sig
 *   BASE/releases/VERSION/fortis-node
 *
 * BASE is the store's address followed by the host's processor
 * architecture: a store holds one such tree for each.
 *
 * Flat (the downloads of GitHub releases, where a folder is a release and
 * cannot hold folders):
 *
 *   PREFIX/node-channel-CHANNEL/index-ARCH
 *   PREFIX/node-channel-CHANNEL/index-ARCH.sig
 *   PREFIX/node-V/fortis-node-ARCH
 *   PREFIX/node-V/fortis-node-ARCH.manifest
 *   PREFIX/node-V/fortis-node-ARCH.manifest.sig
 *
 * V is the version without a leading "node-", so the versions
 * "node-9ed7c09016ee" and "1.2.3" live under node-9ed7c09016ee and
 * node-1.2.3.
 *
 * A store may answer with a redirect to another https address (GitHub does,
 * for every download). Up to five are followed for one file.
 */
namespace fortis::host::updates {

/** The channels a release list may be published for and a host may follow.
 * Having exactly these two is provisional and expected to change: the names,
 * their number and what each promises are not settled yet, so nothing
 * outside this list and the setting that selects from it should depend on
 * there being two. */
inline constexpr std::array<std::string_view, 2> kReleaseChannels{"stable", "edge"};
inline bool KnownChannel(std::string_view channel) {
  return std::find(kReleaseChannels.begin(), kReleaseChannels.end(), channel) != kReleaseChannels.end();
}

struct ReleaseIndexEntry {
  std::string version, manifest_sha256;
  uint64_t bytes = 0;           // size of the release's executable
  unsigned host_interface = 1;  // what the release needs from its host; format 1 lists mean 1
};
/** A parsed release list. `sequence` grows by one with every publication. */
struct ReleaseIndex {
  unsigned format = 1;
  uint64_t sequence = 0, published_ms = 0;
  uint64_t expires_ms = 0;                  // 0: the list never expires (format 1)
  std::string channel;                      // empty: the list names no channel (format 1)
  std::vector<ReleaseIndexEntry> releases;  // oldest first; the last is the newest
  const ReleaseIndexEntry* Find(std::string_view version) const;
};
/** Parse release list text strictly: a fixed header, then one line per
 * release with no version listed twice.
 *
 *   format=2                      format=1
 *   sequence=N                    sequence=N
 *   published_ms=MS               published_ms=MS
 *   expires_ms=MS                 release<TAB>VERSION<TAB>MANIFEST_SHA256<TAB>BYTES
 *   channel=stable
 *   release<TAB>VERSION<TAB>MANIFEST_SHA256<TAB>BYTES<TAB>HOST_INTERFACE
 *
 * The text is untrusted until its signature has been verified; parsing it is
 * bounded and has no effect. Whether the list has expired, and whether it
 * is for this host's channel, is for the caller to judge: it knows the time
 * and the channel. Throws runtime_error on anything unexpected. */
ReleaseIndex ParseReleaseIndex(std::string_view text);

enum class StoreLayout { kTree, kFlat };
struct StoreSettings {
  std::string base_url;         // https, no trailing slash: BASE of a tree, PREFIX of a flat store
  std::string ca_file;          // trust anchors for the store's certificate
  std::string user_agent;       // "FortisNet-Orchestrator/<version>"
  bool allow_loopback = false;  // a local test store only
  StoreLayout layout = StoreLayout::kTree;
  std::string channel = "stable";  // names the list's folder in a flat store
};
/** Download the release list and its signature into `staging` (as `index`
 * and `index.sig`). Runs unprivileged. Verifies nothing: the caller's
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
 * `staging/VERSION/` (as `manifest`, `manifest.sig` and `fortis-node`,
 * whatever the store calls them). The executable is fetched in ranges and
 * must be exactly `bytes` long. Runs unprivileged and verifies nothing
 * else. */
void DownloadRelease(const StoreSettings& store, const fs::path& staging, const std::string& version, uint64_t bytes);

}  // namespace fortis::host::updates
