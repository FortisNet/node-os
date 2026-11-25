#pragma once

#include "native_control_support.h"
#include <set>

namespace fortis::host::updates {

/** Name of the manifest file at the top of every backup folder. */
inline constexpr char kBackupManifest[] = "fortis-backup.manifest";

/** What a backup's manifest says about it. */
struct BackupSummary {
  uint64_t created_ms = 0, entries = 0, bytes = 0;
  std::string storage_epoch, release, release_sha256;
};

/** Hash every file under `directory` and write the manifest beside them: one
 * line per directory, file (with size and SHA-256) and symbolic link, after a
 * short header. `release` and `release_sha256` name the node release that
 * last wrote the data ("none" when no release is installed).
 * Throws runtime_error when the tree holds anything but directories, regular
 * files and relative symbolic links that stay inside it. */
BackupSummary WriteBackupManifest(const fs::path& directory, std::string_view release, std::string_view release_sha256);

/** Check `directory` against the manifest text `manifest`: every listed
 * entry is present with the listed size and hash, and nothing else is.
 * Top-level names in `ignored` are left out on both sides. The manifest may
 * come from another machine, so it is treated as untrusted input: it is
 * bounded, and no path in it may leave the folder.
 * Throws runtime_error naming the first problem. */
BackupSummary VerifyTree(const fs::path& directory, std::string_view manifest, const std::set<std::string>& ignored);

/** A backup folder is complete and undamaged: its own manifest matches it. */
BackupSummary VerifyBackup(const fs::path& directory);

}  // namespace fortis::host::updates
