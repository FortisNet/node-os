#include "backup.h"

namespace fortis::host::updates {
namespace {
constexpr size_t kManifestLimit = 64 * 1024 * 1024;
constexpr uint64_t kEntryLimit = 2'000'000;

struct Entry {
  char kind = 'f';     // 'd' directory, 'f' file, 'l' symbolic link
  std::string detail;  // file: SHA-256; link: target
  uint64_t bytes = 0;
  bool operator==(const Entry&) const = default;
};
using Entries = std::map<std::string, Entry>;

/** A path that names something inside the folder and nowhere else. */
bool Inside(std::string_view path) {
  if (path.empty() || path.size() > 4096 || path.front() == '/') return false;
  size_t start = 0;
  while (start <= path.size()) {
    const auto end = std::min(path.find('/', start), path.size());
    const auto part = path.substr(start, end - start);
    if (part.empty() || part == "." || part == "..") return false;
    start = end + 1;
  }
  return std::all_of(path.begin(), path.end(), [](char c) {
    return static_cast<unsigned char>(c) >= 0x20 && static_cast<unsigned char>(c) != 0x7f;
  });
}
/** Everything under `directory`, by path relative to it. */
Entries Scan(const fs::path& directory, const std::set<std::string>& ignored) {
  Entries found;
  std::vector<fs::path> pending{directory};
  while (!pending.empty()) {
    const auto current = std::move(pending.back());
    pending.pop_back();
    for (const auto& item : fs::directory_iterator(current)) {
      const auto relative = item.path().lexically_relative(directory).generic_string();
      if (current == directory && ignored.contains(relative)) continue;
      Require(Inside(relative), "a file name in the tree cannot be recorded");
      Require(found.size() < kEntryLimit, "too many files");
      struct stat info {};
      Check(lstat(item.path().c_str(), &info), "inspect entry");
      if (S_ISDIR(info.st_mode)) {
        found[relative] = {'d', "", 0};
        pending.push_back(item.path());
      } else if (S_ISREG(info.st_mode)) {
        found[relative] = {'f', Digest(item.path()), static_cast<uint64_t>(info.st_size)};
      } else if (S_ISLNK(info.st_mode)) {
        const auto target = fs::read_symlink(item.path()).generic_string();
        // Resolved from the link's own folder, the target must stay inside.
        const auto resolved = (fs::path(relative).parent_path() / target).lexically_normal().generic_string();
        Require(Inside(target) || (!target.empty() && target.front() != '/' && Inside(resolved)),
                "a symbolic link leaves the tree");
        Require(!resolved.starts_with(".."), "a symbolic link leaves the tree");
        found[relative] = {'l', target, 0};
      } else throw std::runtime_error("the tree holds a special file");
    }
  }
  return found;
}
std::vector<std::string_view> Fields(std::string_view line) {
  std::vector<std::string_view> fields;
  for (size_t start = 0; start <= line.size();) {
    const auto end = std::min(line.find('\t', start), line.size());
    fields.push_back(line.substr(start, end - start));
    start = end + 1;
  }
  return fields;
}
}  // namespace

BackupSummary WriteBackupManifest(const fs::path& directory, std::string_view release,
                                  std::string_view release_sha256) {
  Require(Token(release) && (release_sha256 == "none" || Hex(release_sha256)), "invalid release for a backup");
  const auto entries = Scan(directory, {kBackupManifest});
  BackupSummary summary{NowMs(), entries.size(), 0, "1", std::string(release), std::string(release_sha256)};
  std::string body;
  for (const auto& [path, entry] : entries) {
    summary.bytes += entry.bytes;
    body += entry.kind;
    if (entry.kind != 'd') body += '\t' + entry.detail;
    if (entry.kind == 'f') body += '\t' + std::to_string(entry.bytes);
    body += '\t' + path + '\n';
  }
  const auto header = "format=1\ncreated_ms=" + std::to_string(summary.created_ms) +
                      "\nstorage_epoch=1\nrelease=" + summary.release + "\nrelease_sha256=" + summary.release_sha256 +
                      "\nentries=" + std::to_string(summary.entries) + "\nbytes=" + std::to_string(summary.bytes) +
                      "\n";
  std::error_code ignored;
  fs::remove(directory / kBackupManifest, ignored);
  AtomicFile(directory / kBackupManifest, header + body, 0600);
  return summary;
}

BackupSummary VerifyTree(const fs::path& directory, std::string_view manifest, const std::set<std::string>& ignored) {
  Require(!manifest.empty() && manifest.size() <= kManifestLimit && manifest.back() == '\n',
          "backup manifest unreadable");
  BackupSummary summary;
  Entries listed;
  uint64_t bytes = 0;
  size_t line_number = 0;
  static constexpr std::array<std::string_view, 7> kHeader{"format",         "created_ms", "storage_epoch", "release",
                                                           "release_sha256", "entries",    "bytes"};
  for (size_t start = 0; start < manifest.size(); ++line_number) {
    const auto end = manifest.find('\n', start);
    const auto line = manifest.substr(start, end - start);
    start = end + 1;
    if (line_number < kHeader.size()) {
      const auto equal = line.find('=');
      Require(equal != std::string_view::npos && line.substr(0, equal) == kHeader[line_number],
              "backup manifest header is not as expected");
      const auto value = line.substr(equal + 1);
      switch (line_number) {
        case 0: Require(value == "1", "unsupported backup format"); break;
        case 1: summary.created_ms = Integer(value); break;
        case 2: summary.storage_epoch = std::string(value); break;
        case 3: summary.release = std::string(value); break;
        case 4: summary.release_sha256 = std::string(value); break;
        case 5: summary.entries = Integer(value, kEntryLimit); break;
        default: summary.bytes = Integer(value); break;
      }
      continue;
    }
    const auto fields = Fields(line);
    Require(!fields.empty() && fields[0].size() == 1, "backup manifest entry malformed");
    Entry entry;
    entry.kind = fields[0][0];
    std::string_view path;
    if (entry.kind == 'd' && fields.size() == 2) path = fields[1];
    else if (entry.kind == 'f' && fields.size() == 4 && Hex(fields[1])) {
      entry.detail = std::string(fields[1]);
      entry.bytes = Integer(fields[2]);
      path = fields[3];
    } else if (entry.kind == 'l' && fields.size() == 3) {
      entry.detail = std::string(fields[1]);
      path = fields[2];
    } else throw std::runtime_error("backup manifest entry malformed");
    Require(Inside(path), "backup manifest names a path outside the backup");
    const auto top = std::string(path.substr(0, path.find('/')));
    if (ignored.contains(top) && path.find('/') == std::string_view::npos) continue;
    Require(listed.emplace(std::string(path), entry).second, "backup manifest lists a path twice");
    bytes += entry.bytes;
  }
  Require(line_number >= kHeader.size() && Token(summary.release) &&
              (summary.release_sha256 == "none" || Hex(summary.release_sha256)),
          "backup manifest header is incomplete");
  // The header's totals describe the whole backup; with entries ignored the
  // lists are compared instead.
  if (ignored.empty() || ignored == std::set<std::string>{kBackupManifest})
    Require(listed.size() == summary.entries && bytes == summary.bytes,
            "backup manifest totals do not match its entries");
  const auto present = Scan(directory, ignored);
  for (const auto& [path, entry] : listed) {
    const auto found = present.find(path);
    Require(found != present.end(), "the backup is missing a listed file");
    Require(found->second == entry, "a file in the backup differs from the manifest");
  }
  Require(present.size() == listed.size(), "the backup holds a file its manifest does not list");
  return summary;
}

BackupSummary VerifyBackup(const fs::path& directory) {
  Require(fs::is_directory(directory) && !fs::is_symlink(fs::symlink_status(directory)), "backup folder absent");
  return VerifyTree(directory, Read(directory / kBackupManifest, kManifestLimit), {kBackupManifest});
}

}  // namespace fortis::host::updates
