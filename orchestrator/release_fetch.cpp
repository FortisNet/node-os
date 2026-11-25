#include "release_fetch.h"
#include <iostream>
#include "outbound_https.h"

namespace fortis::host::updates {
namespace {
constexpr size_t kIndexLimit = 256 * 1024, kSignatureLimit = 16 * 1024, kManifestLimit = 1024;
constexpr uint64_t kExecutableLimit = 134217728;  // as the release admission allows
constexpr size_t kChunk = 2 * 1024 * 1024;

struct Url {
  std::string host, port, path;
};
Url ParseUrl(std::string_view text) {
  constexpr std::string_view scheme = "https://";
  Require(text.size() <= 2000 && text.starts_with(scheme), "the release store must use https");
  text.remove_prefix(scheme.size());
  const auto slash = text.find('/');
  const auto authority = text.substr(0, slash);
  Url url;
  url.path = slash == std::string_view::npos ? "/" : std::string(text.substr(slash));
  const auto colon = authority.rfind(':');
  url.host = std::string(authority.substr(0, colon));
  url.port = colon == std::string_view::npos ? "443" : std::string(authority.substr(colon + 1));
  Require(!url.host.empty() && !url.port.empty(), "invalid release store address");
  return url;
}
bool Loopback(void*, uint32_t address) { return (address >> 24) == 127; }

struct Fetched {
  int status = 0;
  std::string body;
};
/** One GET; with `length`, only that range of the file. */
Fetched Get(const StoreSettings& store, const std::string& address, size_t limit, uint64_t offset = 0,
            uint64_t length = 0) {
  const auto url = ParseUrl(address);
  http::OutboundRequest request;
  request.host = url.host.c_str();
  request.port = url.port.c_str();
  request.path = url.path.c_str();
  request.ca_file = store.ca_file.c_str();
  request.user_agent = store.user_agent.c_str();
  request.timeout_ms = 60000;
  request.max_response_bytes = limit;
  if (store.allow_loopback) request.allow_address = Loopback;
  if (length) {
    request.header_count = 1;
    std::snprintf(request.headers[0].name, sizeof(request.headers[0].name), "Range");
    std::snprintf(request.headers[0].value, sizeof(request.headers[0].value), "bytes=%llu-%llu",
                  static_cast<unsigned long long>(offset), static_cast<unsigned long long>(offset + length - 1));
  }
  std::vector<unsigned char> buffer(limit);
  const auto response = http::OutboundHttpsRequest(request, buffer.data(), buffer.size());
  if (response.error != http::OutboundError::kNone)
    throw std::runtime_error(std::string("release store unreachable: ") + http::OutboundErrorName(response.error));
  return {response.status, std::string(reinterpret_cast<const char*>(buffer.data()), response.body_length)};
}
/** A whole small file, which must exist and fit. */
std::string Whole(const StoreSettings& store, const std::string& address, size_t limit) {
  const auto fetched = Get(store, address, limit);
  Require(fetched.status == 200, "the release store does not have a requested file");
  return fetched.body;
}
void Save(const fs::path& path, std::string_view bytes) {
  std::error_code ignored;
  fs::remove(path, ignored);
  AtomicFile(path, bytes, 0600);
}
}  // namespace

const ReleaseIndexEntry* ReleaseIndex::Find(std::string_view version) const {
  for (const auto& entry : releases)
    if (entry.version == version) return &entry;
  return nullptr;
}

ReleaseIndex ParseReleaseIndex(std::string_view text) {
  Require(!text.empty() && text.size() <= kIndexLimit && text.back() == '\n', "release index unreadable");
  ReleaseIndex index;
  static constexpr std::array<std::string_view, 3> kHeader{"format", "sequence", "published_ms"};
  size_t line_number = 0;
  for (size_t start = 0; start < text.size(); ++line_number) {
    const auto end = text.find('\n', start);
    const auto line = text.substr(start, end - start);
    start = end + 1;
    if (line_number < kHeader.size()) {
      const auto equal = line.find('=');
      Require(equal != std::string_view::npos && line.substr(0, equal) == kHeader[line_number],
              "release index header is not as expected");
      const auto value = line.substr(equal + 1);
      if (line_number == 0) Require(value == "1", "unsupported release index format");
      else if (line_number == 1) index.sequence = Integer(value);
      else index.published_ms = Integer(value);
      continue;
    }
    // release<TAB>VERSION<TAB>MANIFEST_SHA256<TAB>EXECUTABLE_BYTES
    std::vector<std::string_view> fields;
    for (size_t at = 0; at <= line.size();) {
      const auto tab = std::min(line.find('\t', at), line.size());
      fields.push_back(line.substr(at, tab - at));
      at = tab + 1;
    }
    Require(fields.size() == 4 && fields[0] == "release" && Token(fields[1]) && Hex(fields[2]),
            "release index entry malformed");
    ReleaseIndexEntry entry{std::string(fields[1]), std::string(fields[2]), Integer(fields[3], kExecutableLimit)};
    Require(entry.bytes >= 64 && !index.Find(entry.version) && index.releases.size() < 1000,
            "release index entry refused");
    index.releases.push_back(std::move(entry));
  }
  Require(line_number >= kHeader.size() && index.sequence > 0, "release index header is incomplete");
  return index;
}

void DownloadIndex(const StoreSettings& store, const fs::path& staging) {
  // The signature first: an index published between the two requests then
  // fails verification instead of pairing a new index with an old signature
  // silently, and the next check simply tries again.
  const auto signature = Whole(store, store.base_url + "/index.sig", kSignatureLimit);
  const auto index = Whole(store, store.base_url + "/index", kIndexLimit);
  Save(staging / "index", index);
  Save(staging / "index.sig", signature);
}

void DownloadAddressAnswers(const StoreSettings& client, const std::vector<std::string>& services,
                            const fs::path& staging) {
  for (size_t index = 0; index < services.size(); ++index) {
    const auto answer = staging / ("address." + std::to_string(index));
    std::error_code ignored;
    fs::remove(answer, ignored);
    try {
      const auto fetched = Get(client, services[index], 256);
      if (fetched.status == 200) Save(answer, fetched.body);
    } catch (const std::exception& error) {
      if (interrupted) throw;
      std::cerr << "Address service " << index << " did not answer: " << error.what() << '\n';
    }
  }
}

void DownloadRelease(const StoreSettings& store, const fs::path& staging, const std::string& version, uint64_t bytes) {
  Require(Token(version) && bytes >= 64 && bytes <= kExecutableLimit, "invalid release request");
  const auto base = store.base_url + "/releases/" + version + "/";
  const auto folder = staging / version;
  std::error_code ignored;
  fs::remove_all(folder, ignored);
  Directory(folder, 0700);
  Save(folder / "manifest", Whole(store, base + "manifest", kManifestLimit));
  Save(folder / "manifest.sig", Whole(store, base + "manifest.sig", kSignatureLimit));
  const auto partial = folder / "fortis-node.partial";
  {
    FileDescriptor output(
        Check(::open(partial.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600), "create download"));
    for (uint64_t offset = 0; offset < bytes;) {
      Require(!interrupted, "download interrupted");
      const auto wanted = std::min<uint64_t>(kChunk, bytes - offset);
      const auto part = Get(store, base + "fortis-node", kChunk, offset, wanted);
      // 206 with exactly the range asked for; a store that ignores ranges
      // answers 200 with the whole file, which is accepted only when the
      // whole file was the range.
      Require(
          (part.status == 206 || (part.status == 200 && offset == 0 && wanted == bytes)) && part.body.size() == wanted,
          "the release store returned a short or unexpected part of the release");
      WriteAll(output.get(), part.body.data(), part.body.size());
      offset += wanted;
    }
    Check(fsync(output.get()), "sync download");
  }
  Check(::rename(partial.c_str(), (folder / "fortis-node").c_str()), "complete download");
  SyncDirectory(folder);
}

}  // namespace fortis::host::updates
