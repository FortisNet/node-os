#include "release_fetch.h"
#include <iostream>
#include "outbound_https.h"

namespace fortis::host::updates {
namespace {
constexpr size_t kIndexLimit = 256 * 1024, kSignatureLimit = 16 * 1024, kManifestLimit = 1024;
constexpr uint64_t kExecutableLimit = 134217728;  // as the release admission allows
constexpr size_t kChunk = 2 * 1024 * 1024;

// How many redirects are followed for one file before the store is given up on.
constexpr unsigned kMaxRedirects = 5;

struct Url {
  std::string host, port, path;
};
Url ParseUrl(std::string_view text, const char* refusal = "the release store must use https") {
  constexpr std::string_view scheme = "https://";
  Require(text.size() <= 2000 && text.starts_with(scheme), refusal);
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
  std::string location;  // of a redirect; empty when the answer named none
};
/** One GET of exactly `url`; with `length`, only that range of the file. A
 * redirect is returned, not followed. Only an answer in the 200s has a
 * body: nothing here reads what a store says beside a refusal. */
Fetched GetOnce(const StoreSettings& store, const Url& url, size_t limit, uint64_t offset = 0, uint64_t length = 0) {
  http::OutboundRequest request;
  request.host = url.host.c_str();
  request.port = url.port.c_str();
  request.path = url.path.c_str();
  request.ca_file = store.ca_file.c_str();
  request.user_agent = store.user_agent.c_str();
  request.timeout_ms = 60000;
  request.max_response_bytes = limit;
  request.skip_non_2xx_body = true;
  if (store.allow_loopback) request.allow_address = Loopback;
  if (length) {
    request.header_count = 1;
    std::snprintf(request.headers[0].name, sizeof(request.headers[0].name), "Range");
    std::snprintf(request.headers[0].value, sizeof(request.headers[0].value), "bytes=%llu-%llu",
                  static_cast<unsigned long long>(offset), static_cast<unsigned long long>(offset + length - 1));
  }
  std::vector<unsigned char> buffer(limit);
  const auto response = http::OutboundHttpsRequest(request, buffer.data(), buffer.size());
  // A refusal or a redirect whose page is larger than the file asked for is
  // still only a refusal or a redirect: its page is never read.
  const bool unread_page = response.error == http::OutboundError::kTooLarge && response.declared_too_large &&
                           (response.status < 200 || response.status >= 300);
  if (response.error != http::OutboundError::kNone && !unread_page)
    throw std::runtime_error(std::string("release store unreachable: ") + http::OutboundErrorName(response.error));
  return {response.status, std::string(reinterpret_cast<const char*>(buffer.data()), response.body_length),
          response.has_location ? std::string(response.location) : std::string()};
}
bool Redirect(int status) { return status == 301 || status == 302 || status == 303 || status == 307 || status == 308; }
/** The address a redirect from `from` to `location` leads to. A Location
 * may be a whole address, which must be https, or relative to the address
 * that answered. Plain http is refused: a release list or a release would
 * then cross the network readable and changeable by anyone on the way, and
 * although signatures would catch a change, nothing is gained by allowing
 * it. */
Url RedirectTarget(const Url& from, std::string_view location) {
  constexpr const char* refusal = "the release store redirects to an address that is not https";
  location = location.substr(0, location.find('#'));
  Require(!location.empty(), "the release store redirects without saying where to");
  if (location.starts_with("//")) return ParseUrl("https:" + std::string(location), refusal);
  // "scheme:" before any slash or question mark means a whole address.
  const auto mark = location.find_first_of(":/?");
  if (mark != std::string_view::npos && location[mark] == ':') return ParseUrl(location, refusal);
  Url target = from;
  if (location.front() == '/') {
    target.path = std::string(location);
  } else {
    // Relative to the folder of the file that answered.
    const auto file = std::string_view(from.path).substr(0, from.path.find('?'));
    target.path = std::string(file.substr(0, file.rfind('/') + 1)) + std::string(location);
  }
  Require(target.path.size() <= 2000, "the release store redirects to an overlong address");
  return target;
}
/** One GET, following redirects: with `length`, only that range of the file.
 * Every hop is an https request under the same rules as the first: the same
 * trust anchors, the same size limit, the same address policy (so a store
 * on the internet cannot send this host to a loopback or private address).
 * The range is asked for again at every hop. */
Fetched Get(const StoreSettings& store, const std::string& address, size_t limit, uint64_t offset = 0,
            uint64_t length = 0) {
  auto url = ParseUrl(address);
  for (unsigned followed = 0;; ++followed) {
    auto fetched = GetOnce(store, url, limit, offset, length);
    if (!Redirect(fetched.status)) return fetched;
    Require(followed < kMaxRedirects, "the release store redirects too many times");
    url = RedirectTarget(url, fetched.location);
  }
}
/** A whole small file, which must exist and fit. */
std::string Whole(const StoreSettings& store, const std::string& address, size_t limit) {
  const auto fetched = Get(store, address, limit);
  Require(fetched.status == 200, "the release store does not have a requested file");
  return fetched.body;
}
/** Where the store keeps the release list. */
std::string IndexAddress(const StoreSettings& store) {
  if (store.layout == StoreLayout::kTree) return store.base_url + "/index";
  Require(KnownChannel(store.channel), "unknown release channel");
  return store.base_url + "/node-channel-" + store.channel + "/index-" + std::string(kArchitecture);
}
/** Where the store keeps one file of a release: `name` is "manifest",
 * "manifest.sig" or "fortis-node". */
std::string ReleaseFileAddress(const StoreSettings& store, const std::string& version, std::string_view name) {
  if (store.layout == StoreLayout::kTree) return store.base_url + "/releases/" + version + "/" + std::string(name);
  constexpr std::string_view prefix = "node-";
  const auto bare = std::string_view(version).substr(version.starts_with(prefix) ? prefix.size() : 0);
  Require(!bare.empty(), "invalid release request");
  auto address = store.base_url + "/node-" + std::string(bare) + "/fortis-node-" + std::string(kArchitecture);
  if (name != "fortis-node") address += "." + std::string(name);
  return address;
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
  static constexpr std::array<std::string_view, 5> kHeader{"format", "sequence", "published_ms", "expires_ms",
                                                           "channel"};
  // Format 1 has the first three header lines; the first line says which.
  size_t header_lines = 3;
  size_t line_number = 0;
  for (size_t start = 0; start < text.size(); ++line_number) {
    const auto end = text.find('\n', start);
    const auto line = text.substr(start, end - start);
    start = end + 1;
    if (line_number < header_lines) {
      const auto equal = line.find('=');
      Require(equal != std::string_view::npos && line.substr(0, equal) == kHeader.at(line_number),
              "release index header is not as expected");
      const auto value = line.substr(equal + 1);
      if (line_number == 0) {
        Require(value == "1" || value == "2", "unsupported release index format");
        index.format = value == "2" ? 2 : 1;
        header_lines = index.format == 2 ? 5 : 3;
      } else if (line_number == 1) index.sequence = Integer(value);
      else if (line_number == 2) index.published_ms = Integer(value);
      else if (line_number == 3) {
        index.expires_ms = Integer(value);
        Require(index.expires_ms > 0, "release index names no expiry");
      } else {
        Require(KnownChannel(value), "release index names an unknown channel");
        index.channel = std::string(value);
      }
      continue;
    }
    // release<TAB>VERSION<TAB>MANIFEST_SHA256<TAB>EXECUTABLE_BYTES, and in
    // format 2 <TAB>HOST_INTERFACE.
    std::vector<std::string_view> fields;
    for (size_t at = 0; at <= line.size();) {
      const auto tab = std::min(line.find('\t', at), line.size());
      fields.push_back(line.substr(at, tab - at));
      at = tab + 1;
      Require(fields.size() <= 5, "release index entry malformed");
    }
    Require(
        fields.size() == (index.format == 2 ? 5U : 4U) && fields[0] == "release" && Token(fields[1]) && Hex(fields[2]),
        "release index entry malformed");
    ReleaseIndexEntry entry{std::string(fields[1]), std::string(fields[2]), Integer(fields[3], kExecutableLimit),
                            index.format == 2 ? static_cast<unsigned>(Integer(fields[4], kHostInterfaceLimit)) : 1U};
    Require(
        entry.bytes >= 64 && entry.host_interface >= 1 && !index.Find(entry.version) && index.releases.size() < 1000,
        "release index entry refused");
    index.releases.push_back(std::move(entry));
  }
  Require(line_number >= header_lines && index.sequence > 0, "release index header is incomplete");
  return index;
}

void DownloadIndex(const StoreSettings& store, const fs::path& staging) {
  // The signature first: an index published between the two requests then
  // fails verification instead of pairing a new index with an old signature
  // silently, and the next check simply tries again.
  const auto address = IndexAddress(store);
  const auto signature = Whole(store, address + ".sig", kSignatureLimit);
  const auto index = Whole(store, address, kIndexLimit);
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
      // An address service is asked exactly where it was configured: a
      // redirect is not an answer.
      const auto fetched = GetOnce(client, ParseUrl(services[index]), 256);
      if (fetched.status == 200) Save(answer, fetched.body);
    } catch (const std::exception& error) {
      if (interrupted) throw;
      std::cerr << "Address service " << index << " did not answer: " << error.what() << '\n';
    }
  }
}

void DownloadRelease(const StoreSettings& store, const fs::path& staging, const std::string& version, uint64_t bytes) {
  Require(Token(version) && bytes >= 64 && bytes <= kExecutableLimit, "invalid release request");
  const auto folder = staging / version;
  std::error_code ignored;
  fs::remove_all(folder, ignored);
  Directory(folder, 0700);
  Save(folder / "manifest", Whole(store, ReleaseFileAddress(store, version, "manifest"), kManifestLimit));
  Save(folder / "manifest.sig", Whole(store, ReleaseFileAddress(store, version, "manifest.sig"), kSignatureLimit));
  const auto partial = folder / "fortis-node.partial";
  {
    FileDescriptor output(
        Check(::open(partial.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600), "create download"));
    const auto executable = ReleaseFileAddress(store, version, "fortis-node");
    for (uint64_t offset = 0; offset < bytes;) {
      Require(!interrupted, "download interrupted");
      const auto wanted = std::min<uint64_t>(kChunk, bytes - offset);
      const auto part = Get(store, executable, kChunk, offset, wanted);
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
