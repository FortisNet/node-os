#pragma once

#include "bounded_json.h"
#include "posix_support.h"
#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <exception>
#include <fcntl.h>
#include <filesystem>
#include <limits>
#include <map>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <optional>
#include <poll.h>
#include <sstream>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <thread>

namespace fortis::host::updates {
namespace fs = std::filesystem;

/** The processor architecture this orchestrator was built for, as release
 * manifests name it. A host runs only node releases built for the same one. */
#if defined(__x86_64__)
inline constexpr std::string_view kArchitecture = "x86_64";
inline constexpr std::string_view kSeccompArchitecture = "SCMP_ARCH_X86_64";
inline constexpr unsigned kElfMachine = 62;
#elif defined(__aarch64__)
inline constexpr std::string_view kArchitecture = "aarch64";
inline constexpr std::string_view kSeccompArchitecture = "SCMP_ARCH_AARCH64";
inline constexpr unsigned kElfMachine = 183;
#else
inline constexpr std::string_view kArchitecture = "unsupported";
inline constexpr std::string_view kSeccompArchitecture = "unsupported";
inline constexpr unsigned kElfMachine = 0;
static_assert(false, "The orchestrator is built for x86_64 and aarch64 only");
#endif
using SteadyClock = std::chrono::steady_clock;
inline constexpr uint64_t kMaxPublicInteger = 9007199254740991ULL;
inline volatile std::sig_atomic_t interrupted = 0;
inline void OnSignal(int) { interrupted = 1; }

inline void Require(bool condition, const char* reason) {
  if (!condition) throw std::runtime_error(reason);
}
inline uint64_t Integer(std::string_view value, uint64_t maximum = kMaxPublicInteger) {
  Require(!value.empty() && value.size() <= 20, "invalid bounded integer");
  uint64_t result = 0;
  const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
  Require(!value.empty() && parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size() && result <= maximum,
          "invalid bounded integer");
  return result;
}
inline bool Token(std::string_view value, size_t maximum = 64) {
  return !value.empty() && value.size() <= maximum && value != "." && value != ".." &&
         std::all_of(value.begin(), value.end(), [](char c) {
           return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                  c == '.';
         });
}
inline bool Hex(std::string_view value, size_t count = 64) {
  return value.size() == count && std::all_of(value.begin(), value.end(),
                                              [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
inline uint64_t NowMs() {
  const auto value =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
          .count();
  Require(value > 0 && static_cast<uint64_t>(value) <= kMaxPublicInteger, "wall clock unavailable");
  return static_cast<uint64_t>(value);
}
inline std::string Quote(std::string_view value) {
  std::string out = "\"";
  for (const unsigned char c : value) {
    if (c == '"' || c == '\\') {
      out += '\\';
      out += static_cast<char>(c);
    } else if (c < 32) {
      out += "\\u00";
      out += "0123456789abcdef"[c >> 4];
      out += "0123456789abcdef"[c & 15];
    } else out += static_cast<char>(c);
  }
  return out + '"';
}
inline std::string Read(const fs::path& path, size_t limit = 64 * 1024) {
  FileDescriptor file(Check(::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC), "open regular file"));
  struct stat info {};
  Check(fstat(file.get(), &info), "stat file");
  Require(S_ISREG(info.st_mode) && info.st_size >= 0 && static_cast<uint64_t>(info.st_size) <= limit,
          "not a bounded regular file");
  std::string bytes;
  std::array<char, 8192> buffer{};
  for (;;) {
    const ssize_t n = ::read(file.get(), buffer.data(), buffer.size());
    if (n < 0 && errno == EINTR) continue;
    Check(n < 0 ? -1 : 0, "read file");
    if (!n) break;
    Require(static_cast<size_t>(n) <= limit - bytes.size(), "file grew past bound");
    bytes.append(buffer.data(), static_cast<size_t>(n));
  }
  return bytes;
}
inline void SyncDirectory(const fs::path& directory) {
  FileDescriptor file(Check(::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC), "open directory"));
  Check(fsync(file.get()), "sync directory");
}
inline void AtomicFile(const fs::path& path, std::string_view bytes, mode_t mode = 0600) {
  const auto temporary = path.string() + ".tmp-" + std::to_string(getpid());
  FileDescriptor file(
      Check(::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode), "create snapshot"));
  try {
    WriteAll(file.get(), bytes.data(), bytes.size());
    Check(fchmod(file.get(), mode), "snapshot permissions");
    Check(fsync(file.get()), "sync snapshot");
    Check(::rename(temporary.c_str(), path.c_str()), "publish snapshot");
    SyncDirectory(path.parent_path());
  } catch (...) {
    (void)::unlink(temporary.c_str());
    throw;
  }
}
inline void Directory(const fs::path& path, mode_t mode) {
  fs::create_directories(path);
  Require(!fs::is_symlink(fs::symlink_status(path)) && fs::is_directory(path), "unsafe directory");
  Check(chmod(path.c_str(), mode), "directory permissions");
}
struct CommandResult {
  int exit = 0;
  std::string output;
};

/** Execute bounded argv without a shell; all string views are consumed
 * synchronously. Owns/reaps the child and kills its process group on
 * timeout/output overflow. No command arguments or captured stderr are included
 * in public error messages. Serialized controller calls only; never invoke
 * after starting controller threads.
 */
inline CommandResult Command(std::vector<std::string> command, unsigned timeout = 30,
                             size_t output_limit = 1024 * 1024) {
  Require(!command.empty(), "empty command");
  Require(command.size() <= 128, "command argument count exceeded");
  std::vector<char*> argv;
  argv.reserve(command.size() + 1);
  for (auto& value : command) argv.push_back(value.data());
  argv.push_back(nullptr);
  int descriptors[2]{};
  Check(pipe(descriptors), "command pipe");
  FileDescriptor input(descriptors[0]), output(descriptors[1]);
  Check(fcntl(input.get(), F_SETFD, FD_CLOEXEC), "command pipe close-on-exec");
  Check(fcntl(output.get(), F_SETFD, FD_CLOEXEC), "command output close-on-exec");
  Check(fcntl(input.get(), F_SETFL, O_NONBLOCK), "nonblocking command output");
  const pid_t child = fork();
  Check(child < 0 ? -1 : 0, "fork command");
  if (!child) {
    (void)setpgid(0, 0);
    (void)dup2(output.get(), STDOUT_FILENO);
    const int null = ::open("/dev/null", O_RDWR);
    if (null >= 0) {
      (void)dup2(null, STDERR_FILENO);
      (void)dup2(null, STDIN_FILENO);
    }
    ::execvp(argv.front(), argv.data());
    _exit(127);
  }
  (void)setpgid(child, child);
  output.reset();
  CommandResult result;
  int status = 0;
  bool reaped = false, eof = false;
  const auto deadline = SteadyClock::now() + std::chrono::seconds(timeout);
  try {
    while (!reaped || !eof) {
      Require(SteadyClock::now() < deadline && !interrupted, "command timed out or interrupted");
      std::array<char, 8192> buffer{};
      for (;;) {
        const ssize_t count = ::read(input.get(), buffer.data(), buffer.size());
        if (count > 0) {
          Require(static_cast<size_t>(count) <= output_limit - result.output.size(), "command output exceeded bound");
          result.output.append(buffer.data(), static_cast<size_t>(count));
        } else if (!count) {
          eof = true;
          break;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        else if (errno != EINTR) Check(-1, "read command output");
      }
      if (!reaped) {
        const pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) reaped = true;
        else if (waited < 0 && errno != EINTR) Check(-1, "reap command");
      }
      if (!reaped || !eof) {
        pollfd fd{input.get(), POLLIN, 0};
        (void)poll(&fd, 1, 20);
      }
    }
  } catch (...) {
    (void)kill(-child, SIGKILL);
    if (!reaped)
      while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    throw;
  }
  result.exit = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
  while (!result.output.empty() && (result.output.back() == '\n' || result.output.back() == '\r'))
    result.output.pop_back();
  return result;
}
inline void Pause(unsigned milliseconds) {
  const auto end = SteadyClock::now() + std::chrono::milliseconds(milliseconds);
  while (!interrupted && SteadyClock::now() < end) std::this_thread::sleep_for(std::chrono::milliseconds(20));
  Require(!interrupted, "controller interrupted");
}
inline std::string HexDigest(const std::array<unsigned char, 32>& digest) {
  std::string result;
  result.reserve(64);
  for (const auto byte : digest) {
    result += "0123456789abcdef"[byte >> 4];
    result += "0123456789abcdef"[byte & 15];
  }
  return result;
}
inline std::array<unsigned char, 32> RawDigest(std::string_view bytes) {
  std::array<unsigned char, 32> digest{};
  Require(mbedtls_sha256(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), digest.data(), 0) == 0,
          "SHA-256 failed");
  return digest;
}
inline std::string DigestBytes(std::string_view bytes) { return HexDigest(RawDigest(bytes)); }
/** SHA-256 of a file of any size, read in pieces. Follows a final symbolic
 * link: callers hash /proc/PID/exe. */
inline std::string Digest(const fs::path& path) {
  FileDescriptor file(Check(::open(path.c_str(), O_RDONLY | O_CLOEXEC), "open file to hash"));
  struct Context {
    mbedtls_sha256_context value;
    Context() { mbedtls_sha256_init(&value); }
    ~Context() { mbedtls_sha256_free(&value); }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
  } context;
  Require(mbedtls_sha256_starts(&context.value, 0) == 0, "SHA-256 failed");
  std::vector<unsigned char> buffer(64 * 1024);
  for (;;) {
    const ssize_t count = ::read(file.get(), buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR) continue;
    Check(count < 0 ? -1 : 0, "read file to hash");
    if (!count) break;
    Require(mbedtls_sha256_update(&context.value, buffer.data(), static_cast<size_t>(count)) == 0, "SHA-256 failed");
  }
  std::array<unsigned char, 32> digest{};
  Require(mbedtls_sha256_finish(&context.value, digest.data()) == 0, "SHA-256 failed");
  return HexDigest(digest);
}
/** True when `signature` is a valid ECDSA signature (ASN.1 DER, as OpenSSL
 * writes it) over the SHA-256 of `message` by the PEM public key in `key`.
 * Any unreadable, malformed or non-elliptic-curve key is simply not valid. */
inline bool SignatureValid(const fs::path& key, std::string_view message, std::string_view signature) {
  const auto pem = Read(key, 16 * 1024);
  struct Key {
    mbedtls_pk_context value;
    Key() { mbedtls_pk_init(&value); }
    ~Key() { mbedtls_pk_free(&value); }
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
  } parsed;
  // The PEM parser requires the terminating zero to be counted.
  if (mbedtls_pk_parse_public_key(&parsed.value, reinterpret_cast<const unsigned char*>(pem.c_str()), pem.size() + 1) !=
      0)
    return false;
  if (!mbedtls_pk_can_do(&parsed.value, MBEDTLS_PK_ECDSA) || mbedtls_pk_get_bitlen(&parsed.value) < 256) return false;
  const auto digest = RawDigest(message);
  return mbedtls_pk_verify(&parsed.value, MBEDTLS_MD_SHA256, digest.data(), digest.size(),
                           reinterpret_cast<const unsigned char*>(signature.data()), signature.size()) == 0;
}
/** True when `path` is a directory on a different filesystem from its parent
 * (or is the root). A bind mount of the same filesystem is not recognised. */
inline bool MountPoint(const fs::path& path) {
  struct stat self {
  }, parent{};
  if (stat(path.c_str(), &self) != 0 || !S_ISDIR(self.st_mode) || stat((path / "..").c_str(), &parent) != 0)
    return false;
  return self.st_dev != parent.st_dev || self.st_ino == parent.st_ino;
}
/** Bytes an unprivileged writer may still use on the filesystem of `path`. */
inline uint64_t AvailableBytes(const fs::path& path) {
  struct statvfs info {};
  Check(statvfs(path.c_str(), &info), "filesystem space");
  return static_cast<uint64_t>(info.f_bavail) * static_cast<uint64_t>(info.f_frsize);
}
/** Bytes a full copy of the tree writes: every file's length (holes are
 * copied as data) plus one block per entry for directories and metadata. */
inline uint64_t TreeBytes(const fs::path& directory) {
  uint64_t total = 4096;
  for (const auto& entry : fs::recursive_directory_iterator(directory)) {
    total += 4096;
    if (entry.is_regular_file() && !entry.is_symlink()) total += entry.file_size();
  }
  return total;
}
/** Copy one regular file to a new path and flush it to storage. With
 * `preserve`, owner, mode and modification time are copied as well; otherwise
 * the new file is private to the caller. Never follows a symbolic link. */
inline void CopyFile(const fs::path& source, const fs::path& destination, bool preserve,
                     SteadyClock::time_point deadline = SteadyClock::time_point::max()) {
  FileDescriptor input(Check(::open(source.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC), "open file to copy"));
  struct stat info {};
  Check(fstat(input.get(), &info), "stat file to copy");
  Require(S_ISREG(info.st_mode), "only regular files are copied");
  FileDescriptor output(Check(::open(destination.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600),
                              "create copied file"));
  std::vector<char> buffer(256 * 1024);
  for (;;) {
    Require(!interrupted && SteadyClock::now() < deadline, "copy timed out or interrupted");
    const ssize_t count = ::read(input.get(), buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR) continue;
    Check(count < 0 ? -1 : 0, "read file to copy");
    if (!count) break;
    WriteAll(output.get(), buffer.data(), static_cast<size_t>(count));
  }
  if (preserve) {
    Check(fchown(output.get(), info.st_uid, info.st_gid), "copied file owner");
    Check(fchmod(output.get(), info.st_mode & 07777), "copied file permissions");
    const struct timespec times[2]{info.st_atim, info.st_mtim};
    Check(futimens(output.get(), times), "copied file time");
  }
  Check(fsync(output.get()), "sync copied file");
}
/** Copy the contents of `source` into the existing directory `destination`,
 * keeping owners, modes and modification times, and flush everything to
 * storage. Symbolic links are copied as links; any other special file is an
 * error, because a database directory has no business holding one. Names
 * in `skip` are left out at the top level only. */
inline void CopyTree(const fs::path& source, const fs::path& destination, SteadyClock::time_point deadline,
                     const std::vector<std::string>& skip = {}) {
  for (const auto& entry : fs::directory_iterator(source)) {
    if (std::find(skip.begin(), skip.end(), entry.path().filename().string()) != skip.end()) continue;
    const auto target = destination / entry.path().filename();
    struct stat info {};
    Check(lstat(entry.path().c_str(), &info), "stat entry to copy");
    if (S_ISDIR(info.st_mode)) {
      Check(mkdir(target.c_str(), 0700), "create copied directory");
      CopyTree(entry.path(), target, deadline);
      Check(chown(target.c_str(), info.st_uid, info.st_gid), "copied directory owner");
      Check(chmod(target.c_str(), info.st_mode & 07777), "copied directory permissions");
      const struct timespec times[2]{info.st_atim, info.st_mtim};
      Check(utimensat(AT_FDCWD, target.c_str(), times, 0), "copied directory time");
    } else if (S_ISREG(info.st_mode)) {
      CopyFile(entry.path(), target, true, deadline);
    } else if (S_ISLNK(info.st_mode)) {
      fs::copy_symlink(entry.path(), target);
      Check(lchown(target.c_str(), info.st_uid, info.st_gid), "copied link owner");
    } else throw std::runtime_error("unsupported special file in copied directory");
  }
  SyncDirectory(destination);
}
inline std::map<std::string, std::string> KeyValues(std::string_view text, bool duplicates = false) {
  std::map<std::string, std::string> result;
  std::istringstream lines{std::string(text)};
  for (std::string line; std::getline(lines, line);) {
    if (line.empty() || line.front() == '#') continue;
    const auto equal = line.find('=');
    Require(equal != std::string::npos && equal > 0, "configuration must contain literal key=value lines");
    auto key = line.substr(0, equal), value = line.substr(equal + 1);
    if (value.size() >= 2 &&
        ((value.front() == '\'' && value.back() == '\'') || (value.front() == '"' && value.back() == '"')))
      value = value.substr(1, value.size() - 2);
    Require(duplicates || !result.contains(key), "duplicate metadata field");
    result[key] = std::move(value);
  }
  return result;
}
/** Own JSON input and tokens together. Parsed borrows never escape this
 * nonmoving owner. */
class Json final {
 public:
  explicit Json(std::string text) : text_(std::move(text)), tokens_(codec::kBoundedJsonMaxTokens) {
    codec::BoundedJsonError error{};
    Require(
        document_.ParseWithLimits(reinterpret_cast<const unsigned char*>(text_.data()), text_.size(), tokens_.data(),
                                  tokens_.size(), tokens_.size(), codec::kBoundedJsonMaxExpandedInputBytes, &error),
        "invalid bounded JSON");
  }
  Json(const Json&) = delete;
  Json& operator=(const Json&) = delete;
  Json(Json&&) = delete;
  Json& operator=(Json&&) = delete;
  const codec::BoundedJsonDocument& Get() const& { return document_; }
  const codec::BoundedJsonDocument& Get() const&& = delete;
  uint32_t Field(uint32_t object, const char* key) const { return document_.FindObjectValue(object, key); }
  uint32_t Root() const { return document_.root(); }
  bool Is(uint32_t value, codec::BoundedJsonType type) const {
    const auto* token = document_.token(value);
    return token && token->type == type;
  }
  uint64_t Unsigned(uint32_t token) const {
    const auto* value = document_.token(token);
    Require(value && value->type == codec::BoundedJsonType::kNumber, "missing JSON integer");
    return Integer(std::string_view(text_).substr(value->start, value->length));
  }
  std::string String(uint32_t token) const {
    std::array<char, 1024> output{};
    size_t length = 0;
    Require(document_.DecodeString(token, output.data(), output.size(), &length), "invalid JSON string");
    return {output.data(), length};
  }

 private:
  std::string text_;
  std::vector<codec::BoundedJsonToken> tokens_;
  codec::BoundedJsonDocument document_;
};
}  // namespace fortis::host::updates
