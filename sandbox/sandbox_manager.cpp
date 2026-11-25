// Linux host tool only. Never linked into the API server or Unikraft guest.
#include "sandbox_spec.h"
#include "native_control_support.h"
#include "sandbox_socket.h"
#include "sandbox_wire.h"

#include <iostream>
#include <limits>
#include <optional>
#include <set>
#include <sys/resource.h>
#ifdef __linux__
#include <linux/magic.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/vfs.h>
#endif

namespace fortis::host::sandbox {
namespace {
namespace io = updates;
namespace fs = std::filesystem;
void Require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

#ifdef __linux__
volatile std::sig_atomic_t cancelled = 0;
void Interrupt(int) { cancelled = 1; }

void TrustedPath(const fs::path& path, bool directory) {
  Require(path.is_absolute() && path.lexically_normal() == path, "unsafe host path");
  struct stat root {};
  Check(lstat("/", &root), "inspect host root");
  Require(S_ISDIR(root.st_mode) && root.st_uid == 0 && !(root.st_mode & 0022), "untrusted host root");
  fs::path at = "/";
  for (const auto& part : path.relative_path()) {
    at /= part;
    struct stat info {};
    Check(lstat(at.c_str(), &info), "inspect protected path");
    Require(!S_ISLNK(info.st_mode) && info.st_uid == 0 && !(info.st_mode & 0022), "untrusted host path");
    Require(at == path && !directory ? S_ISREG(info.st_mode) : S_ISDIR(info.st_mode), "wrong host object type");
  }
}

void MakeDirectory(const fs::path& path, mode_t mode) {
  TrustedPath(path.parent_path(), true);
  if (mkdir(path.c_str(), mode) != 0 && errno != EEXIST) Check(-1, "create sandbox directory");
  TrustedPath(path, true);
  struct stat info {};
  Check(stat(path.c_str(), &info), "stat sandbox directory");
  Require((info.st_mode & 0777) == mode, "sandbox directory permissions mismatch");
}

std::string Digest(std::string_view bytes) {
  std::array<unsigned char, 32> hash{};
  Require(mbedtls_sha256(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), hash.data(), 0) == 0,
          "sandbox checksum failed");
  std::string out;
  for (unsigned char c : hash) {
    out += "0123456789abcdef"[c >> 4];
    out += "0123456789abcdef"[c & 15];
  }
  return out;
}

std::string FileDigest(const fs::path& path) {
  TrustedPath(path, false);
  FileDescriptor file(Check(open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC), "open sandbox runtime"));
  struct stat info {};
  Check(fstat(file.get(), &info), "stat sandbox runtime");
  Require((info.st_mode & 0111) && !(info.st_mode & 06000) && info.st_size > 0 && info.st_size <= 512 * 1024 * 1024,
          "invalid sandbox runtime executable");
  struct Hash {
    mbedtls_sha256_context context{};
    Hash() { mbedtls_sha256_init(&context); }
    ~Hash() { mbedtls_sha256_free(&context); }
  } hash;
  Require(mbedtls_sha256_starts(&hash.context, 0) == 0, "runtime hash initialization failed");
  std::array<unsigned char, 16384> bytes{};
  for (;;) {
    const ssize_t n = read(file.get(), bytes.data(), bytes.size());
    if (n < 0 && errno == EINTR) continue;
    Check(n < 0 ? -1 : 0, "read sandbox runtime");
    if (!n) break;
    Require(mbedtls_sha256_update(&hash.context, bytes.data(), static_cast<size_t>(n)) == 0, "runtime hash failed");
  }
  std::array<unsigned char, 32> sum{};
  Require(mbedtls_sha256_finish(&hash.context, sum.data()) == 0, "runtime hash finish failed");
  std::string out;
  for (unsigned char c : sum) {
    out += "0123456789abcdef"[c >> 4];
    out += "0123456789abcdef"[c & 15];
  }
  return out;
}

FileDescriptor Lock(const fs::path& path, bool wait = true) {
  FileDescriptor file(Check(open(path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600), "open sandbox lock"));
  struct stat info {};
  Check(fstat(file.get(), &info), "stat sandbox lock");
  Require(S_ISREG(info.st_mode) && info.st_uid == 0 && !(info.st_mode & 0077), "untrusted sandbox lock");
  if (flock(file.get(), LOCK_EX | (wait ? 0 : LOCK_NB)) < 0) {
    if (!wait && (errno == EWOULDBLOCK || errno == EAGAIN)) return FileDescriptor{};
    Check(-1, "lock sandbox state");
  }
  return file;
}

struct Record {
  std::string id;
  std::string image;
  std::string state = "starting";
  uint64_t slot = 0;
  uint64_t cpu = 0;
  uint64_t memory = 0;
  uint64_t created = 0;
  uint64_t finished = 0;
  uint64_t cpu_usec = 0;
  uint64_t memory_peak = 0;
  uint64_t oom_kills = 0;
  uint64_t output_bytes = 0;
  uint64_t task_limit_hits = 0;
  uint64_t deadline_mono_ms = 0;
  bool metrics_sampled = false;
  int exit_code = -1;
  uint32_t owner_uid = 0;
  std::string request_hash;
};

bool Terminal(std::string_view state) {
  return state == "succeeded" || state == "failed" || state == "timed_out" || state == "cancelled" ||
         state == "oom_killed" || state == "task_limit" || state == "output_limit" || state == "interrupted";
}

std::string RecordJson(const Record& r) {
  return "{\"schemaVersion\":1,\"id\":" + Quote(r.id) + ",\"image\":" + Quote(r.image) +
         ",\"state\":" + Quote(r.state) + ",\"slot\":" + std::to_string(r.slot) +
         ",\"cpuLimitMillicores\":" + std::to_string(r.cpu) + ",\"memoryLimitMiB\":" + std::to_string(r.memory) +
         ",\"createdAtMs\":" + std::to_string(r.created) + ",\"finishedAtMs\":" + std::to_string(r.finished) +
         ",\"cpuUsageUsec\":" + std::to_string(r.cpu_usec) + ",\"memoryPeakBytes\":" + std::to_string(r.memory_peak) +
         ",\"oomKills\":" + std::to_string(r.oom_kills) + ",\"outputBytes\":" + std::to_string(r.output_bytes) +
         ",\"deadlineMonotonicMs\":" + std::to_string(r.deadline_mono_ms) +
         ",\"taskLimitHits\":" + std::to_string(r.task_limit_hits) +
         ",\"metricsSampled\":" + std::string(r.metrics_sampled ? "true" : "false") +
         ",\"exitCode\":" + std::to_string(r.exit_code) + "}";
}

void Store(const fs::path& job, const Record& record) {
  auto json = RecordJson(record);
  json.pop_back();
  json += ",\"ownerUid\":" + std::to_string(record.owner_uid) + ",\"requestHash\":" + Quote(record.request_hash) + "}";
  io::AtomicFile(job / "record", json + '\n' + Digest(json) + '\n');
}

Record Load(const fs::path& job, const Policy& policy) {
  TrustedPath(job, true);
  const auto bytes = io::Read(job / "record", 8192);
  const size_t end = bytes.find('\n');
  Require(end != std::string::npos && bytes.substr(end + 1) == Digest(std::string_view(bytes).substr(0, end)) + '\n',
          "sandbox record checksum mismatch");
  const io::Json json(bytes.substr(0, end));
  const auto field = [&](const char* key) { return json.Field(json.Root(), key); };
  Require(json.Unsigned(field("schemaVersion")) == 1, "unsupported sandbox record");
  Record r;
  if (field("ownerUid") != codec::kBoundedJsonNoToken) {
    const auto uid = json.Unsigned(field("ownerUid"));
    Require(uid <= UINT32_MAX, "invalid sandbox owner");
    r.owner_uid = static_cast<uint32_t>(uid);
    r.request_hash = json.String(field("requestHash"));
    Require(r.request_hash.empty() ? r.owner_uid == 0 : io::Hex(r.request_hash, 64), "invalid request identity");
  }
  r.id = json.String(field("id"));
  r.image = json.String(field("image"));
  r.state = json.String(field("state"));
  r.slot = json.Unsigned(field("slot"));
  r.cpu = json.Unsigned(field("cpuLimitMillicores"));
  r.memory = json.Unsigned(field("memoryLimitMiB"));
  r.created = json.Unsigned(field("createdAtMs"));
  r.finished = json.Unsigned(field("finishedAtMs"));
  r.cpu_usec = json.Unsigned(field("cpuUsageUsec"));
  r.memory_peak = json.Unsigned(field("memoryPeakBytes"));
  r.oom_kills = json.Unsigned(field("oomKills"));
  r.output_bytes = json.Unsigned(field("outputBytes"));
  r.task_limit_hits = json.Unsigned(field("taskLimitHits"));
  r.deadline_mono_ms = json.Unsigned(field("deadlineMonotonicMs"));
  r.metrics_sampled = json.Is(field("metricsSampled"), codec::BoundedJsonType::kTrue);
  const auto code = json.Get().token(field("exitCode"));
  Require(code != nullptr, "missing sandbox exit code");
  const auto literal = std::string_view(bytes).substr(code->start, code->length);
  if (literal != "-1") r.exit_code = static_cast<int>(io::Integer(literal, 255));
  Require(Identifier(r.id) && Identifier(r.image) && r.id == job.filename() && r.slot < policy.limits.jobs &&
              r.cpu >= 10 && r.cpu <= policy.limits.cpu_millicores && r.memory >= 64 &&
              r.memory <= policy.limits.memory_mib && r.created > 0 &&
              (Terminal(r.state) || r.state == "starting" || r.state == "running" || r.state == "cleanup_failed"),
          "invalid sandbox record");
  return r;
}

std::vector<fs::path> Jobs(const Policy& policy) {
  std::vector<fs::path> jobs;
  for (const auto& entry : fs::directory_iterator(fs::path(policy.state_root) / "jobs")) {
    Require(Identifier(entry.path().filename().string()), "unexpected sandbox state entry");
    jobs.push_back(entry.path());
    Require(jobs.size() <= 128, "sandbox history capacity exhausted");
  }
  std::sort(jobs.begin(), jobs.end());
  return jobs;
}

fs::path Cgroup(const Policy& policy, std::string_view id = {}) {
  const fs::path parent("/sys/fs/cgroup" + policy.cgroup_parent);
  return id.empty() ? parent : parent / std::string(id);
}

std::string Control(const fs::path& path) {
  FileDescriptor file(Check(open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC), "open cgroup control"));
  std::array<char, 8192> bytes{};
  const ssize_t n = read(file.get(), bytes.data(), bytes.size());
  Check(n < 0 ? -1 : 0, "read cgroup control");
  Require(n >= 0 && static_cast<size_t>(n) < bytes.size(), "cgroup control too large");
  return {bytes.data(), static_cast<size_t>(n)};
}

void SetControl(const fs::path& path, std::string_view value) {
  FileDescriptor file(Check(open(path.c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC), "open cgroup setting"));
  WriteAll(file.get(), value.data(), value.size());
}

void CgroupReady(const Policy& policy) {
#ifdef __linux__
  struct statfs info {};
  Check(statfs("/sys/fs/cgroup", &info), "inspect cgroup mount");
  Require(static_cast<unsigned long>(info.f_type) == CGROUP2_SUPER_MAGIC, "cgroup v2 required");
#else
  throw std::runtime_error("Linux cgroup v2 required");
#endif
  TrustedPath(Cgroup(policy), true);
  const auto enabled = Control(Cgroup(policy) / "cgroup.subtree_control");
  for (const char* name : {"cpu", "memory", "pids"})
    Require((" " + enabled + " ").find(" " + std::string(name) + " ") != std::string::npos ||
                enabled.starts_with(std::string(name) + '\n') ||
                enabled.find(std::string(name) + '\n') != std::string::npos,
            "required delegated cgroup controller unavailable");
  Require(fs::exists(Cgroup(policy) / "cgroup.kill"), "kernel cgroup.kill support required");
}

// Root runtimes can map arbitrary IDs. Require an explicit exclusive reservation
// rather than relying on a high number that might belong to another tenant.
void ReservedIds(const Policy& policy) {
  const uint64_t begin = policy.uid_base;
  const uint64_t count = policy.limits.jobs * 65536;
  for (const char* name : {"/etc/subuid", "/etc/subgid"}) {
    TrustedPath(name, false);
    std::istringstream lines(io::Read(name, 131072));
    std::string line;
    bool found = false;
    while (std::getline(lines, line)) {
      if (line.empty() || line.front() == '#') continue;
      const auto first = line.find(':');
      const auto second = line.find(':', first == std::string::npos ? first : first + 1);
      Require(
          first != std::string::npos && second != std::string::npos && line.find(':', second + 1) == std::string::npos,
          "invalid subordinate ID registry");
      const auto start = io::Integer(std::string_view(line).substr(first + 1, second - first - 1), UINT32_MAX);
      const auto length = io::Integer(std::string_view(line).substr(second + 1), UINT32_MAX);
      Require(length && start + length <= uint64_t{UINT32_MAX} + 1, "invalid subordinate ID range");
      if (start < begin + count && begin < start + length) {
        Require(!found && line.substr(0, first) == "fortis-sandbox" && start == begin && length == count,
                "sandbox subordinate IDs are not exclusively reserved");
        found = true;
      }
    }
    Require(found, "dedicated fortis-sandbox subordinate ID reservation required");
  }
}

void Installation(const Policy& policy) {
  Require(geteuid() == 0, "sandbox host operations require root");
  ReservedIds(policy);
  for (const auto& path :
       {fs::path(policy.state_root), fs::path(policy.state_root) / "jobs", fs::path(policy.state_root) / "runtime"}) {
    TrustedPath(path, true);
    struct stat permissions {};
    Check(stat(path.c_str(), &permissions), "inspect private sandbox directory");
    Require((permissions.st_mode & 0777) == 0700, "sandbox state must be private");
  }
  TrustedPath(policy.image_root, true);
  Require(FileDigest(policy.runtime) == policy.runtime_sha256, "sandbox runtime hash mismatch");
  const auto version = io::Command({policy.runtime, "--version"}, 5, 4096);
  Require(version.exit == 0 &&
              version.output.find(policy.isolation == "gvisor" ? "runsc version" : "crun version") != std::string::npos,
          "runtime does not match configured isolation class");
  if (policy.isolation == "gvisor") {
    const auto sidecars = fs::path(policy.runtime).parent_path() / "gvisor-bin";
    TrustedPath(sidecars, true);
    // Minimal systrap profile: the Sentry and all lifecycle/security helpers.
    // Never substitute direct host execution when an essential helper is absent.
    for (const char* name : {"gvisor_sentry", "gvisor-sentry-prewarmer", "runsc-fd-parking", "gvisor-proc-umounter"}) {
      const auto file = sidecars / name;
      TrustedPath(file, false);
      struct stat permissions {};
      Check(stat(file.c_str(), &permissions), "inspect required gVisor sidecar");
      Require((permissions.st_mode & 0111) && !(permissions.st_mode & 06000), "invalid gVisor sidecar executable");
    }
    for (const auto& file : fs::recursive_directory_iterator(sidecars)) TrustedPath(file.path(), file.is_directory());
  }
  auto lock = Lock(fs::path(policy.state_root) / "admission.lock");
  const auto identity = PolicyIdentity(policy);
  const auto path = fs::path(policy.state_root) / "policy.json";
  if (fs::exists(path)) Require(io::Read(path) == identity, "sandbox installation policy changed");
  else io::AtomicFile(path, identity);
  CgroupReady(policy);
}

void Image(const fs::path& root) {
  TrustedPath(root, true);
  size_t count = 0;
  for (const auto& entry : fs::recursive_directory_iterator(root)) {
    Require(++count <= 100000, "sandbox image entry bound exceeded");
    struct stat info {};
    Check(lstat(entry.path().c_str(), &info), "inspect sandbox image");
    Require(info.st_uid == 0 && (S_ISLNK(info.st_mode) || !(info.st_mode & 0022)), "image is not administrator-owned");
    Require(S_ISDIR(info.st_mode) || S_ISREG(info.st_mode) || S_ISLNK(info.st_mode), "special file in sandbox image");
    if (S_ISREG(info.st_mode)) Require(!(info.st_mode & 0222), "sandbox image file is writable");
  }
  for (const char* name : {"proc", "tmp", "dev"}) TrustedPath(root / name, true);
  Require(fs::is_empty(root / "proc") && fs::is_empty(root / "tmp") && fs::is_empty(root / "dev"),
          "sandbox mount targets must be empty");
}

std::vector<std::string> RuntimeArgs(const Policy& policy) {
  std::vector<std::string> command{policy.runtime, "--root", (fs::path(policy.state_root) / "runtime").string()};
  if (policy.isolation == "gvisor") {
    command.emplace_back("--platform=systrap");
    command.emplace_back("--network=none");
    command.emplace_back("--directfs=false");
    command.emplace_back("--oci-seccomp=true");
    command.emplace_back("--netgofer=off");
    command.emplace_back("--metric-server=");
    command.emplace_back("--sidecar-release-enforcement-policy=ALWAYS");
  }
  return command;
}

bool EmptyCgroup(const Policy& policy, const Record& record) {
  const auto path = Cgroup(policy, record.id);
  if (!fs::exists(path)) return true;
  return Control(path / "cgroup.events").find("populated 0") != std::string::npos;
}

bool Cleanup(const Policy& policy, const Record& record) noexcept {
  try {
    const auto group = Cgroup(policy, record.id);
    if (fs::exists(group)) SetControl(group / "cgroup.kill", "1");
    auto kill = RuntimeArgs(policy);
    kill.insert(kill.end(), {"kill", record.id, "KILL"});
    (void)io::Command(kill, 5, 8192);
    auto remove = RuntimeArgs(policy);
    remove.insert(remove.end(), {"delete", "--force", record.id});
    (void)io::Command(remove, 5, 8192);
    for (unsigned attempt = 0; attempt < 50; ++attempt) {
      if (EmptyCgroup(policy, record)) return true;
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  } catch (...) { return false; }
  return false;
}

void Sample(const Policy& policy, Record& record) {
  const auto group = Cgroup(policy, record.id);
  if (!fs::exists(group)) return;
  record.metrics_sampled = true;
  for (const auto& [name, output] :
       std::array<std::pair<const char*, uint64_t*>, 3>{{{"memory.peak", &record.memory_peak},
                                                         {"memory.events", &record.oom_kills},
                                                         {"pids.events", &record.task_limit_hits}}}) {
    const auto text = Control(group / name);
    if (std::string_view(name) == "memory.peak") {
      *output = std::max(*output, io::Integer(std::string_view(text).substr(0, text.find('\n'))));
    } else {
      std::istringstream lines(text);
      std::string key;
      uint64_t value = 0;
      while (lines >> key >> value)
        if (key == (std::string_view(name) == "pids.events" ? "max" : "oom_kill")) *output = std::max(*output, value);
    }
  }
  std::istringstream cpu(Control(group / "cpu.stat"));
  std::string key;
  uint64_t value = 0;
  while (cpu >> key >> value)
    if (key == "usage_usec") record.cpu_usec = std::max(record.cpu_usec, value);
}

class Child {
 public:
  Child(std::vector<std::string>& command, int output, const fs::path& launcher) {
    int barrier[2]{};
    Check(pipe(barrier), "sandbox start barrier");
    FileDescriptor ready(barrier[0]), release(barrier[1]);
    Check(fcntl(ready.get(), F_SETFD, FD_CLOEXEC), "sandbox start read close-on-exec");
    Check(fcntl(release.get(), F_SETFD, FD_CLOEXEC), "sandbox start write close-on-exec");
    std::vector<char*> argv;
    argv.reserve(command.size() + 1);
    for (auto& arg : command) argv.push_back(arg.data());
    argv.push_back(nullptr);
    // This CLI is single-threaded. Snapshot every inherited descriptor before
    // fork, without allocating in the child. Bounded fallback supports syscall
    // emulators reporting ENOSYS; permission failures still refuse execution.
    std::vector<int> inherited;
    for (const auto& entry : fs::directory_iterator("/proc/self/fd")) {
      Require(inherited.size() < 8192, "too many inherited sandbox descriptors");
      const auto fd = io::Integer(entry.path().filename().string(), std::numeric_limits<int>::max());
      if (fd >= 3) inherited.push_back(static_cast<int>(fd));
    }
    pid_ = fork();
    Check(pid_ < 0 ? -1 : 0, "fork sandbox runtime");
    if (!pid_) {
      (void)close(release.get());
      char start = 0;
      ssize_t n = 0;
      do { n = read(ready.get(), &start, 1); } while (n < 0 && errno == EINTR);
      if (n != 1 || start != '1') _exit(126);
      (void)setpgid(0, 0);
      (void)signal(SIGINT, SIG_DFL);
      (void)signal(SIGTERM, SIG_DFL);
      (void)signal(SIGPIPE, SIG_DFL);
      if (dup2(output, STDOUT_FILENO) < 0 || dup2(output, STDERR_FILENO) < 0 || fcntl(STDOUT_FILENO, F_SETFD, 0) < 0 ||
          fcntl(STDERR_FILENO, F_SETFD, 0) < 0)
        _exit(126);
      const int input = open("/dev/null", O_RDONLY);
      if (input < 0 || dup2(input, STDIN_FILENO) < 0) _exit(126);
      if (input > STDERR_FILENO) (void)close(input);
      sigset_t empty;
      (void)sigemptyset(&empty);
      (void)sigprocmask(SIG_SETMASK, &empty, nullptr);
      // musl does not expose the glibc close_range wrapper.
      if (::syscall(SYS_close_range, 3U, ~0U, 0U) < 0) {
        if (errno != ENOSYS) _exit(126);
        for (int fd : inherited) (void)close(fd);
      }
      ::execv(argv[0], argv.data());
      _exit(127);
    }
    (void)setpgid(pid_, pid_);
    try {
      SetControl(launcher / "cgroup.procs", std::to_string(pid_));
      WriteAll(release.get(), "1", 1);
    } catch (...) {
      (void)kill(pid_, SIGKILL);
      while (waitpid(pid_, nullptr, 0) < 0 && errno == EINTR) {}
      pid_ = -1;
      throw;
    }
  }
  Child(const Child&) = delete;
  Child& operator=(const Child&) = delete;
  ~Child() {
    if (pid_ > 0) {
      (void)kill(-pid_, SIGKILL);
      while (waitpid(pid_, nullptr, 0) < 0 && errno == EINTR) {}
    }
  }
  bool Poll(int& code) {
    int status = 0;
    const pid_t result = waitpid(pid_, &status, WNOHANG);
    if (!result || (result < 0 && errno == EINTR)) return false;
    Check(result < 0 ? -1 : 0, "reap sandbox runtime");
    code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    pid_ = -1;
    return true;
  }

 private:
  pid_t pid_ = -1;
};

void WatchdogReady(const Policy& policy);

int Run(const Policy& policy, const Spec& spec, uint32_t owner_uid = 0) {
  Validate(spec, policy.limits);
  if (policy.isolation == "gvisor")
    Require(spec.memory_mib >= 256, "gVisor minimum reservation is 256 MiB including runtime");
  const auto image = fs::path(policy.image_root) / spec.image / "rootfs";
  Image(image);
  Record record;
  record.owner_uid = owner_uid;
  record.request_hash = Digest(SpecIdentity(spec));
  record.id = spec.id;
  record.image = spec.image;
  record.cpu = spec.cpu_millicores;
  record.memory = spec.memory_mib;
  record.created = io::NowMs();
  record.deadline_mono_ms =
      static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::milliseconds>(io::SteadyClock::now().time_since_epoch()).count()) +
      spec.timeout_seconds * 1000;
  const auto job = fs::path(policy.state_root) / "jobs" / spec.id;
  FileDescriptor owned;
  {
    auto admission = Lock(fs::path(policy.state_root) / "admission.lock");
    WatchdogReady(policy);
    uint64_t memory = 0, cpu = 0;
    std::set<uint64_t> slots;
    const auto jobs = Jobs(policy);
    Require(jobs.size() < 128 && !fs::exists(job), "sandbox ID or history capacity unavailable");
    for (const auto& existing : jobs) {
      const auto r = Load(existing, policy);
      if (Terminal(r.state)) continue;
      memory += r.memory;
      cpu += r.cpu;
      slots.insert(r.slot);
    }
    Require(slots.size() < policy.limits.jobs && memory + record.memory <= policy.limits.memory_mib &&
                cpu + record.cpu <= policy.limits.cpu_millicores,
            "sandbox admission capacity exhausted");
    while (slots.contains(record.slot)) ++record.slot;
    Require(record.slot < policy.limits.jobs, "no reserved sandbox identity");
    MakeDirectory(job, 0700);
    owned = Lock(job / "owner.lock");
    Store(job, record);
  }
  const uint32_t uid_base = policy.uid_base + static_cast<uint32_t>(record.slot) * 65536;
  try {
    const auto group = Cgroup(policy, spec.id);
    if (mkdir(group.c_str(), 0700) < 0) Check(-1, "create sandbox resource envelope");
    SetControl(group / "memory.max", std::to_string(spec.memory_mib * 1024 * 1024));
    SetControl(group / "memory.swap.max", "0");
    SetControl(group / "memory.oom.group", "1");
    SetControl(group / "cpu.max", std::to_string(spec.cpu_millicores * 100) + " 100000");
    SetControl(group / "pids.max", std::to_string(spec.processes));
    SetControl(group / "cgroup.subtree_control", "+cpu +memory +pids");
    if (mkdir((group / "launcher").c_str(), 0700) < 0) Check(-1, "create runtime resource group");
    io::AtomicFile(job / "config.json",
                   OciConfig(spec, image.string(), policy.cgroup_parent + '/' + spec.id + "/payload", uid_base));
    int descriptors[2]{};
    Check(pipe(descriptors), "sandbox output pipe");
    FileDescriptor input(descriptors[0]), output(descriptors[1]);
    Check(fcntl(input.get(), F_SETFD, FD_CLOEXEC), "sandbox pipe close-on-exec");
    Check(fcntl(output.get(), F_SETFD, FD_CLOEXEC), "sandbox pipe close-on-exec");
    Check(fcntl(input.get(), F_SETFL, O_NONBLOCK), "sandbox pipe nonblocking");
    FileDescriptor log(
        Check(open((job / "output.log").c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600),
              "create bounded sandbox log"));
    auto command = RuntimeArgs(policy);
    command.insert(command.end(), {"run", "--bundle", job.string(), spec.id});
    const auto started = io::SteadyClock::now();
    Child child(command, output.get(), Cgroup(policy, spec.id) / "launcher");
    output.reset();
    record.state = "running";
    Store(job, record);
    std::cout << RecordJson(record) << '\n' << std::flush;
    auto saved = started;
    const auto drain = [&]() {
      bool exhausted = true;
      std::array<char, 8192> buffer{};
      for (size_t burst = 0; burst < 8; ++burst) {
        const ssize_t n = read(input.get(), buffer.data(), buffer.size());
        if (n < 0 && errno == EINTR) continue;
        if ((n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) || n == 0) {
          exhausted = false;
          break;
        }
        Check(n < 0 ? -1 : 0, "read sandbox output");
        const size_t take =
            std::min(static_cast<size_t>(n), static_cast<size_t>(spec.output_bytes - record.output_bytes));
        WriteAll(log.get(), buffer.data(), take);
        record.output_bytes += take;
        if (static_cast<size_t>(n) > take) {
          record.state = "output_limit";
          return false;
        }
      }
      return exhausted;
    };
    bool done = false;
    while (!done) {
      (void)drain();
      Sample(policy, record);
      if (record.state == "output_limit") break;
      if (cancelled || fs::exists(job / "cancel")) {
        record.state = "cancelled";
        break;
      }
      if (fs::exists(job / "expired") ||
          io::SteadyClock::now() - started >= std::chrono::seconds(spec.timeout_seconds)) {
        record.state = "timed_out";
        break;
      }
      if (child.Poll(record.exit_code)) {
        record.state = record.exit_code == 0 ? "succeeded" : "failed";
        done = true;
      }
      if (io::SteadyClock::now() - saved >= std::chrono::seconds(1)) {
        Store(job, record);
        saved = io::SteadyClock::now();
      }
      if (!done) {
        pollfd fd{input.get(), POLLIN, 0};
        (void)poll(&fd, 1, 20);
      }
    }
    const bool cleaned = Cleanup(policy, record);
    while (record.state != "output_limit" && drain()) {}
    Sample(policy, record);
    if (record.task_limit_hits) record.state = "task_limit";
    if (record.oom_kills) record.state = "oom_killed";
    if (!cleaned) record.state = "cleanup_failed";
    Check(fsync(log.get()), "sync bounded sandbox log");
    record.finished = io::NowMs();
    Store(job, record);
  } catch (...) {
    record.state = Cleanup(policy, record) ? "failed" : "cleanup_failed";
    record.finished = io::NowMs();
    Store(job, record);
    throw;
  }
  std::cout << RecordJson(record) << '\n';
  return record.state == "succeeded" ? 0 : 1;
}

void Recover(const Policy& policy, std::optional<std::string_view> selected = std::nullopt) {
  auto admission = Lock(fs::path(policy.state_root) / "admission.lock");
  for (const auto& job : Jobs(policy)) {
    if (selected && job.filename() != *selected) continue;
    auto record = Load(job, policy);
    if (Terminal(record.state)) continue;
    auto owner = Lock(job / "owner.lock", false);
    if (owner.get() < 0) continue;
    const bool cleaned = Cleanup(policy, record);
    Sample(policy, record);
    record.state = cleaned ? "interrupted" : "cleanup_failed";
    record.finished = io::NowMs();
    Store(job, record);
  }
}

uint64_t MonotonicMs() {
  const auto now =
      std::chrono::duration_cast<std::chrono::milliseconds>(io::SteadyClock::now().time_since_epoch()).count();
  Require(now > 0, "monotonic clock unavailable");
  return static_cast<uint64_t>(now);
}

void WatchdogReady(const Policy& policy) {
  auto absent = Lock(fs::path(policy.state_root) / "supervisor.lock", false);
  Require(absent.get() < 0 && !fs::exists(fs::path(policy.state_root) / "stopping"),
          "sandbox supervisor must be running");
  auto text = io::Read(fs::path(policy.state_root) / "heartbeat", 32);
  const auto stamp = io::Integer(text);
  const auto now = MonotonicMs();
  Require(stamp <= now && now - stamp < 2000, "sandbox supervisor heartbeat unavailable");
}

void Heartbeat(const fs::path& root) {
  const auto temporary = root / "heartbeat.next";
  FileDescriptor file(
      Check(open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600), "open heartbeat"));
  const auto stamp = std::to_string(MonotonicMs());
  WriteAll(file.get(), stamp.data(), stamp.size());
  Check(rename(temporary.c_str(), (root / "heartbeat").c_str()), "publish heartbeat");
}

void Supervise(const Policy& policy) {
  auto exclusive = Lock(fs::path(policy.state_root) / "supervisor.lock", false);
  Require(exclusive.get() >= 0, "sandbox supervisor already running");
  (void)signal(SIGINT, Interrupt);
  (void)signal(SIGTERM, Interrupt);
  Recover(policy);
  (void)unlink((fs::path(policy.state_root) / "stopping").c_str());
  std::cout << "{\"supervising\":true}\n" << std::flush;
  while (!cancelled) {
    Heartbeat(policy.state_root);
    {
      auto admission = Lock(fs::path(policy.state_root) / "admission.lock");
      for (const auto& job : Jobs(policy)) {
        const auto record = Load(job, policy);
        if (!Terminal(record.state) && record.deadline_mono_ms <= MonotonicMs()) {
          io::AtomicFile(job / "expired", "expired\n");
          if (fs::exists(Cgroup(policy, record.id))) SetControl(Cgroup(policy, record.id) / "cgroup.kill", "1");
        }
      }
    }
    Recover(policy);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
  {
    auto admission = Lock(fs::path(policy.state_root) / "admission.lock");
    io::AtomicFile(fs::path(policy.state_root) / "stopping", "shutdown\n");
    for (const auto& job : Jobs(policy)) {
      const auto record = Load(job, policy);
      if (!Terminal(record.state)) {
        io::AtomicFile(job / "cancel", "shutdown\n");
        (void)Cleanup(policy, record);
      }
    }
  }
  Recover(policy);
  (void)unlink((fs::path(policy.state_root) / "heartbeat").c_str());
}

namespace wire = codec::sandbox;
namespace channel = compat::sandbox;
struct BrokerReply {
  wire::ReplyCode code;
  std::string body;
};
BrokerReply BrokerError(wire::ReplyCode code) {
  const char* value = code == wire::ReplyCode::NotFound     ? "not_found"
                      : code == wire::ReplyCode::Conflict   ? "conflict"
                      : code == wire::ReplyCode::Denied     ? "denied"
                      : code == wire::ReplyCode::Busy       ? "busy"
                      : code == wire::ReplyCode::BadRequest ? "bad_request"
                                                            : "unavailable";
  return {code, "{\"error\":" + Quote(value) + "}"};
}

class BrokerSocket {
 public:
  BrokerSocket(const fs::path& path, uint32_t uid) : path_(path) {
    Require(path.string().starts_with("/run/fortis-sandbox/") && path.lexically_normal() == path,
            "broker socket must use protected runtime directory");
    TrustedPath(path.parent_path(), true);
    sockaddr_un address{};
    const auto text = path.string();
    Require(text.size() < sizeof(address.sun_path), "broker socket path too long");
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, text.data(), text.size());
    struct stat existing {};
    if (lstat(path.c_str(), &existing) == 0) {
      Require(S_ISSOCK(existing.st_mode) && existing.st_uid == uid && (existing.st_mode & 0777) == 0600,
              "unexpected broker socket object");
      FileDescriptor probe(
          Check(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0), "probe broker socket"));
      const int connected = connect(probe.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address));
      Require(connected < 0 && errno == ECONNREFUSED, "broker socket is already active");
      Check(unlink(path.c_str()), "remove stale broker socket");
    } else Require(errno == ENOENT, "cannot inspect broker socket");
    listener_.reset(Check(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0), "create broker socket"));
    Check(bind(listener_.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)), "bind broker socket");
    Check(lstat(path.c_str(), &identity_), "identify broker socket");
    bound_ = true;
    try {
      Check(chmod(path.c_str(), 0600), "protect broker socket");
      Check(chown(path.c_str(), uid, 0), "authorize node account");
      Check(listen(listener_.get(), 16), "listen for local control");
    } catch (...) {
      (void)unlink(path.c_str());
      bound_ = false;
      throw;
    }
  }
  BrokerSocket(const BrokerSocket&) = delete;
  BrokerSocket& operator=(const BrokerSocket&) = delete;
  ~BrokerSocket() {
    struct stat current {};
    if (bound_ && lstat(path_.c_str(), &current) == 0 && current.st_dev == identity_.st_dev &&
        current.st_ino == identity_.st_ino)
      (void)unlink(path_.c_str());
  }
  int get() const { return listener_.get(); }

 private:
  fs::path path_;
  FileDescriptor listener_;
  bool bound_ = false;
  struct stat identity_ {};
};

class BrokerWorkers {
 public:
  explicit BrokerWorkers(size_t limit) : limit_(limit) { children_.reserve(limit); }
  BrokerWorkers(const BrokerWorkers&) = delete;
  BrokerWorkers& operator=(const BrokerWorkers&) = delete;
  ~BrokerWorkers() {
    for (pid_t pid : children_) (void)kill(pid, SIGTERM);
    const auto end = io::SteadyClock::now() + std::chrono::seconds(15);
    while (!children_.empty() && io::SteadyClock::now() < end) {
      Reap();
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    for (pid_t pid : children_) (void)kill(pid, SIGKILL);
    // The independent supervisor reclaims orphaned cgroups if a manager is stuck.
    for (pid_t pid : children_) (void)waitpid(pid, nullptr, WNOHANG);
  }
  void Reap() noexcept {
    for (auto at = children_.begin(); at != children_.end();) {
      const pid_t result = waitpid(*at, nullptr, WNOHANG);
      if (result == *at || (result < 0 && errno == ECHILD)) at = children_.erase(at);
      else ++at;
    }
  }
  bool Full() const { return children_.size() >= limit_; }
  void Add(pid_t pid) { children_.push_back(pid); }

 private:
  std::vector<pid_t> children_;
  size_t limit_;
};

BrokerReply ExistingStart(const Policy& policy, const Spec& spec, uint32_t uid) {
  const auto record = Load(fs::path(policy.state_root) / "jobs" / spec.id, policy);
  if (record.owner_uid != uid) return BrokerError(wire::ReplyCode::Denied);
  if (record.request_hash != Digest(SpecIdentity(spec))) return BrokerError(wire::ReplyCode::Conflict);
  return {wire::ReplyCode::Ok, RecordJson(record)};
}

BrokerReply DispatchBroker(const Policy& policy, wire::Operation operation, std::string_view body, uint32_t uid,
                           BrokerWorkers& workers, int listener, int peer, int broker_lock) {
  const auto jobs = fs::path(policy.state_root) / "jobs";
  if (operation != wire::Operation::Start) {
    if (!Identifier(body)) return BrokerError(wire::ReplyCode::BadRequest);
    const auto job = jobs / std::string(body);
    if (!fs::exists(job)) return BrokerError(wire::ReplyCode::NotFound);
    auto record = Load(job, policy);
    if (record.owner_uid != uid) return BrokerError(wire::ReplyCode::NotFound);
    if (operation == wire::Operation::Stop && !Terminal(record.state)) {
      io::AtomicFile(job / "cancel", "local-control\n");
      Recover(policy, body);
      record = Load(job, policy);
    }
    return {wire::ReplyCode::Ok, RecordJson(record)};
  }
  Spec spec;
  try {
    spec = ParseSpec(body);
    Validate(spec, policy.limits);
  } catch (const std::exception&) { return BrokerError(wire::ReplyCode::BadRequest); }
  if (fs::exists(jobs / spec.id)) return ExistingStart(policy, spec, uid);
  WatchdogReady(policy);
  workers.Reap();
  if (workers.Full()) return BrokerError(wire::ReplyCode::Busy);
  Require(!cancelled, "broker is stopping");
  const pid_t pid = fork();
  Check(pid < 0 ? -1 : 0, "fork job manager");
  if (!pid) {
    (void)close(listener);
    (void)close(peer);
    (void)close(broker_lock);
    cancelled = 0;
    const int sink = open("/dev/null", O_WRONLY);
    if (sink < 0 || dup2(sink, STDOUT_FILENO) < 0 || dup2(sink, STDERR_FILENO) < 0) _exit(2);
    if (sink > STDERR_FILENO) (void)close(sink);
    int code = 2;
    try {
      code = Run(policy, spec, uid);
    } catch (...) { code = 2; }
    _exit(code);
  }
  workers.Add(pid);
  const auto end = io::SteadyClock::now() + std::chrono::seconds(3);
  while (!cancelled && io::SteadyClock::now() < end) {
    // Creation of the directory precedes the atomic durable record publication.
    if (fs::exists(jobs / spec.id / "record")) {
      auto reply = ExistingStart(policy, spec, uid);
      if (reply.code == wire::ReplyCode::Ok) reply.code = wire::ReplyCode::Accepted;
      return reply;
    }
    workers.Reap();
    if (kill(pid, 0) < 0 && errno == ESRCH) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  // A lost/late acknowledgement must be retried with the same id/spec.
  return BrokerError(wire::ReplyCode::Unavailable);
}

void Broker(const Policy& policy, const fs::path& path, uint32_t uid) {
  Require(uid > 0 && uid < 65534 && policy.isolation == "gvisor", "broker requires a dedicated host UID and gVisor");
  auto exclusive = Lock(fs::path(policy.state_root) / "broker.lock", false);
  Require(exclusive.get() >= 0, "broker already running");
  WatchdogReady(policy);
  BrokerSocket listener(path, uid);
  BrokerWorkers workers(static_cast<size_t>(policy.limits.jobs));
  (void)signal(SIGINT, Interrupt);
  (void)signal(SIGTERM, Interrupt);
  std::cout << "{\"brokerReady\":true}\n" << std::flush;
  while (!cancelled) {
    workers.Reap();
    pollfd poller{listener.get(), POLLIN, 0};
    const int ready = poll(&poller, 1, 100);
    if (ready < 0 && errno == EINTR) continue;
    Check(ready < 0 ? -1 : 0, "poll local broker");
    if (!ready) continue;
    FileDescriptor peer(accept4(listener.get(), nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK));
    if (peer.get() < 0 && (errno == EAGAIN || errno == EINTR)) continue;
    Check(peer.get(), "accept local broker peer");
    const auto deadline = io::SteadyClock::now() + std::chrono::seconds(2);
    BrokerReply reply = BrokerError(wire::ReplyCode::Unavailable);
    bool dispatching = false;
    try {
      if (channel::PeerUid(peer.get()) != uid) reply = BrokerError(wire::ReplyCode::Denied);
      else {
        wire::Header header{};
        channel::Receive(peer.get(), header.data(), header.size(), deadline);
        uint8_t code = 0;
        uint32_t length = 0;
        if (!wire::Decode(header, false, code, length)) reply = BrokerError(wire::ReplyCode::BadRequest);
        else {
          std::string body(length, '\0');
          channel::Receive(peer.get(), body.data(), body.size(), deadline);
          channel::EndOfMessage(peer.get(), deadline);
          dispatching = true;
          reply = DispatchBroker(policy, static_cast<wire::Operation>(code), body, uid, workers, listener.get(),
                                 peer.get(), exclusive.get());
        }
      }
    } catch (const std::exception&) {
      reply = BrokerError(dispatching ? wire::ReplyCode::Unavailable : wire::ReplyCode::BadRequest);
    }
    try {
      const auto write_end = io::SteadyClock::now() + std::chrono::seconds(1);
      Require(!reply.body.empty() && reply.body.size() <= wire::kReplyLimit, "invalid broker reply size");
      const auto header =
          wire::Encode(true, static_cast<uint8_t>(reply.code), static_cast<uint32_t>(reply.body.size()));
      channel::Transmit(peer.get(), header.data(), header.size(), write_end);
      channel::Transmit(peer.get(), reply.body.data(), reply.body.size(), write_end);
    } catch (const std::exception&) {
      // Abandon this connection; durable acceptance survives a lost reply.
      peer.reset();
    }
  }
  // Cancel this principal's jobs, including managers orphaned by an older broker.
  for (const auto& job : Jobs(policy)) {
    const auto record = Load(job, policy);
    if (record.owner_uid == uid && !Terminal(record.state)) io::AtomicFile(job / "cancel", "broker-shutdown\n");
  }
}

#endif

void StandardStreams() {
  // Never let private state/lock files occupy a closed standard descriptor.
  // Adopt /dev/null as process-owned stdio; other descriptors remain RAII-owned.
  for (int descriptor = 0; descriptor < 3; ++descriptor) {
    if (fcntl(descriptor, F_GETFD) >= 0) continue;
    Require(errno == EBADF, "cannot inspect standard stream");
    FileDescriptor stream(Check(open("/dev/null", O_RDWR | O_CLOEXEC), "open standard stream"));
    Check(dup2(stream.get(), descriptor), "initialize standard stream");
    Check(fcntl(descriptor, F_SETFD, 0), "retain standard stream");
    if (stream.get() == descriptor) (void)stream.release();
  }
}

int Main(int argc, char** argv) {
  StandardStreams();
  Require(argc >= 3,
          "usage: fortis-sandbox validate SPEC | plan POLICY SPEC | POLICY init|doctor|run|status|list|stop|recover "
          "[SPEC|ID]");
  if (std::string_view(argv[1]) == "validate") {
    Require(argc == 3, "validate requires one specification");
    const auto spec = ParseSpec(io::Read(argv[2], 16384));
    std::cout << "{\"valid\":true,\"schemaVersion\":1,\"id\":" << Quote(spec.id) << "}\n";
    return 0;
  }
  if (std::string_view(argv[1]) == "plan") {
    Require(argc == 4, "plan requires policy and specification");
    const auto policy = ParsePolicy(io::Read(argv[2], 16384));
    const auto spec = ParseSpec(io::Read(argv[3], 16384));
    Validate(spec, policy.limits);
    std::cout << OciConfig(spec, (fs::path(policy.image_root) / spec.image / "rootfs").string(),
                           policy.cgroup_parent + '/' + spec.id + "/payload", policy.uid_base)
              << '\n';
    return 0;
  }
#ifndef __linux__
  throw std::runtime_error("sandbox execution is available only on Linux");
#else
  Require(geteuid() == 0, "sandbox host operations require root");
  TrustedPath(argv[1], false);
  struct stat policy_permissions {};
  Check(stat(argv[1], &policy_permissions), "inspect sandbox policy permissions");
  Require((policy_permissions.st_mode & 0777) == 0600, "sandbox policy must be mode 0600");
  const auto policy = ParsePolicy(io::Read(argv[1], 16384));
  Require(policy.state_root.starts_with("/var/lib/fortis-sandboxes") ||
              policy.state_root.starts_with("/run/fortis-sandboxes"),
          "sandbox state must use the dedicated FortisNet prefix");
  Check(clearenv(), "clear sandbox manager environment");
  Check(setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1), "set trusted host path");
  Check(setenv("LANG", "C", 1), "set sandbox manager locale");
  umask(0077);
  (void)signal(SIGPIPE, SIG_IGN);
  const std::string_view operation(argv[2]);
  if (operation == "init") {
    Require(argc == 3, "init takes no job argument");
    MakeDirectory(policy.state_root, 0700);
    MakeDirectory(fs::path(policy.state_root) / "jobs", 0700);
    MakeDirectory(fs::path(policy.state_root) / "runtime", 0700);
    const auto parent = Cgroup(policy);
    TrustedPath(parent.parent_path(), true);
    if (mkdir(parent.c_str(), 0755) < 0 && errno != EEXIST) Check(-1, "create delegated cgroup");
    SetControl(parent / "cgroup.subtree_control", "+cpu +memory +pids");
  }
  Installation(policy);
  if (operation == "init" || operation == "doctor") {
    Require(argc == 3, "doctor takes no job argument");
    std::cout << "{\"ready\":true,\"platform\":\"linux\",\"cgroupVersion\":2,\"isolation\":" << Quote(policy.isolation)
              << ",\"runtimeSha256\":" << Quote(policy.runtime_sha256) << "}\n";
  } else if (operation == "run") {
    Require(argc == 4, "run requires one specification");
    (void)signal(SIGINT, Interrupt);
    (void)signal(SIGTERM, Interrupt);
    WatchdogReady(policy);
    Recover(policy);
    return Run(policy, ParseSpec(io::Read(argv[3], 16384)));
  } else if (operation == "broker") {
    Require(argc == 5, "broker requires socket path and authorized UID");
    Broker(policy, argv[3], static_cast<uint32_t>(io::Integer(argv[4], 65533)));
  } else if (operation == "supervise") {
    Require(argc == 3, "supervise takes no job argument");
    Supervise(policy);
  } else if (operation == "recover") {
    Require(argc == 3, "recover takes no job argument");
    Recover(policy);
  } else if (operation == "list") {
    Require(argc == 3, "list takes no job argument");
    auto admission = Lock(fs::path(policy.state_root) / "admission.lock");
    std::cout << '[';
    bool first = true;
    for (const auto& job : Jobs(policy)) {
      if (!first) std::cout << ',';
      first = false;
      std::cout << RecordJson(Load(job, policy));
    }
    std::cout << "]\n";
  } else if (operation == "status" || operation == "stop") {
    Require(argc == 4 && Identifier(argv[3]), "valid sandbox ID required");
    const auto job = fs::path(policy.state_root) / "jobs" / argv[3];
    auto record = Load(job, policy);
    if (operation == "stop" && !Terminal(record.state)) {
      io::AtomicFile(job / "cancel", "cancel\n");
      Recover(policy, argv[3]);
      record = Load(job, policy);
    }
    std::cout << RecordJson(record) << '\n';
  } else Require(false, "unknown sandbox operation");
  return 0;
#endif
}
}  // namespace
}  // namespace fortis::host::sandbox

int main(int argc, char** argv) {
  try {
    return fortis::host::sandbox::Main(argc, argv);
  } catch (const std::exception& error) {
    std::cerr << "sandbox operation refused: " << error.what() << '\n';
    return 2;
  }
}
