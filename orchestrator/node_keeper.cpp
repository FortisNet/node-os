#include "node_keeper.h"
#include "first_boot.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

namespace fortis::host::updates {
namespace {

constexpr uint64_t kLogBytes = 5 * 1024 * 1024;
constexpr unsigned kStopGraceSeconds = 180;
constexpr int kFirstInherited = 3;

std::string List(const std::vector<std::string>& values) {
  std::string out = "[";
  for (const auto& value : values) out += (out.size() > 1 ? "," : "") + Quote(value);
  return out + "]";
}

// Calls a process with no capabilities cannot use legitimately. They fail
// with EPERM instead of reaching kernel code the node never needs. This is a
// deny list on purpose: an allow list must first be traced on real x86_64.
constexpr const char* kDeniedCalls[] = {"acct",
                                        "add_key",
                                        "bpf",
                                        "chroot",
                                        "clock_adjtime",
                                        "clock_settime",
                                        "clone3",
                                        "create_module",
                                        "delete_module",
                                        "fanotify_init",
                                        "finit_module",
                                        "fsconfig",
                                        "fsmount",
                                        "fsopen",
                                        "fspick",
                                        "get_kernel_syms",
                                        "init_module",
                                        "io_uring_enter",
                                        "io_uring_register",
                                        "io_uring_setup",
                                        "ioperm",
                                        "iopl",
                                        "kcmp",
                                        "kexec_file_load",
                                        "kexec_load",
                                        "keyctl",
                                        "lookup_dcookie",
                                        "mbind",
                                        "migrate_pages",
                                        "mount",
                                        "mount_setattr",
                                        "move_mount",
                                        "move_pages",
                                        "name_to_handle_at",
                                        "nfsservctl",
                                        "open_by_handle_at",
                                        "open_tree",
                                        "perf_event_open",
                                        "personality",
                                        "pidfd_getfd",
                                        "pivot_root",
                                        "process_madvise",
                                        "process_vm_readv",
                                        "process_vm_writev",
                                        "ptrace",
                                        "query_module",
                                        "quotactl",
                                        "reboot",
                                        "request_key",
                                        "set_mempolicy",
                                        "setns",
                                        "settimeofday",
                                        "swapoff",
                                        "swapon",
                                        "sysfs",
                                        "syslog",
                                        "umount2",
                                        "unshare",
                                        "userfaultfd",
                                        "uselib",
                                        "ustat",
                                        "vhangup"};

std::string Seccomp() {
  std::string names;
  for (const char* name : kDeniedCalls) names += (names.empty() ? "" : ",") + Quote(name);
  // clone3 hides its flags behind a pointer, so it reports "not implemented"
  // and the C library falls back to clone, where CLONE_NEWUSER is refused.
  // The filter is for this host's own architecture; a call from any other
  // one (a 32-bit call on a 64-bit kernel) is killed by the kernel filter.
  return R"(,"seccomp":{"defaultAction":"SCMP_ACT_ALLOW","architectures":[")" + std::string(kSeccompArchitecture) +
         R"("],"syscalls":[)"
         R"({"names":[)" +
         names +
         R"(],"action":"SCMP_ACT_ERRNO","errnoRet":1},)"
         R"({"names":["clone3"],"action":"SCMP_ACT_ERRNO","errnoRet":38},)"
         R"({"names":["clone"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[)"
         R"({"index":0,"value":268435456,"valueTwo":268435456,"op":"SCMP_CMP_MASKED_EQ"}]}]})";
}

sockaddr_un ControlAddress(const fs::path& root) {
  const auto path = (root / "keeper.sock").string();
  sockaddr_un address{};
  Require(path.size() < sizeof(address.sun_path), "keeper socket path too long");
  address.sun_family = AF_UNIX;
  std::copy(path.begin(), path.end(), address.sun_path);
  return address;
}

void Timeouts(int descriptor, unsigned seconds) {
  const timeval limit{static_cast<time_t>(seconds), 0};
  Check(setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit)), "socket receive timeout");
  Check(setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit)), "socket send timeout");
}

bool SameUser(int descriptor) {
#ifdef __linux__
  ucred peer{};
  socklen_t size = sizeof(peer);
  return getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0 && peer.uid == geteuid();
#else
  uid_t user = 0;
  gid_t group = 0;
  return getpeereid(descriptor, &user, &group) == 0 && user == geteuid();
#endif
}

// One newline-terminated line of at most 1024 bytes, without the newline.
std::string ReadLine(int descriptor) {
  std::string line;
  for (char c = 0;;) {
    const ssize_t count = ::read(descriptor, &c, 1);
    if (count < 0 && errno == EINTR) continue;
    Require(count == 1 && line.size() < 1024, "keeper message truncated or unanswered");
    if (c == '\n') return line;
    line += c;
  }
}

class Keeper final {
 public:
  explicit Keeper(const KeeperPlan& plan) : plan_(plan) {}
  int Run();

 private:
  struct Child {
    std::string id;
    fs::path log;
    pid_t crun = -1;
    FileDescriptor pipe, file, listener;
    uint64_t pid = 0, started = 0, written = 0;
    int exit = 0;
    bool running = false;
  };
  const KeeperPlan& plan_;
  FileDescriptor control_;
  std::vector<NodeListener> bound_;
  std::vector<FileDescriptor> sockets_;
  Child node_, preflight_, page_;
  bool shutdown_ = false;

  std::vector<std::string> Crun(std::initializer_list<std::string> arguments) const {
    std::vector<std::string> command{"crun", "--root", plan_.runtime_state.string()};
    command.insert(command.end(), arguments);
    return command;
  }
  static FileDescriptor Bind(const std::string& address, unsigned port);
  void SyncListeners();
  void Pump(Child& child, bool drain);
  void Reap(Child& child);
  bool Step(int timeout_ms);
  void Launch(Child& child, const NodeContainer& container, const std::vector<std::pair<unsigned, int>>& listeners);
  void Stop(Child& child, unsigned grace_seconds);
  void Forget(const std::string& id) const;
  std::string State() const {
    return "running=" + std::to_string(node_.running ? 1 : 0) + " pid=" + std::to_string(node_.pid) +
           " started=" + std::to_string(node_.started) + " exit=" + std::to_string(node_.exit);
  }
  std::string Handle(const std::string& request);
  void Serve();
};

FileDescriptor Keeper::Bind(const std::string& address, unsigned port) {
  FileDescriptor server(Check(socket(AF_INET, SOCK_STREAM, 0), "listener socket"));
  Check(fcntl(server.get(), F_SETFD, FD_CLOEXEC), "listener close-on-exec");
  const int reuse = 1;
  Check(setsockopt(server.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)), "listener address reuse");
  sockaddr_in name{};
  name.sin_family = AF_INET;
  name.sin_port = htons(static_cast<uint16_t>(port));
  Require(port <= 65535 && inet_pton(AF_INET, address.c_str(), &name.sin_addr) == 1, "invalid listener address");
  Check(bind(server.get(), reinterpret_cast<const sockaddr*>(&name), sizeof(name)), "bind node listener");
  // The node applies its own backlog when it adopts the socket. Until then
  // connections wait here instead of being refused.
  Check(listen(server.get(), 128), "listen for node");
  return server;
}

void Keeper::SyncListeners() {
  auto wanted = plan_.listeners(plan_.config);
  if (wanted == bound_ && sockets_.size() == bound_.size()) return;
  sockets_.clear();
  bound_.clear();
  std::vector<FileDescriptor> sockets;
  sockets.reserve(wanted.size());
  for (const auto& listener : wanted) sockets.push_back(Bind(listener.address, listener.port));
  sockets_ = std::move(sockets);
  bound_ = std::move(wanted);
}

void Keeper::Pump(Child& child, bool drain) {
  if (child.pipe.get() < 0) return;
  std::array<char, 16384> buffer{};
  // Bounded per call, so a container that never stops writing cannot keep
  // the keeper from answering requests or reaping exits.
  for (unsigned round = 0; round < 64; ++round) {
    const ssize_t count = ::read(child.pipe.get(), buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) {
      if (count == 0 || (errno != EAGAIN && errno != EWOULDBLOCK) || drain) child.pipe.reset();
      return;
    }
    if (child.written + static_cast<uint64_t>(count) > kLogBytes) {
      // Keep one previous file: output is bounded at twice the limit.
      (void)::rename(child.log.c_str(), (child.log.string() + ".1").c_str());
      child.file.reset(
          ::open(child.log.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600));
      child.written = 0;
    }
    if (child.file.get() >= 0 && ::write(child.file.get(), buffer.data(), static_cast<size_t>(count)) == count)
      child.written += static_cast<uint64_t>(count);
  }
}

void Keeper::Reap(Child& child) {
  if (child.crun <= 0) return;
  int status = 0;
  const pid_t waited = waitpid(child.crun, &status, WNOHANG);
  if (waited != child.crun) return;
  child.exit = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
  child.crun = -1;
  child.running = false;
  child.pid = 0;
  Pump(child, true);
  child.file.reset();
}

// Waits up to `timeout_ms` for output, an exit or a control connection.
// Returns true when a control connection is waiting.
bool Keeper::Step(int timeout_ms) {
  pollfd descriptors[4] = {{control_.get(), POLLIN, 0},
                           {node_.pipe.get(), POLLIN, 0},
                           {preflight_.pipe.get(), POLLIN, 0},
                           {page_.pipe.get(), POLLIN, 0}};
  (void)poll(descriptors, 4, timeout_ms);
  for (Child* child : {&node_, &preflight_, &page_}) {
    Pump(*child, false);
    Reap(*child);
  }
  return (descriptors[0].revents & POLLIN) != 0;
}

void Keeper::Forget(const std::string& id) const {
  (void)Command(Crun({"delete", "--force", id}), 20);
  std::error_code ignored;
  fs::remove_all(plan_.root / "run" / id, ignored);
}

void Keeper::Launch(Child& child, const NodeContainer& container,
                    const std::vector<std::pair<unsigned, int>>& listeners) {
  Require(child.crun <= 0 && !child.running, "container already running");
  Require(listeners.size() <= 8, "too many inherited listeners");
  Forget(child.id);
  const auto bundle = plan_.root / "run" / child.id;
  Directory(bundle, 0700);
  // The root filesystem is only mount points: the release, data and host
  // files are bound over it, and the runtime mounts it read-only.
  const auto rootfs = bundle / "rootfs";
  Directory(rootfs, 0755);
  for (const auto& mount : container.mounts) {
    const fs::path destination = mount.destination;
    Require(destination.is_absolute() && destination.lexically_normal() == destination &&
                mount.destination.find("..") == std::string::npos,
            "mount escapes the runtime root");
    const bool file = mount.type == "bind" && fs::is_regular_file(mount.source);
    // The node's unprivileged user must be able to walk to every mount
    // point, whatever file mode mask the administrator's shell uses.
    auto target = rootfs;
    for (const auto& part : destination.relative_path()) {
      target /= part;
      if (file && target == rootfs / destination.relative_path()) break;
      if (!fs::exists(target)) Check(::mkdir(target.c_str(), 0755), "create mount point");
      Check(chmod(target.c_str(), 0755), "mount point permissions");
    }
    if (file && !fs::exists(target)) AtomicFile(target, "", 0444);
  }
  std::string map;
  for (size_t i = 0; i < listeners.size(); ++i)
    map += (i ? "," : "") + std::to_string(listeners[i].first) + "=" + std::to_string(kFirstInherited + i);
  AtomicFile(bundle / "config.json", NodeOciConfig(container, rootfs, child.id, "/fortis/" + child.id, map));
  Directory(plan_.root / "log", 0700);
  child.file.reset(Check(::open(child.log.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600),
                         "open container log"));
  struct stat info {};
  Check(fstat(child.file.get(), &info), "inspect container log");
  child.written = static_cast<uint64_t>(info.st_size);
  int ends[2]{};
  Check(pipe(ends), "container output pipe");
  FileDescriptor reader(ends[0]), writer(ends[1]);
  Check(fcntl(reader.get(), F_SETFD, FD_CLOEXEC), "output pipe close-on-exec");
  Check(fcntl(reader.get(), F_SETFL, O_NONBLOCK), "nonblocking container output");
  const auto pid_file = bundle / "pid";
  auto command = Crun({"run"});
  // In a container, Docker's system call filter forbids two things crun does
  // by default. One is making a session keyring for each container; none is
  // needed, the node's own filter forbids every keyring call and the helpers
  // use none. The other, on some servers, is pivot_root; crun then moves the
  // new root into place and changes root to it instead. What it starts has
  // no capability, cannot gain one and may not call chroot or mount, so it
  // cannot leave that root either way.
  if (HostKind() == "container") command.insert(command.end(), {"--no-new-keyring", "--no-pivot"});
  command.insert(command.end(), {"--bundle", bundle.string(), "--pid-file", pid_file.string(), "--preserve-fds",
                                 std::to_string(listeners.size()), child.id});
  std::vector<char*> argv;
  argv.reserve(command.size() + 1);
  for (auto& value : command) argv.push_back(value.data());
  argv.push_back(nullptr);
  const pid_t started = fork();
  Check(started < 0 ? -1 : 0, "fork container runtime");
  if (!started) {
    // Only async-signal-safe calls from here to exec.
    (void)setpgid(0, 0);
    (void)signal(SIGTERM, SIG_DFL);
    (void)signal(SIGINT, SIG_DFL);
    (void)signal(SIGHUP, SIG_DFL);
    int staged[8];
    // Move every listener clear of the target range before placing it, so a
    // source descriptor is never overwritten by an earlier placement.
    for (size_t i = 0; i < listeners.size(); ++i) {
      staged[i] = fcntl(listeners[i].second, F_DUPFD, 64);
      if (staged[i] < 0) _exit(126);
    }
    for (size_t i = 0; i < listeners.size(); ++i)
      if (dup2(staged[i], kFirstInherited + static_cast<int>(i)) < 0) _exit(126);
    const int null = ::open("/dev/null", O_RDONLY);
    if (null < 0 || dup2(null, STDIN_FILENO) < 0 || dup2(writer.get(), STDOUT_FILENO) < 0 ||
        dup2(writer.get(), STDERR_FILENO) < 0)
      _exit(126);
    for (int descriptor = kFirstInherited + static_cast<int>(listeners.size()); descriptor < 256; ++descriptor)
      (void)close(descriptor);
    ::execvp(argv.front(), argv.data());
    _exit(127);
  }
  writer.reset();
  child.crun = started;
  child.pipe = std::move(reader);
  child.exit = 0;
  child.pid = 0;
  const auto deadline = SteadyClock::now() + std::chrono::seconds(20);
  while (child.crun > 0 && SteadyClock::now() < deadline) {
    (void)Step(50);
    std::error_code ignored;
    if (child.crun > 0 && fs::is_regular_file(pid_file, ignored)) {
      const auto text = Read(pid_file, 32);
      if (text.empty()) continue;  // The runtime is still writing it.
      child.pid = Integer(text.substr(0, text.find('\n')), INT32_MAX);
      child.started = NowMs();
      child.running = true;
      return;
    }
  }
  if (child.crun > 0) Stop(child, 0);
  throw std::runtime_error("container runtime did not start the process");
}

void Keeper::Stop(Child& child, unsigned grace_seconds) {
  if (child.crun <= 0) return;
  const auto wait = [&](unsigned seconds) {
    const auto deadline = SteadyClock::now() + std::chrono::seconds(seconds);
    while (child.crun > 0 && SteadyClock::now() < deadline) (void)Step(50);
  };
  if (grace_seconds) {
    (void)Command(Crun({"kill", child.id, "SIGTERM"}), 20);
    wait(grace_seconds);
  }
  if (child.crun > 0) {
    (void)Command(Crun({"kill", child.id, "SIGKILL"}), 20);
    wait(10);
  }
  if (child.crun > 0) {
    // The runtime itself is stuck: remove its whole process group.
    (void)kill(-child.crun, SIGKILL);
    wait(10);
    Require(child.crun <= 0, "container runtime cannot be stopped");
    child.exit = 137;
  }
  Forget(child.id);
}

std::string Keeper::Handle(const std::string& request) {
  std::istringstream words(request);
  std::string verb, first, second, extra;
  words >> verb >> first >> second >> extra;
  Require(extra.empty(), "unexpected keeper arguments");
  if (verb == "ping" || verb == "state") return State();
  if (verb == "shutdown") {
    shutdown_ = true;
    return State();
  }
  if (verb == "start") {
    Require(!node_.running, "node already running");
    // The page server only stands in while no node serves; it would
    // otherwise compete with the node for the same connections.
    Stop(page_, 2);
    SyncListeners();
    std::vector<std::pair<unsigned, int>> listeners;
    for (size_t i = 0; i < bound_.size(); ++i) listeners.emplace_back(bound_[i].inside, sockets_[i].get());
    Launch(node_, plan_.node(plan_.config), listeners);
    return State();
  }
  if (verb == "stop") {
    Stop(node_, std::min<unsigned>(static_cast<unsigned>(Integer(first, 600)), kStopGraceSeconds));
    return State();
  }
  if (verb == "reload") {
    // The node re-reads its certificates on this signal and keeps serving.
    Require(node_.running, "no node is running");
    Require(Command(Crun({"kill", node_.id, "SIGHUP"}), 20).exit == 0, "node could not be signalled");
    return State();
  }
  if (verb == "page-start") {
    // Answers certificate challenges on the public HTTP port while no node
    // serves, as an unprivileged container holding only that one socket.
    Require(!node_.running, "the node is serving");
    if (page_.running) return State();
    SyncListeners();
    std::vector<std::pair<unsigned, int>> listeners;
    for (size_t i = 0; i < bound_.size(); ++i)
      if (bound_[i].inside == 8082) listeners.emplace_back(8082U, sockets_[i].get());
    Require(listeners.size() == 1 && plan_.page, "no public HTTP port is configured");
    Launch(page_, plan_.page(plan_.config), listeners);
    return State();
  }
  if (verb == "page-stop") {
    Stop(page_, 2);
    return State();
  }
  if (verb == "preflight") {
    // `second` is a release name below app/releases; nothing else can be run.
    Require(Integer(first) > 0 && Token(second), "invalid preflight request");
    Require(preflight_.crun <= 0, "another preflight is active");
    preflight_.id = plan_.name + "-preflight-" + first;
    preflight_.log = plan_.root / "log" / "preflight.log";
    // Loopback and ephemeral: reachable only from this host, with no port to
    // reserve and none left behind.
    preflight_.listener = Bind("127.0.0.1", 0);
    sockaddr_in name{};
    socklen_t size = sizeof(name);
    Check(getsockname(preflight_.listener.get(), reinterpret_cast<sockaddr*>(&name), &size), "preflight address");
    try {
      Launch(preflight_, plan_.preflight(plan_.config, plan_.root / "app/releases" / second),
             {{8080U, preflight_.listener.get()}});
    } catch (...) {
      preflight_.listener.reset();
      throw;
    }
    return "port=" + std::to_string(ntohs(name.sin_port));
  }
  if (verb == "preflight-stop") {
    Require(Integer(first) > 0, "invalid preflight request");
    if (preflight_.id == plan_.name + "-preflight-" + first) {
      Stop(preflight_, 2);
      preflight_.listener.reset();
    }
    return State();
  }
  throw std::runtime_error("unknown keeper request");
}

void Keeper::Serve() {
  FileDescriptor client(accept(control_.get(), nullptr, nullptr));
  if (client.get() < 0) return;
  std::string reply;
  try {
    Check(fcntl(client.get(), F_SETFD, FD_CLOEXEC), "control close-on-exec");
    Timeouts(client.get(), 2);
    Require(SameUser(client.get()), "keeper serves its own user only");
    reply = "ok " + Handle(ReadLine(client.get()));
  } catch (const std::exception& failure) { reply = std::string("error ") + failure.what(); }
  reply += '\n';
  try {
    WriteAll(client.get(), reply.data(), reply.size());
  } catch (const std::exception&) {
    return;  // The requester left; the state is still correct.
  }
}

int Keeper::Run() {
  Directory(plan_.root / "run", 0700);
  Directory(plan_.root / "log", 0700);
  FileDescriptor lock(Check(
      ::open((plan_.root / "keeper.lock").c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600), "keeper lock"));
  if (flock(lock.get(), LOCK_EX | LOCK_NB) != 0) return 0;  // Another keeper already serves this root.
  fs::create_directories(plan_.runtime_state);
  // A previous keeper may have died with containers still alive and still
  // holding the ports. They are unobserved now, so they are removed.
  std::vector<std::string> stale;
  for (const auto& entry : fs::directory_iterator(plan_.root / "run"))
    if (Token(entry.path().filename().string(), 128)) stale.push_back(entry.path().filename().string());
  for (const auto& id : stale) Forget(id);
  node_.id = plan_.name;
  node_.log = plan_.root / "log" / "node.log";
  page_.id = plan_.name + "-page";
  page_.log = plan_.root / "log" / "page.log";
  const auto address = ControlAddress(plan_.root);
  (void)::unlink(address.sun_path);
  control_.reset(Check(socket(AF_UNIX, SOCK_STREAM, 0), "keeper socket"));
  Check(fcntl(control_.get(), F_SETFD, FD_CLOEXEC), "keeper socket close-on-exec");
  const mode_t previous = umask(0177);
  const int bound = bind(control_.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address));
  (void)umask(previous);
  Check(bound, "bind keeper socket");
  Check(listen(control_.get(), 8), "listen on keeper socket");
  SyncListeners();
  while (!shutdown_ && !interrupted)
    if (Step(200)) Serve();
  interrupted = 0;  // Finish the orderly stop even though a signal asked for it.
  Stop(preflight_, 0);
  Stop(page_, 0);
  Stop(node_, kStopGraceSeconds);
  (void)::unlink(address.sun_path);
  return 0;
}

}  // namespace

std::string NodeOciConfig(const NodeContainer& container, const fs::path& rootfs, std::string_view hostname,
                          std::string_view cgroup, std::string_view listen_fds) {
  Require(!container.args.empty() && container.memory_bytes && container.tasks, "incomplete container");
  auto env = container.env;
  if (!listen_fds.empty()) env.push_back("FORTIS_LISTEN_FDS=" + std::string(listen_fds));
  std::string mounts;
  for (const auto& mount : container.mounts)
    mounts += std::string(mounts.empty() ? "" : ",") + R"({"destination":)" + Quote(mount.destination) + R"(,"type":)" +
              Quote(mount.type) + R"(,"source":)" + Quote(mount.source) + R"(,"options":)" + List(mount.options) + "}";
  std::string out = R"({"ociVersion":"1.0.2","process":{"terminal":false,"user":{"uid":)" +
                    std::to_string(container.user) + R"(,"gid":)" + std::to_string(container.user) + R"(},"args":)";
  out += List(container.args) + R"(,"env":)" + List(env);
  out += R"(,"cwd":"/","capabilities":{"bounding":[],"effective":[],"inheritable":[],"permitted":[],"ambient":[]})"
         R"(,"noNewPrivileges":true,"rlimits":[{"type":"RLIMIT_CORE","hard":0,"soft":0},)"
         R"({"type":"RLIMIT_NOFILE","hard":65536,"soft":65536}]},"root":{"path":)";
  out += Quote(rootfs.string()) + R"(,"readonly":true},"hostname":)" + Quote(hostname) + R"(,"mounts":[)" + mounts;
  out += R"(],"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"ipc"},{"type":"uts"},{"type":"cgroup"})";
  if (!container.host_network) out += R"(,{"type":"network"})";
  out += R"(],"cgroupsPath":)" + Quote(cgroup) + R"(,"resources":{"memory":{"limit":)" +
         std::to_string(container.memory_bytes) + R"(},"pids":{"limit":)" + std::to_string(container.tasks) + "}}";
  out += R"(,"maskedPaths":["/proc/acpi","/proc/asound","/proc/kcore","/proc/keys","/proc/latency_stats",)"
         R"("/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/sys/firmware"])"
         R"(,"readonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"])";
  if (container.seccomp) out += Seccomp();
  return out + "}}";
}

int RunKeeper(const KeeperPlan& plan) { return Keeper(plan).Run(); }

std::string KeeperRequest(const fs::path& root, std::string_view request, unsigned timeout_seconds) {
  const auto address = ControlAddress(root);
  FileDescriptor client(Check(socket(AF_UNIX, SOCK_STREAM, 0), "keeper client socket"));
  Check(fcntl(client.get(), F_SETFD, FD_CLOEXEC), "keeper client close-on-exec");
  Timeouts(client.get(), timeout_seconds);
  Require(connect(client.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0,
          "node keeper is not running");
  const auto line = std::string(request) + "\n";
  WriteAll(client.get(), line.data(), line.size());
  const auto reply = ReadLine(client.get());
  if (reply == "ok") return {};
  if (reply.starts_with("ok ")) return reply.substr(3);
  throw std::runtime_error("node keeper refused: " + (reply.starts_with("error ") ? reply.substr(6) : reply));
}

bool KeeperPresent(const fs::path& root) {
  try {
    (void)KeeperRequest(root, "ping", 2);
    return true;
  } catch (const std::exception&) { return false; }
}

uint64_t KeeperField(std::string_view reply, std::string_view key) {
  const auto name = std::string(key) + "=";
  size_t at = 0;
  while (at < reply.size()) {
    const auto end = std::min(reply.find(' ', at), reply.size());
    const auto word = reply.substr(at, end - at);
    if (word.starts_with(name)) return Integer(word.substr(name.size()));
    at = end + 1;
  }
  throw std::runtime_error("node keeper reply incomplete");
}

}  // namespace fortis::host::updates
