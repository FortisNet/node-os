#include "sandbox_spec.h"

#include "bounded_json.h"
#include "utf8.h"
#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <set>
#include <stdexcept>

namespace fortis::host::sandbox {
namespace {
void Require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

Limits AbsoluteLimits() { return {32, 64000, 65536, 1024, 86400, 4096, 16 * 1024 * 1024}; }

class Reader {
 public:
  explicit Reader(std::string_view input) : input_(input) {
    codec::BoundedJsonError error{};
    Require(!input.empty() && input.size() <= 16384 &&
                document_.Parse(reinterpret_cast<const unsigned char*>(input.data()), input.size(), tokens_.data(),
                                tokens_.size(), &error),
            "invalid bounded sandbox request");
  }
  Reader(const Reader&) = delete;
  Reader& operator=(const Reader&) = delete;
  std::string String(uint32_t token) const {
    std::array<char, 4097> bytes{};
    size_t length = 0;
    Require(document_.DecodeString(token, bytes.data(), bytes.size(), &length), "invalid sandbox string");
    Require(std::find(bytes.begin(), bytes.begin() + static_cast<ptrdiff_t>(length), '\0') ==
                bytes.begin() + static_cast<ptrdiff_t>(length),
            "NUL in sandbox string");
    return {bytes.data(), length};
  }
  uint64_t Number(uint32_t index) const {
    const auto* token = document_.token(index);
    Require(token && token->type == codec::BoundedJsonType::kNumber, "expected sandbox integer");
    const auto text = input_.substr(token->start, token->length);
    uint64_t number = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), number);
    Require(parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size(), "invalid sandbox integer");
    return number;
  }
  const codec::BoundedJsonDocument& Get() const& { return document_; }
  const codec::BoundedJsonDocument& Get() const&& = delete;

 private:
  std::string_view input_;
  std::array<codec::BoundedJsonToken, 1024> tokens_{};
  codec::BoundedJsonDocument document_;
};

std::string Strings(const std::vector<std::string>& values) {
  std::string out = "[";
  for (size_t i = 0; i < values.size(); ++i) {
    if (i) out += ',';
    out += Quote(values[i]);
  }
  return out + ']';
}
}  // namespace

bool Identifier(std::string_view value) {
  return !value.empty() && value.size() <= 48 && value.front() >= 'a' && value.front() <= 'z' &&
         std::all_of(value.begin(), value.end(),
                     [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'; });
}

std::string Quote(std::string_view value) {
  Require(codec::utf8::Valid(reinterpret_cast<const uint8_t*>(value.data()), value.size()),
          "invalid UTF-8 in sandbox string");
  std::string out = "\"";
  for (const unsigned char c : value) {
    Require(c != 0, "NUL in JSON string");
    if (c == '"' || c == '\\') {
      out += '\\';
      out += static_cast<char>(c);
    } else if (c < 32 || c >= 127) {
      // Input requests are validated UTF-8 by the bounded JSON reader. Preserve
      // non-ASCII bytes; escaping them separately would change their encoding.
      if (c >= 127) out += static_cast<char>(c);
      else {
        out += "\\u00";
        out += "0123456789abcdef"[c >> 4];
        out += "0123456789abcdef"[c & 15];
      }
    } else out += static_cast<char>(c);
  }
  return out + '"';
}

Spec ParseSpec(std::string_view json) {
  const Reader reader(json);
  const auto& doc = reader.Get();
  const auto* root = doc.token(doc.root());
  Require(root && root->type == codec::BoundedJsonType::kObject, "sandbox request must be an object");
  std::set<std::string> seen;
  Spec spec;
  bool version = false;
  for (uint32_t key = root->first_child; key != codec::kBoundedJsonNoToken;) {
    const auto* name = doc.token(key);
    Require(name != nullptr, "invalid sandbox field");
    const uint32_t index = name->next_sibling;
    const auto* value = doc.token(index);
    Require(value != nullptr, "invalid sandbox value");
    const auto field = reader.String(key);
    Require(seen.insert(field).second, "duplicate sandbox field");
    if (field == "schemaVersion") {
      Require(reader.Number(index) == 1, "unsupported sandbox schema");
      version = true;
    } else if (field == "id") spec.id = reader.String(index);
    else if (field == "image") spec.image = reader.String(index);
    else if (field == "args") {
      Require(value->type == codec::BoundedJsonType::kArray, "sandbox args must be an array");
      for (uint32_t arg = value->first_child; arg != codec::kBoundedJsonNoToken;) {
        Require(spec.args.size() < 64, "too many sandbox arguments");
        spec.args.push_back(reader.String(arg));
        const auto* item = doc.token(arg);
        Require(item != nullptr, "invalid sandbox argument");
        arg = item->next_sibling;
      }
    } else if (field == "cpuLimitMillicores") spec.cpu_millicores = reader.Number(index);
    else if (field == "memoryLimitMiB") spec.memory_mib = reader.Number(index);
    else if (field == "maxProcesses") spec.processes = reader.Number(index);
    else if (field == "timeoutSeconds") spec.timeout_seconds = reader.Number(index);
    else if (field == "scratchLimitMiB") spec.scratch_mib = reader.Number(index);
    else if (field == "outputLimitBytes") spec.output_bytes = reader.Number(index);
    else Require(false, "unknown sandbox field");
    key = value->next_sibling;
  }
  Require(version, "sandbox schema version required");
  Validate(spec, AbsoluteLimits());
  return spec;
}

Policy ParsePolicy(std::string_view json) {
  const Reader reader(json);
  const auto& doc = reader.Get();
  const auto* root = doc.token(doc.root());
  Require(root && root->type == codec::BoundedJsonType::kObject, "sandbox policy must be an object");
  Policy policy;
  std::set<std::string> seen;
  bool version = false;
  for (uint32_t key = root->first_child; key != codec::kBoundedJsonNoToken;) {
    const auto* name = doc.token(key);
    Require(name != nullptr, "invalid policy field");
    const uint32_t index = name->next_sibling;
    const auto* value = doc.token(index);
    Require(value != nullptr, "invalid policy value");
    const auto field = reader.String(key);
    Require(seen.insert(field).second, "duplicate policy field");
    if (field == "schemaVersion") {
      Require(reader.Number(index) == 1, "unsupported sandbox policy");
      version = true;
    } else if (field == "stateRoot") policy.state_root = reader.String(index);
    else if (field == "imageRoot") policy.image_root = reader.String(index);
    else if (field == "runtime") policy.runtime = reader.String(index);
    else if (field == "runtimeSha256") policy.runtime_sha256 = reader.String(index);
    else if (field == "isolation") policy.isolation = reader.String(index);
    else if (field == "cgroupParent") policy.cgroup_parent = reader.String(index);
    else if (field == "uidBase") {
      const auto number = reader.Number(index);
      Require(number >= 65536 && number <= UINT32_MAX - 32 * 65536ULL, "invalid sandbox UID allocation");
      policy.uid_base = static_cast<uint32_t>(number);
    } else if (field == "maxJobs") policy.limits.jobs = reader.Number(index);
    else if (field == "cpuBudgetMillicores") policy.limits.cpu_millicores = reader.Number(index);
    else if (field == "memoryBudgetMiB") policy.limits.memory_mib = reader.Number(index);
    else if (field == "maxProcesses") policy.limits.processes = reader.Number(index);
    else if (field == "maxTimeoutSeconds") policy.limits.timeout_seconds = reader.Number(index);
    else if (field == "maxScratchMiB") policy.limits.scratch_mib = reader.Number(index);
    else if (field == "maxOutputBytes") policy.limits.output_bytes = reader.Number(index);
    else Require(false, "unknown sandbox policy field");
    key = value->next_sibling;
  }
  Require(version && policy.runtime_sha256.size() == 64 &&
              std::all_of(policy.runtime_sha256.begin(), policy.runtime_sha256.end(),
                          [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }),
          "sandbox runtime SHA-256 required");
  Require(policy.isolation == "gvisor" || policy.isolation == "process", "unsupported sandbox isolation");
  for (const auto* path : {&policy.state_root, &policy.image_root, &policy.runtime, &policy.cgroup_parent}) {
    Require(path->size() > 1 && path->size() <= 512 && path->front() == '/' && path->back() != '/' &&
                path->find("//") == std::string::npos && path->find("/../") == std::string::npos &&
                path->find("/./") == std::string::npos && !path->ends_with("/..") && !path->ends_with("/."),
            "invalid absolute policy path");
    Require(std::all_of(path->begin(), path->end(), [](unsigned char c) { return c > 32 && c < 127; }),
            "invalid policy path bytes");
  }
  Require(policy.cgroup_parent.starts_with("/fortis-sandboxes"), "sandbox cgroup prefix required");
  Spec minimum;
  minimum.id = "policy-check";
  minimum.image = "policy-check";
  minimum.args = {"/check"};
  minimum.cpu_millicores = 10;
  minimum.memory_mib = 64;
  minimum.processes = 1;
  minimum.timeout_seconds = 1;
  minimum.scratch_mib = 1;
  minimum.output_bytes = 1024;
  Validate(minimum, policy.limits);
  return policy;
}

std::string SpecIdentity(const Spec& spec) {
  Validate(spec, AbsoluteLimits());
  return "{\"schemaVersion\":1,\"id\":" + Quote(spec.id) + ",\"image\":" + Quote(spec.image) +
         ",\"args\":" + Strings(spec.args) + ",\"cpuLimitMillicores\":" + std::to_string(spec.cpu_millicores) +
         ",\"memoryLimitMiB\":" + std::to_string(spec.memory_mib) +
         ",\"maxProcesses\":" + std::to_string(spec.processes) +
         ",\"timeoutSeconds\":" + std::to_string(spec.timeout_seconds) +
         ",\"scratchLimitMiB\":" + std::to_string(spec.scratch_mib) +
         ",\"outputLimitBytes\":" + std::to_string(spec.output_bytes) + "}";
}

std::string PolicyIdentity(const Policy& p) {
  return "{\"schemaVersion\":1,\"stateRoot\":" + Quote(p.state_root) + ",\"imageRoot\":" + Quote(p.image_root) +
         ",\"runtime\":" + Quote(p.runtime) + ",\"runtimeSha256\":" + Quote(p.runtime_sha256) +
         ",\"isolation\":" + Quote(p.isolation) + ",\"cgroupParent\":" + Quote(p.cgroup_parent) +
         ",\"uidBase\":" + std::to_string(p.uid_base) + ",\"maxJobs\":" + std::to_string(p.limits.jobs) +
         ",\"cpuBudgetMillicores\":" + std::to_string(p.limits.cpu_millicores) +
         ",\"memoryBudgetMiB\":" + std::to_string(p.limits.memory_mib) +
         ",\"maxProcesses\":" + std::to_string(p.limits.processes) +
         ",\"maxTimeoutSeconds\":" + std::to_string(p.limits.timeout_seconds) +
         ",\"maxScratchMiB\":" + std::to_string(p.limits.scratch_mib) +
         ",\"maxOutputBytes\":" + std::to_string(p.limits.output_bytes) + "}";
}

void Validate(const Spec& spec, const Limits& limits) {
  Require(Identifier(spec.id) && Identifier(spec.image), "invalid sandbox or image identifier");
  Require(!spec.args.empty() && spec.args.size() <= 64 && !spec.args[0].empty() && spec.args[0][0] == '/',
          "sandbox command must be absolute");
  size_t bytes = 0;
  for (const auto& arg : spec.args) {
    Require(arg.size() <= 4096 && arg.find('\0') == std::string::npos, "invalid sandbox argument");
    Require(arg.size() <= 8192 - bytes, "sandbox arguments too large");
    bytes += arg.size();
  }
  Require(limits.jobs > 0 && limits.jobs <= 32 && limits.cpu_millicores > 0 && limits.cpu_millicores <= 64000 &&
              limits.memory_mib >= 64 && limits.memory_mib <= 65536 && limits.processes > 0 &&
              limits.processes <= 1024 && limits.timeout_seconds > 0 && limits.timeout_seconds <= 86400 &&
              limits.scratch_mib > 0 && limits.scratch_mib <= 4096 && limits.output_bytes >= 1024 &&
              limits.output_bytes <= 16 * 1024 * 1024,
          "invalid sandbox host ceilings");
  Require(spec.cpu_millicores >= 10 && spec.cpu_millicores <= limits.cpu_millicores && spec.memory_mib >= 64 &&
              spec.memory_mib <= limits.memory_mib && spec.processes >= 1 && spec.processes <= limits.processes &&
              spec.timeout_seconds >= 1 && spec.timeout_seconds <= limits.timeout_seconds && spec.scratch_mib >= 1 &&
              spec.scratch_mib <= limits.scratch_mib && spec.scratch_mib <= spec.memory_mib &&
              spec.output_bytes >= 1024 && spec.output_bytes <= limits.output_bytes,
          "sandbox request exceeds host ceilings");
}

std::string OciConfig(const Spec& spec, std::string_view rootfs, std::string_view cgroup, uint32_t uid_base) {
  Validate(spec, AbsoluteLimits());
  Require(!rootfs.empty() && rootfs.front() == '/' && !cgroup.empty() && cgroup.front() == '/' && cgroup != "/" &&
              uid_base >= 65536 && uid_base <= std::numeric_limits<uint32_t>::max() - 65536,
          "invalid host sandbox placement");
  const auto memory = std::to_string(spec.memory_mib * 1024 * 1024);
  std::string out =
      "{\"ociVersion\":\"1.0.2\",\"hostname\":\"fortis-sandbox\",\"root\":{\"path\":" + Quote(rootfs) +
      ",\"readonly\":true},\"process\":{\"terminal\":false,\"user\":{\"uid\":1000,\"gid\":1000},\"args\":" +
      Strings(spec.args) +
      ",\"env\":[\"PATH=/usr/bin:/bin\",\"HOME=/tmp\",\"LANG=C\"],\"cwd\":\"/tmp\",\"noNewPrivileges\":true,"
      "\"capabilities\":{\"bounding\":[],\"effective\":[],\"inheritable\":[],\"permitted\":[],\"ambient\":[]},"
      "\"rlimits\":[{\"type\":\"RLIMIT_NOFILE\",\"hard\":256,\"soft\":256},{\"type\":\"RLIMIT_CORE\",\"hard\":0,"
      "\"soft\":0},"
      "{\"type\":\"RLIMIT_NPROC\",\"hard\":" +
      std::to_string(spec.processes) + ",\"soft\":" + std::to_string(spec.processes) +
      "}]},"
      "\"mounts\":[{\"destination\":\"/"
      "proc\",\"type\":\"proc\",\"source\":\"proc\",\"options\":[\"nosuid\",\"noexec\",\"nodev\"]},"
      "{\"destination\":\"/"
      "tmp\",\"type\":\"tmpfs\",\"source\":\"tmpfs\",\"options\":[\"nosuid\",\"nodev\",\"mode=1777\",\"size=" +
      std::to_string(spec.scratch_mib * 1024 * 1024) +
      "\"]},"
      "{\"destination\":\"/"
      "dev\",\"type\":\"tmpfs\",\"source\":\"tmpfs\",\"options\":[\"nosuid\",\"noexec\",\"mode=755\",\"size=1048576\"]}"
      "],"
      "\"linux\":{\"rootfsPropagation\":\"private\",\"cgroupsPath\":" +
      Quote(cgroup) + ",\"uidMappings\":[{\"containerID\":0,\"hostID\":" + std::to_string(uid_base) +
      ",\"size\":65536}],"
      "\"gidMappings\":[{\"containerID\":0,\"hostID\":" +
      std::to_string(uid_base) +
      ",\"size\":65536}],"
      "\"namespaces\":[{\"type\":\"pid\"},{\"type\":\"mount\"},{\"type\":\"network\"},{\"type\":\"ipc\"},{\"type\":"
      "\"uts\"},"
      "{\"type\":\"user\"},{\"type\":\"cgroup\"}],\"resources\":{\"memory\":{\"limit\":" +
      memory + ",\"swap\":" + memory +
      "},\"cpu\":{\"period\":100000,\"quota\":" + std::to_string(spec.cpu_millicores * 100) +
      "},\"pids\":{\"limit\":" + std::to_string(spec.processes) + "},\"devices\":[{\"allow\":false,\"access\":\"rwm\"}";
  constexpr std::array<unsigned, 5> minors{3, 5, 7, 8, 9};
  for (unsigned minor : minors)
    out += ",{\"allow\":true,\"type\":\"c\",\"major\":1,\"minor\":" + std::to_string(minor) + ",\"access\":\"rwm\"}";
  out += "]},\"devices\":[";
  constexpr std::array<const char*, 5> devices{"null", "zero", "full", "random", "urandom"};
  for (size_t i = 0; i < devices.size(); ++i) {
    if (i) out += ',';
    out += "{\"path\":\"/dev/" + std::string(devices[i]) +
           "\",\"type\":\"c\",\"major\":1,\"minor\":" + std::to_string(minors[i]) +
           ",\"fileMode\":438,\"uid\":0,\"gid\":0}";
  }
  out +=
      "],\"maskedPaths\":[\"/proc/kcore\",\"/proc/keys\",\"/proc/timer_list\",\"/proc/sched_debug\",\"/proc/scsi\"],"
      "\"readonlyPaths\":[\"/proc/sys\",\"/proc/irq\",\"/proc/bus\"],\"seccomp\":{\"defaultAction\":\"SCMP_ACT_ALLOW\","
      "\"syscalls\":[{\"action\":\"SCMP_ACT_ERRNO\",\"errnoRet\":1,\"names\":[\"bpf\",\"perf_event_open\",\"ptrace\","
      "\"process_vm_readv\",\"process_vm_writev\",\"keyctl\",\"add_key\",\"request_key\",\"mount\",\"umount2\",\"pivot_"
      "root\","
      "\"setns\",\"unshare\",\"reboot\",\"kexec_load\",\"kexec_file_load\",\"init_module\",\"finit_module\",\"delete_"
      "module\","
      "\"swapon\",\"swapoff\",\"open_by_handle_at\",\"userfaultfd\",\"io_uring_setup\",\"fsopen\",\"fsconfig\","
      "\"fsmount\",\"fspick\",\"open_tree\",\"move_mount\",\"mount_setattr\"]},"
      "{\"action\":\"SCMP_ACT_ERRNO\",\"errnoRet\":38,\"names\":[\"clone3\"]}";
  for (uint64_t flag :
       {0x00020000ULL, 0x02000000ULL, 0x04000000ULL, 0x08000000ULL, 0x10000000ULL, 0x20000000ULL, 0x40000000ULL}) {
    out +=
        ",{\"action\":\"SCMP_ACT_ERRNO\",\"errnoRet\":1,\"names\":[\"clone\"],\"args\":[{\"index\":0,\"op\":\"SCMP_CMP_"
        "MASKED_EQ\",\"value\":" +
        std::to_string(flag) + ",\"valueTwo\":" + std::to_string(flag) + "}]}";
  }
  out += "]}}}";
  return out;
}
}  // namespace fortis::host::sandbox
