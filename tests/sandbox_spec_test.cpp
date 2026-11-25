#include "sandbox_spec.h"

#include <cassert>
#include <functional>
#include <limits>
#include <stdexcept>
#include <thread>
#include <utility>

using namespace fortis::host::sandbox;
namespace {
const std::string kRequest = R"({"schemaVersion":1,"id":"job-a","image":"approved","args":["/bin/probe","hello"]})";
const std::string kPolicy = R"({"schemaVersion":1,"runtimeSha256":")" + std::string(64, 'a') + "\"}";
void Refused(const std::function<void()>& operation) {
  bool refused = false;
  try {
    operation();
  } catch (const std::runtime_error&) { refused = true; }
  assert(refused);
}
std::string Field(const std::string& extra) { return kRequest.substr(0, kRequest.size() - 1) + ',' + extra + '}'; }
}  // namespace
int main() try {
  auto spec = ParseSpec(std::string(kRequest));
  auto moved = std::move(spec);
  assert(moved.id == "job-a" && moved.args[1] == "hello");
  auto policy = ParsePolicy(std::string(kPolicy));
  assert(ParsePolicy(PolicyIdentity(policy)).runtime_sha256 == policy.runtime_sha256);
  Validate(moved, policy.limits);
  assert(SpecIdentity(ParseSpec(SpecIdentity(moved))) == SpecIdentity(moved));
  auto different = moved;
  different.args.push_back("changed");
  assert(SpecIdentity(different) != SpecIdentity(moved));
  for (const auto* value : {"", "../escape", "Upper", "a/b", "a.b", "1a", "a_b"}) assert(!Identifier(value));
  assert(Identifier("a") && Identifier(std::string(48, 'a')) && !Identifier(std::string(49, 'a')));
  for (const auto* json : {"", "[]", "{}", "{", "null", "true", "1", "{\"schemaVersion\":2}"})
    Refused([&] { (void)ParseSpec(json); });
  for (const auto* extra :
       {"\"id\":\"duplicate\"", "\"env\":[]", "\"mounts\":[]", "\"network\":true", "\"isolation\":\"process\"",
        "\"cpuLimitMillicores\":0", "\"cpuLimitMillicores\":1.5", "\"cpuLimitMillicores\":1e3",
        "\"cpuLimitMillicores\":-1", "\"cpuLimitMillicores\":18446744073709551616", "\"memoryLimitMiB\":63",
        "\"memoryLimitMiB\":65537", "\"maxProcesses\":0", "\"maxProcesses\":1025", "\"timeoutSeconds\":0",
        "\"timeoutSeconds\":86401", "\"scratchLimitMiB\":257", "\"outputLimitBytes\":1023",
        "\"outputLimitBytes\":16777217"})
    Refused([&] { (void)ParseSpec(Field(extra)); });
  Refused([&] { (void)ParseSpec(kRequest + "x"); });
  Refused([&] { (void)ParseSpec(std::string(16385, ' ')); });
  auto nul = kRequest;
  nul.replace(nul.find("hello"), 5, "\\u0000");
  Refused([&] { (void)ParseSpec(nul); });
  auto unicode = kRequest;
  unicode.replace(unicode.find("hello"), 5, "caf\\u00e9");
  assert(ParseSpec(unicode).args[1] == "caf\xc3\xa9");
  assert(Quote("a\n\"\\") == "\"a\\u000a\\\"\\\\\"");
  Refused([] { (void)Quote(std::string_view("a\0b", 3)); });
  for (const auto* invalid : {"\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xc3"})
    Refused([&] { (void)Quote(invalid); });
  auto boundary = moved;
  boundary.cpu_millicores = 10;
  boundary.memory_mib = 64;
  boundary.scratch_mib = 64;
  boundary.processes = 1;
  boundary.timeout_seconds = 1;
  boundary.output_bytes = 1024;
  Validate(boundary, policy.limits);
  boundary.args.assign(64, std::string(128, 'a'));
  boundary.args[0][0] = '/';
  Validate(boundary, policy.limits);
  boundary.args.back() += 'x';
  Refused([&] { Validate(boundary, policy.limits); });
  boundary = moved;
  boundary.args[0] = "relative";
  Refused([&] { Validate(boundary, policy.limits); });
  boundary = moved;
  boundary.args = {"/bin/probe", std::string(4097, 'a')};
  Refused([&] { Validate(boundary, policy.limits); });
  boundary = moved;
  boundary.cpu_millicores = std::numeric_limits<uint64_t>::max();
  Refused([&] { Validate(boundary, policy.limits); });
  for (const auto* extra :
       {"\"runtime\":\"relative\"", "\"runtime\":\"/a/../b\"", "\"runtime\":\"/a//b\"", "\"runtime\":\"/a/.\"",
        "\"isolation\":\"unsafe\"", "\"maxJobs\":33", "\"uidBase\":4294967295", "\"uidBase\":0", "\"unexpected\":0"}) {
    const auto json = kPolicy.substr(0, kPolicy.size() - 1) + ',' + extra + '}';
    Refused([&] { (void)ParsePolicy(json); });
  }
  const auto config = OciConfig(moved, "/approved/rootfs", "/fortis-sandboxes/job/payload", policy.uid_base);
  assert(config.find("\"readonly\":true") != std::string::npos);
  assert(config.find("\"noNewPrivileges\":true") != std::string::npos);
  assert(config.find("SCMP_ACT_ERRNO") != std::string::npos);
  Refused([&] { (void)OciConfig(moved, "relative", "/a", policy.uid_base); });
  Refused([&] { (void)OciConfig(moved, "/root", "/", policy.uid_base); });
  Refused([&] { (void)OciConfig(moved, "/root", "/a", UINT32_MAX); });
  std::vector<std::thread> readers;
  for (unsigned i = 0; i < 8; ++i)
    readers.emplace_back([&] {
      for (unsigned j = 0; j < 100; ++j) assert(ParseSpec(kRequest).args == moved.args);
    });
  for (auto& reader : readers) reader.join();
}

catch (...) {
  return 2;
}
