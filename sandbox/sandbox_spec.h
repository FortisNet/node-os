#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace fortis::host::sandbox {

/** A caller-owned, versioned execution request. No parsed-input borrows survive.
 * Environment overrides, host mounts, network access and privileged execution
 * are deliberately absent. Requests cannot select a weaker runtime.
 */
struct Spec {
  std::string id;
  std::string image;
  std::vector<std::string> args;
  uint64_t cpu_millicores = 1000;
  uint64_t memory_mib = 256;
  uint64_t processes = 64;
  uint64_t timeout_seconds = 60;
  uint64_t scratch_mib = 64;
  uint64_t output_bytes = 1024 * 1024;
};

/** Operator ceilings. Accounting reserves each job's maximum, not observed use.
 * All instances sharing a state directory must use the same policy.
 */
struct Limits {
  uint64_t jobs = 8;
  uint64_t cpu_millicores = 4000;
  uint64_t memory_mib = 4096;
  uint64_t processes = 256;
  uint64_t timeout_seconds = 3600;
  uint64_t scratch_mib = 512;
  uint64_t output_bytes = 1024 * 1024;
};

/** Root-owned installation policy, never supplied by an agent. The runtime's
 * exact executable hash is pinned; gVisor is the default isolation class.
 * UID/GID ranges must be exclusively reserved for this installation.
 */
struct Policy {
  std::string state_root = "/var/lib/fortis-sandboxes";
  std::string image_root = "/opt/fortis-sandboxes/images";
  std::string runtime = "/usr/local/bin/runsc";
  std::string runtime_sha256;
  std::string isolation = "gvisor";
  std::string cgroup_parent = "/fortis-sandboxes";
  uint32_t uid_base = 1048576;
  Limits limits;
};

/** Parse a strict bounded request; rejects unknown/duplicate fields and overflow.
 * Throws runtime_error on invalid input. Thread-safe with distinct input owners;
 * returned strings/vectors own their bytes, including when input is temporary.
 */
Spec ParseSpec(std::string_view json);
/// Parse strict operator policy with fixed upper ceilings; owns all returned data.
Policy ParsePolicy(std::string_view json);
/// Canonical owned request identity for hashing; includes arguments and must stay private.
std::string SpecIdentity(const Spec& spec);
/// Canonical private installation identity; no workload arguments or credentials.
std::string PolicyIdentity(const Policy& policy);
/// Validate identifiers, command and all ceilings without modifying either value.
void Validate(const Spec& spec, const Limits& limits);
/// A lowercase ASCII identifier, 1–48 characters, beginning with a letter.
bool Identifier(std::string_view value);
/// Quote one JSON string without retaining the input. Throws on embedded NUL or invalid UTF-8.
std::string Quote(std::string_view value);

/** Produce an owned OCI configuration for a root-owned approved root filesystem.
 * The runtime must apply the complete configuration before executing the payload.
 * uid_base selects a disjoint 65,536-ID user namespace; cgroup is host-managed.
 * No shell, command execution, filesystem reads or shared state are involved.
 */
std::string OciConfig(const Spec& spec, std::string_view rootfs, std::string_view cgroup, uint32_t uid_base);

}  // namespace fortis::host::sandbox
