#include "update_plan.h"
#include <sys/random.h>

namespace fortis::host::updates {
namespace {
constexpr std::array<std::string_view, 7> kStates{"idle",      "looking",    "waiting", "downloading",
                                                  "verifying", "installing", "failed"};
constexpr size_t kPlanLimit = 4096, kMessageLimit = 400, kSkippedShown = 8;

std::string Field(const std::map<std::string, std::string>& fields, const char* name) {
  const auto found = fields.find(name);
  Require(found != fields.end(), "update plan field absent");
  return found->second;
}
}  // namespace

void UpdatePlan::Choose(const ReleaseIndexEntry& entry, uint64_t install_at) {
  candidate = entry.version;
  candidate_manifest = entry.manifest_sha256;
  candidate_bytes = entry.bytes;
  candidate_interface = entry.host_interface;
  install_at_ms = install_at;
}
void UpdatePlan::Forget() {
  candidate.clear();
  candidate_manifest.clear();
  candidate_bytes = 0;
  candidate_interface = 0;
  install_at_ms = 0;
}

UpdatePlan LoadUpdatePlan(const fs::path& file) {
  try {
    const auto fields = KeyValues(Read(file, kPlanLimit));
    UpdatePlan plan;
    plan.state = Field(fields, "state");
    plan.message = Field(fields, "message");
    Require(
        std::find(kStates.begin(), kStates.end(), plan.state) != kStates.end() && plan.message.size() <= kMessageLimit,
        "update plan state unknown");
    plan.last_check_ms = Integer(Field(fields, "last_check_ms"));
    plan.next_check_ms = Integer(Field(fields, "next_check_ms"));
    plan.candidate = Field(fields, "candidate");
    if (!plan.candidate.empty()) {
      plan.candidate_manifest = Field(fields, "candidate_manifest");
      plan.candidate_bytes = Integer(Field(fields, "candidate_bytes"));
      plan.candidate_interface =
          static_cast<unsigned>(Integer(Field(fields, "candidate_interface"), kHostInterfaceLimit));
      plan.install_at_ms = Integer(Field(fields, "install_at_ms"));
      Require(Token(plan.candidate) && Hex(plan.candidate_manifest), "update plan candidate malformed");
    }
    return plan;
  } catch (const std::exception&) {
    // No plan yet, or one that cannot be read: start again from nothing.
    return {};
  }
}

void SaveUpdatePlan(const fs::path& file, const UpdatePlan& plan) {
  // One line per field: a message is a single line by construction.
  Require(plan.message.find('\n') == std::string::npos && plan.message.size() <= kMessageLimit,
          "update plan message malformed");
  std::string text = "state=" + plan.state + "\nmessage=" + plan.message +
                     "\nlast_check_ms=" + std::to_string(plan.last_check_ms) +
                     "\nnext_check_ms=" + std::to_string(plan.next_check_ms) + "\ncandidate=" + plan.candidate + "\n";
  if (!plan.candidate.empty())
    text += "candidate_manifest=" + plan.candidate_manifest +
            "\ncandidate_bytes=" + std::to_string(plan.candidate_bytes) +
            "\ncandidate_interface=" + std::to_string(plan.candidate_interface) +
            "\ninstall_at_ms=" + std::to_string(plan.install_at_ms) + "\n";
  AtomicFile(file, text, 0600);
}

std::string InterfaceRefusal(unsigned needed) {
  return "needs host interface " + std::to_string(needed) + "; this Node OS offers " +
         std::to_string(kHostInterfaceMin) + " to " + std::to_string(kHostInterfaceMax);
}

ReleaseChoice ChooseRelease(const ReleaseIndex& index) {
  ReleaseChoice choice;
  for (auto entry = index.releases.rbegin(); entry != index.releases.rend(); ++entry) {
    if (HostInterfaceOffered(entry->host_interface)) {
      choice.newest = *entry;
      break;
    }
    // A list may hold a thousand releases; the pages name the newest few.
    if (choice.skipped.size() < kSkippedShown)
      choice.skipped.push_back(
          {entry->version, InterfaceRefusal(entry->host_interface), entry->host_interface > kHostInterfaceMax});
  }
  return choice;
}

uint64_t RandomBelow(uint64_t bound) {
  Require(bound > 0, "empty random range");
  // Values at or above the largest multiple of `bound` are drawn again, so
  // no remainder is more likely than another.
  const uint64_t limit = UINT64_MAX - UINT64_MAX % bound;
  for (;;) {
    uint64_t value = 0;
    const ssize_t got = getrandom(&value, sizeof(value), 0);
    if (got < 0 && errno == EINTR) continue;
    Require(got == static_cast<ssize_t>(sizeof(value)), "the kernel gave no random bytes");
    if (value < limit) return value % bound;
  }
}

std::string PublicReason(std::string_view reason) {
  reason = reason.substr(0, reason.find('\n'));
  while (!reason.empty() && (reason.back() == '.' || reason.back() == ' ' || reason.back() == '\r'))
    reason.remove_suffix(1);
  const bool plain = !reason.empty() && reason.size() <= 160 && std::all_of(reason.begin(), reason.end(), [](char c) {
    return c >= ' ' && c <= '~' && c != '/' && c != '\\';
  });
  return plain ? std::string(reason) : "an error the orchestrator's log describes";
}

}  // namespace fortis::host::updates
