#pragma once

#include "pages.h"
#include "release_fetch.h"

/** What the host has decided about its next node release, and the pure
 * decisions behind it: which release of a list to take, and how long to
 * wait before installing it.
 *
 * The plan is one small file in the administrator's own state folder. It is
 * written at every step, so the pages can say what the host is doing, and a
 * restart continues where the host was: a release it was waiting to install
 * is still installed at the time first chosen, not at a new one. */
namespace fortis::host::updates {

struct UpdatePlan {
  // "idle", "looking", "waiting", "downloading", "verifying", "installing"
  // or "failed": what the pages show as the update state.
  std::string state = "idle";
  // One sentence for a person. Never holds a path or anything fetched.
  std::string message = "No newer release has been looked for yet.";
  // The release chosen to be installed next; an empty version means none.
  std::string candidate, candidate_manifest;
  uint64_t candidate_bytes = 0;
  unsigned candidate_interface = 0;
  uint64_t install_at_ms = 0;  // when the candidate is installed
  uint64_t last_check_ms = 0;  // when the store last answered with an acceptable list
  uint64_t next_check_ms = 0;  // nothing is asked of the store before this
  void Choose(const ReleaseIndexEntry& entry, uint64_t install_at);
  void Forget();
};
/** The plan in `file`. A missing, unreadable or malformed file is a new
 * plan: the worst that follows is one more check of the store. */
UpdatePlan LoadUpdatePlan(const fs::path& file);
/** Replace `file` with `plan` in one step. Throws when it cannot be written. */
void SaveUpdatePlan(const fs::path& file, const UpdatePlan& plan);

/** "needs host interface 2; this Node OS offers 1 to 1". */
std::string InterfaceRefusal(unsigned needed);

struct ReleaseChoice {
  // The newest release this host can run: the last entry of the list whose
  // host interface is offered. Absent when the list has none.
  std::optional<ReleaseIndexEntry> newest;
  // The releases listed after it, newest first, and why each was not taken:
  // at most the newest eight.
  std::vector<SkippedRelease> skipped;
};
/** Choose from a list that has already been verified. The list is ordered
 * oldest first; nothing is compared but the host interface. */
ReleaseChoice ChooseRelease(const ReleaseIndex& index);

/** A number from 0 to `bound - 1`, each equally likely, from the kernel's
 * random source: not from the clock, so that hosts started in the same
 * second do not all choose the same wait. `bound` must not be 0. Throws
 * when the kernel gives no random bytes. */
uint64_t RandomBelow(uint64_t bound);

/** `reason` as it may be shown on a page: one line, and only when it cannot
 * hold a path of this host. Anything else becomes a pointer to the log. */
std::string PublicReason(std::string_view reason);

}  // namespace fortis::host::updates
