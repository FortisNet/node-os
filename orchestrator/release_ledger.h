#pragma once
#include "native_control_support.h"

namespace fortis::host::updates {
/** One activation. Zero timestamps mean unknown, never a fabricated serving boundary. */
struct Deployment {
  uint64_t id = 0, instance = 0, previous = 0;
  std::string version, digest, source, phase = "requested", outcome = "pending", reason = "none";
  uint64_t requested = 0, started = 0, ready = 0, enabled = 0, disabled = 0;
  uint64_t drained = 0, stopped = 0, stable = 0, updated = 0, duration_ms = 0;
  bool uncertain = false, verified = true;
  uint64_t request_samples = 0, node_events = 0, provider_events = 0, p95_ms = 0, observation_ms = 0;
};
struct LedgerHead {
  uint64_t sequence = 0, deployments = 0, instances = 0, active = 0, candidate = 0;
};

/** Serialized host-only ledger under the controller's exclusive update lock.
 * Events are fsynced before projections and head publication. Recovery replays
 * a bounded uncommitted tail; committed corruption is an error. All event files
 * remain retained. Snapshots contain only bounded public fields, no host paths.
 * Methods throw on I/O/corruption; callers must refuse promotion on failure.
 */
class ReleaseLedger final {
 public:
  explicit ReleaseLedger(fs::path root);
  Deployment New(std::string version, std::string digest, std::string source = {});
  Deployment Load(uint64_t id) const;
  void Save(Deployment& record);
  void Publish();
  LedgerHead& Head() & { return head_; }
  const LedgerHead& Head() const& { return head_; }
  LedgerHead& Head() && = delete;
  const LedgerHead& Head() const&& = delete;
  fs::path PublicDirectory() const { return root_ / "public"; }
  static std::string PublicRecord(const Deployment& record);

 private:
  fs::path root_;
  LedgerHead head_{};
  void Apply(std::string_view event);
};
}  // namespace fortis::host::updates
