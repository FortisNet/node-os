#include "release_ledger.h"

namespace fortis::host::updates {
namespace {
uint32_t Checksum(std::string_view bytes) {
  uint32_t crc = UINT32_MAX;
  for (const unsigned char c : bytes) {
    crc ^= c;
    for (unsigned bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
  }
  return ~crc;
}
std::vector<std::string> Split(std::string_view input) {
  std::vector<std::string> result;
  while (true) {
    const auto next = input.find('\t');
    result.emplace_back(input.substr(0, next));
    Require(result.size() <= 40, "ledger field limit");
    if (next == std::string_view::npos) break;
    input.remove_prefix(next + 1);
  }
  return result;
}
fs::path EventPath(const fs::path& root, uint64_t sequence) {
  Require(sequence > 0, "invalid event sequence");
  return root / "events" / std::to_string((sequence - 1) / 1024) / (std::to_string(sequence) + ".event");
}
std::string Number(uint64_t value) { return value ? std::to_string(value) : "null"; }
std::string Encode(const LedgerHead& head, const Deployment& r) {
  std::ostringstream out;
  out << "FNU1";
  for (auto n :
       {head.sequence, head.deployments, head.instances, head.active, head.candidate, r.id, r.instance, r.previous})
    out << '\t' << n;
  for (const auto& text : {r.version, r.digest.empty() ? "unknown" : r.digest, r.source.empty() ? "unknown" : r.source,
                           r.phase, r.outcome, r.reason}) {
    Require(Token(text, 128), "invalid ledger token");
    out << '\t' << text;
  }
  for (auto n : {r.requested, r.started, r.ready, r.enabled, r.disabled, r.drained, r.stopped, r.stable, r.updated,
                 r.duration_ms, static_cast<uint64_t>(r.uncertain), static_cast<uint64_t>(r.verified),
                 r.request_samples, r.node_events, r.provider_events, r.p95_ms, r.observation_ms})
    out << '\t' << n;
  const auto body = out.str();
  return body + "\n" + std::to_string(Checksum(body)) + "\n";
}
std::pair<LedgerHead, Deployment> Decode(std::string_view bytes) {
  const auto end = bytes.find('\n');
  Require(end != std::string_view::npos && end + 1 < bytes.size() && bytes.back() == '\n', "torn ledger record");
  const auto body = bytes.substr(0, end);
  Require(Integer(bytes.substr(end + 1, bytes.size() - end - 2), UINT32_MAX) == Checksum(body),
          "ledger checksum mismatch");
  const auto f = Split(body);
  Require(f.size() == 32 && f[0] == "FNU1", "invalid ledger schema");
  LedgerHead h{Integer(f[1]), Integer(f[2]), Integer(f[3]), Integer(f[4]), Integer(f[5])};
  Deployment r{};
  r.id = Integer(f[6]);
  r.instance = Integer(f[7]);
  r.previous = Integer(f[8]);
  r.version = f[9];
  r.digest = f[10] == "unknown" ? "" : f[10];
  r.source = f[11] == "unknown" ? "" : f[11];
  r.phase = f[12];
  r.outcome = f[13];
  r.reason = f[14];
  Require(Token(r.version) && (r.digest.empty() || Hex(r.digest)) &&
              (r.source.empty() || Hex(r.source, 40) || Hex(r.source)),
          "invalid ledger identity");
  Require(Token(r.phase) && Token(r.outcome) && Token(r.reason, 128), "invalid ledger phase");
  r.requested = Integer(f[15]);
  r.started = Integer(f[16]);
  r.ready = Integer(f[17]);
  r.enabled = Integer(f[18]);
  r.disabled = Integer(f[19]);
  r.drained = Integer(f[20]);
  r.stopped = Integer(f[21]);
  r.stable = Integer(f[22]);
  r.updated = Integer(f[23]);
  r.duration_ms = Integer(f[24]);
  r.uncertain = Integer(f[25], 1) != 0;
  r.verified = Integer(f[26], 1) != 0;
  r.request_samples = Integer(f[27]);
  r.node_events = Integer(f[28]);
  r.provider_events = Integer(f[29]);
  r.p95_ms = Integer(f[30]);
  r.observation_ms = Integer(f[31]);
  Require(!r.verified || Hex(r.digest), "verified record needs an artifact hash");
  Require(h.sequence && r.id && r.id <= h.deployments && r.instance <= h.instances && h.active <= h.deployments &&
              h.candidate <= h.deployments,
          "invalid ledger counters");
  return {h, r};
}
}  // namespace

ReleaseLedger::ReleaseLedger(fs::path root) : root_(std::move(root)) {
  Directory(root_, 0700);
  Directory(root_ / "events", 0700);
  Directory(root_ / "deployments", 0700);
  Directory(root_ / "public", 0755);
  const auto index = root_ / "head";
  if (fs::exists(index)) {
    const auto bytes = Read(index, 4096);
    const auto [head, record] = Decode(bytes);
    Require(Read(EventPath(root_, head.sequence), 4096) == bytes, "ledger head/event mismatch");
    head_ = head;
    // Repair projections if publication was interrupted after head persistence.
    AtomicFile(root_ / "deployments" / (std::to_string(record.id) + ".state"), bytes);
  }
  for (unsigned tail = 0; tail < 4096; ++tail) {
    Require(head_.sequence < kMaxPublicInteger, "ledger sequence exhausted");
    const auto next = EventPath(root_, head_.sequence + 1);
    if (!fs::exists(next)) return;
    Apply(Read(next, 4096));
  }
  throw std::runtime_error("ledger recovery tail exceeds bound");
}
void ReleaseLedger::Apply(std::string_view event) {
  const auto [head, record] = Decode(event);
  Require(head.sequence == head_.sequence + 1, "nonconsecutive ledger event");
  Require(head.deployments >= head_.deployments && head.instances >= head_.instances, "ledger counter regression");
  AtomicFile(root_ / "deployments" / (std::to_string(record.id) + ".state"), event);
  AtomicFile(root_ / "head", event);
  head_ = head;
}
Deployment ReleaseLedger::New(std::string version, std::string digest, std::string source) {
  Require(head_.deployments < kMaxPublicInteger, "deployment IDs exhausted");
  Deployment record{};
  record.id = ++head_.deployments;
  record.version = std::move(version);
  record.digest = std::move(digest);
  record.source = std::move(source);
  record.requested = NowMs();
  return record;
}
Deployment ReleaseLedger::Load(uint64_t id) const {
  Require(id && id <= head_.deployments, "unknown deployment");
  auto record = Decode(Read(root_ / "deployments" / (std::to_string(id) + ".state"), 4096)).second;
  Require(record.id == id, "deployment projection mismatch");
  return record;
}
void ReleaseLedger::Save(Deployment& record) {
  Require(head_.sequence < kMaxPublicInteger && record.id <= head_.deployments, "ledger sequence exhausted");
  record.updated = NowMs();
  LedgerHead next = head_;
  ++next.sequence;
  const auto bytes = Encode(next, record);
  const auto target = EventPath(root_, next.sequence);
  Directory(target.parent_path(), 0700);
  Require(!fs::exists(target), "immutable event collision");
  AtomicFile(target, bytes);
  Apply(bytes);
  Publish();
}
std::string ReleaseLedger::PublicRecord(const Deployment& r) {
  return "{\"deploymentId\":" + std::to_string(r.id) + ",\"instanceId\":" + Number(r.instance) +
         ",\"previousDeploymentId\":" + Number(r.previous) + ",\"version\":" + Quote(r.version) +
         ",\"sha256\":" + (r.digest.empty() ? "null" : Quote(r.digest)) +
         ",\"sourceCommit\":" + (r.source.empty() ? "null" : Quote(r.source)) + ",\"phase\":" + Quote(r.phase) +
         ",\"outcome\":" + Quote(r.outcome) + ",\"reason\":" + Quote(r.reason) +
         ",\"requestedAtMs\":" + Number(r.requested) + ",\"processStartedAtMs\":" + Number(r.started) +
         ",\"readyAtMs\":" + Number(r.ready) + ",\"trafficEnabledAtMs\":" + Number(r.enabled) +
         ",\"trafficDisabledAtMs\":" + Number(r.disabled) + ",\"drainedAtMs\":" + Number(r.drained) +
         ",\"stoppedAtMs\":" + Number(r.stopped) + ",\"stableAtMs\":" + Number(r.stable) +
         ",\"updatedAtMs\":" + Number(r.updated) + ",\"activationDurationMs\":" + std::to_string(r.duration_ms) +
         ",\"timeUncertain\":" + (r.uncertain ? "true" : "false") +
         ",\"signatureVerified\":" + (r.verified ? "true" : "false") +
         ",\"requestSamples\":" + std::to_string(r.request_samples) +
         ",\"nodeEvents\":" + std::to_string(r.node_events) +
         ",\"providerEvents\":" + std::to_string(r.provider_events) + ",\"maxGroupP95Ms\":" + std::to_string(r.p95_ms) +
         ",\"observationMs\":" + std::to_string(r.observation_ms) + "}";
}
void ReleaseLedger::Publish() {
  const auto latest_page = head_.deployments ? (head_.deployments - 1) / 25 : 0;
  // Only the active/candidate pages can change; old pages are immutable once
  // their final deployment has finished. At most three bounded pages per call.
  std::vector<uint64_t> pages{latest_page};
  if (head_.active) pages.push_back((head_.active - 1) / 25);
  if (head_.candidate) pages.push_back((head_.candidate - 1) / 25);
  std::sort(pages.begin(), pages.end());
  pages.erase(std::unique(pages.begin(), pages.end()), pages.end());
  for (const auto page : pages) {
    const uint64_t begin = page * 25 + 1, end = std::min(begin + 24, head_.deployments);
    std::string records;
    for (uint64_t id = end; id >= begin && id != 0; --id) {
      if (!records.empty()) records += ',';
      records += PublicRecord(Load(id));
    }
    const std::string body = "{\"schemaVersion\":1,\"page\":" + std::to_string(page) +
                             ",\"previousPage\":" + (page ? std::to_string(page - 1) : "null") + ",\"records\":[" +
                             records + "]}";
    AtomicFile(root_ / "public" / ("history-" + std::to_string(page) + ".json"), body, 0644);
  }
  const auto active = head_.active ? PublicRecord(Load(head_.active)) : "null";
  const auto candidate = head_.candidate ? PublicRecord(Load(head_.candidate)) : "null";
  const auto snapshot = "{\"schemaVersion\":1,\"managed\":true,\"observedAtMs\":" + std::to_string(NowMs()) +
                        ",\"sequence\":" + std::to_string(head_.sequence) +
                        ",\"latestPage\":" + std::to_string(latest_page) + ",\"current\":" + active +
                        ",\"candidate\":" + candidate + "}";
  AtomicFile(root_ / "public/current.json", snapshot, 0644);
}
}  // namespace fortis::host::updates
