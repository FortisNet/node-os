#include "pages.h"
#include <ctime>

namespace fortis::host::updates {
namespace {
#include "page_shell.inc"

using State = HealthCheck::State;

std::string Escape(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char c : text) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      case '\'': out += "&#39;"; break;
      default: out += c;
    }
  }
  return out;
}
/** "25 November 2026, 04:40 UTC". */
std::string Date(uint64_t milliseconds) {
  static constexpr std::array<const char*, 12> kMonths{"January",   "February", "March",    "April",
                                                       "May",       "June",     "July",     "August",
                                                       "September", "October",  "November", "December"};
  const auto seconds = static_cast<time_t>(milliseconds / 1000);
  struct tm parts {};
  if (gmtime_r(&seconds, &parts) == nullptr) return "unknown";
  std::array<char, 64> text{};
  std::snprintf(text.data(), text.size(), "%d %s %d, %02d:%02d UTC", parts.tm_mday,
                kMonths.at(static_cast<size_t>(parts.tm_mon)), parts.tm_year + 1900, parts.tm_hour, parts.tm_min);
  return text.data();
}
std::string Size(uint64_t bytes) {
  std::array<char, 32> text{};
  const double gigabytes = static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0);
  if (gigabytes >= 1) std::snprintf(text.data(), text.size(), "%.1f GB", gigabytes);
  else std::snprintf(text.data(), text.size(), "%.0f MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
  return text.data();
}
bool Serving(const HostFacts& facts) { return facts.node_state == "serving"; }
/** The node's state in plain words: a headline and one sentence. */
std::pair<std::string, std::string> StateWords(const HostFacts& facts) {
  if (facts.node_state == "serving")
    return {"The node is running", "It answers wallets and applications at this address."};
  if (facts.node_state == "updating")
    return {"The node is being updated",
            "A new release is being checked and switched in. This page refreshes by itself."};
  if (facts.node_state == "recovering")
    return {"The node is recovering", "The previous release is being started again after a failed update."};
  if (facts.node_state == "stopped")
    return {"The node is stopped", "A release is installed but not running. The orchestrator will start it."};
  return {"This host is being set up", "No node release is installed yet. This page refreshes by itself."};
}
const char* Class(State state) { return state == State::kHealthy ? "ok" : state == State::kWaiting ? "wait" : "bad"; }
const char* Mark(State state) {
  return state == State::kHealthy ? "&#10003;" : state == State::kWaiting ? "&#8230;" : "&#10007;";
}
const char* Word(State state) {
  return state == State::kHealthy ? "HEALTHY" : state == State::kWaiting ? "WAITING" : "NEEDS ATTENTION";
}
std::string Checks(const std::vector<HealthCheck>& checks) {
  std::string out = "<ul class=\"checks\">";
  for (const auto& check : checks) {
    out += std::string("<li class=\"") + Class(check.state) + "\"><span class=\"check\" aria-hidden=\"true\">" +
           Mark(check.state) + "</span><div><strong>" + Escape(check.name) + "</strong><p>" + Escape(check.detail) +
           "</p></div><span class=\"state\">" + Word(check.state) + "</span></li>";
  }
  return out + "</ul>";
}
std::string Section(std::string_view id, std::string_view title, std::string_view label, std::string_view body) {
  return "<section aria-labelledby=\"" + std::string(id) + "\"><div class=\"section-head\"><h2 id=\"" +
         std::string(id) + "\">" + std::string(title) + "</h2><span>" + std::string(label) + "</span></div>" +
         std::string(body) + "</section>\n";
}
/** Fill the shell. Every value is already escaped or fixed text. */
std::string Page(const HostFacts& facts, std::string_view title, std::string_view description, std::string_view eyebrow,
                 std::string_view headline, std::string_view content) {
  std::string page(reinterpret_cast<const char*>(kPageShell), sizeof(kPageShell));
  const auto put = [&page](std::string_view marker, std::string_view value) {
    const auto at = page.find(marker);
    Require(at != std::string::npos, "page shell lacks a marker");
    page.replace(at, marker.size(), value);
  };
  put("@TITLE@", title);
  put("@DESCRIPTION@", description);
  // While the node is not serving, or a release is on its way in, things are
  // changing: look again soon.
  const auto& update = facts.update.state;
  const bool settled = Serving(facts) && (update == "off" || update == "idle" || update == "failed");
  put("@REFRESH@", settled ? "" : "\n<meta http-equiv=\"refresh\" content=\"5\">");
  put("@EYEBROW@", eyebrow);
  put("@HEADLINE@", headline);
  put("@TAGLINE@", "Intelligence needs somewhere<br>to connect, discover and act.");
  put("@STAMP@", "WRITTEN " + Escape(Date(facts.generated_ms)));
  put("@CONTENT@", content);
  return page;
}
std::string Banner(const HostFacts& facts) {
  const auto [headline, sentence] = StateWords(facts);
  const char* kind = Serving(facts) ? "" : facts.node_state == "stopped" ? " bad" : " wait";
  return std::string("<div class=\"banner") + kind + "\" role=\"status\"><strong>" + headline + "</strong><span>" +
         sentence + (facts.waiting_for.empty() ? std::string() : " " + Escape(facts.waiting_for)) + "</span></div>\n";
}
std::string JsonChecks(const std::vector<HealthCheck>& checks) {
  std::string out = "[";
  for (const auto& check : checks) {
    if (out.size() > 1) out += ',';
    out += "{\"name\":" + Quote(check.name) + ",\"state\":\"" +
           (check.state == State::kHealthy   ? "healthy"
            : check.state == State::kWaiting ? "waiting"
                                             : "failing") +
           "\",\"detail\":" + Quote(check.detail) + "}";
  }
  return out + "]";
}
/** "less than a minute", "about a minute", "about 5 minutes", "about 2 hours". */
std::string About(uint64_t seconds) {
  if (seconds < 60) return "less than a minute";
  const uint64_t minutes = (seconds + 30) / 60;
  if (minutes == 1) return "about a minute";
  if (minutes < 90) return "about " + std::to_string(minutes) + " minutes";
  return "about " + std::to_string((minutes + 30) / 60) + " hours";
}
/** Seconds until the waiting release is installed; 0 when that is due. */
uint64_t InstallIn(const HostFacts& facts) {
  const auto& update = facts.update;
  return update.install_at_ms > facts.generated_ms ? (update.install_at_ms - facts.generated_ms + 999) / 1000 : 0;
}
/** What the host is doing about node releases, in one sentence. The plan
 * holds the sentence for most states; the two that count (a wait, a
 * download) are worded here, from the numbers of this very report. */
std::string UpdateSentence(const HostFacts& facts) {
  const auto& update = facts.update;
  if (update.state == "waiting" && !update.candidate_version.empty()) {
    const auto seconds = InstallIn(facts);
    return "Found release " + update.candidate_version + ". It will be installed " +
           (seconds ? "in " + About(seconds) : std::string("in a moment")) + ".";
  }
  if (update.state == "downloading" && !update.candidate_version.empty() && update.candidate_bytes) {
    const auto percent = std::min<uint64_t>(100, update.downloaded_bytes * 100 / update.candidate_bytes);
    return "Downloading release " + update.candidate_version + ": " + std::to_string(percent) + "% so far.";
  }
  return update.message;
}
/** The "Node" entry of the Updates section, on both pages: the sentence
 * above, then one line for every newer release that was not taken. */
std::string NodeUpdates(const HostFacts& facts) {
  std::string out = "<dl class=\"facts\"><dt>Node</dt><dd>" + Escape(UpdateSentence(facts)) + "</dd>";
  for (const auto& skipped : facts.update.skipped)
    out += "<dt>Skipped</dt><dd>A newer release, " + Escape(skipped.version) + ", was not installed: it " +
           Escape(skipped.reason) + "." + (skipped.needs_newer_host ? " A newer Node OS can run it." : "") + "</dd>";
  return out + "</dl>";
}
std::string JsonNumberOrNull(uint64_t value) { return value ? std::to_string(value) : "null"; }
/** "identity":{"did":...,"machine":...}, null for each value not known. */
std::string JsonIdentity(const HostFacts& facts) {
  return ",\"identity\":{\"did\":" + (facts.did.empty() ? std::string("null") : Quote(facts.did)) +
         ",\"machine\":" + (facts.machine_id.empty() ? std::string("null") : Quote(facts.machine_id)) + "}";
}
/** The identity in words, for both pages. A DID is long: it wraps anywhere. */
std::string IdentityFacts(const HostFacts& facts) {
  if (facts.did.empty())
    return "<p class=\"note\">Not created yet. The key service makes this node's identity the first time it "
           "starts.</p>";
  return "<dl class=\"facts\"><dt>DID</dt><dd><code class=\"did\">" + Escape(facts.did) +
         "</code></dd><dt>Machine</dt><dd><code class=\"did\">" + Escape(facts.machine_id) +
         "</code></dd></dl><p class=\"note\">The node's post-quantum identity. Anyone can check its signatures "
         "against this DID, without asking a registry.</p>";
}
/** Replace `path` in one step, without forcing it to storage: these files
 * are rewritten every few seconds and rebuilt from scratch after a restart. */
void Replace(const fs::path& path, std::string_view bytes) {
  const auto temporary = path.string() + ".new";
  {
    FileDescriptor file(
        Check(::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644), "write page"));
    WriteAll(file.get(), bytes.data(), bytes.size());
    Check(fchmod(file.get(), 0644), "page permissions");
  }
  Check(::rename(temporary.c_str(), path.c_str()), "publish page");
}
}  // namespace

std::string PageDate(uint64_t milliseconds) { return Date(milliseconds); }

int HealthStatus(const HostFacts& facts) {
  const auto healthy = [](const std::vector<HealthCheck>& checks) {
    return std::all_of(checks.begin(), checks.end(), [](const HealthCheck& c) { return c.state == State::kHealthy; });
  };
  return Serving(facts) && healthy(facts.orchestrator) && healthy(facts.node) ? 200 : 503;
}

std::string RenderHealthJson(const HostFacts& facts) {
  const int status = HealthStatus(facts);
  std::string out = "{\"schemaVersion\":1,\"generatedMs\":" + std::to_string(facts.generated_ms) +
                    ",\"status\":" + std::to_string(status) + ",\"healthy\":" + (status == 200 ? "true" : "false") +
                    ",\"orchestrator\":{\"version\":" + Quote(facts.orchestrator_version) +
                    ",\"architecture\":" + Quote(facts.architecture) + ",\"runsIn\":" + Quote(facts.runs_in) +
                    ",\"checks\":" + JsonChecks(facts.orchestrator) + "}" + JsonIdentity(facts) +
                    ",\"node\":{\"state\":" + Quote(facts.node_state);
  if (!facts.node_version.empty())
    out += ",\"version\":" + Quote(facts.node_version) + ",\"sha256\":" + Quote(facts.node_sha256);
  return out + ",\"checks\":" + JsonChecks(facts.node) + "}}\n";
}

std::string RenderNodeJson(const HostFacts& facts) {
  const auto& update = facts.update;
  std::string out = "{\"schemaVersion\":1,\"generatedMs\":" + std::to_string(facts.generated_ms) + ",\"running\":";
  // "running" names the installed release; its process may be stopped for a
  // moment, which `sinceMs` being null says.
  if (facts.node_version.empty() || facts.node_sha256.empty()) out += "null";
  else
    out += "{\"version\":" + Quote(facts.node_version) + ",\"sha256\":" + Quote(facts.node_sha256) +
           ",\"hostInterface\":" + std::to_string(facts.node_host_interface) +
           ",\"sinceMs\":" + JsonNumberOrNull(facts.node_since_ms) + "}";
  out += ",\"host\":{\"nodeOsVersion\":" + Quote(facts.orchestrator_version) +
         ",\"architecture\":" + Quote(facts.architecture) + ",\"runsIn\":" + Quote(facts.runs_in) +
         ",\"hostInterfaceMin\":" + std::to_string(kHostInterfaceMin) +
         ",\"hostInterfaceMax\":" + std::to_string(kHostInterfaceMax) + ",\"channel\":" + Quote(facts.channel) +
         ",\"automaticUpdates\":" + (facts.automatic_updates ? "true" : "false") +
         ",\"store\":" + (facts.store.empty() ? "null" : Quote(facts.store)) + "}" + JsonIdentity(facts) +
         ",\"update\":{\"state\":" + Quote(update.state) + ",\"candidate\":";
  if (update.candidate_version.empty()) out += "null";
  else
    out += "{\"version\":" + Quote(update.candidate_version) +
           ",\"hostInterface\":" + std::to_string(update.candidate_interface) +
           ",\"bytes\":" + std::to_string(update.candidate_bytes) + "}";
  const bool waiting = update.state == "waiting", downloading = update.state == "downloading";
  out += ",\"installInSeconds\":" + (waiting ? std::to_string(InstallIn(facts)) : "null") +
         ",\"downloadedBytes\":" + (downloading ? std::to_string(update.downloaded_bytes) : "null") +
         ",\"lastCheckMs\":" + JsonNumberOrNull(update.last_check_ms) +
         ",\"nextCheckMs\":" + JsonNumberOrNull(update.next_check_ms) + ",\"message\":" + Quote(UpdateSentence(facts)) +
         "},\"skipped\":[";
  for (const auto& skipped : update.skipped) {
    if (out.back() != '[') out += ',';
    out += "{\"version\":" + Quote(skipped.version) + ",\"reason\":" + Quote(skipped.reason) + "}";
  }
  out += "],\"history\":[";
  for (const auto& event : facts.history) {
    if (out.back() != '[') out += ',';
    out += "{\"version\":" + Quote(event.version) +
           ",\"sha256\":" + (event.sha256.empty() ? "null" : Quote(event.sha256)) +
           ",\"result\":" + Quote(event.result) + ",\"reason\":" + Quote(event.reason) +
           ",\"atMs\":" + JsonNumberOrNull(event.at_ms) + "}";
  }
  return out + "]}\n";
}

std::string RenderHealthPage(const HostFacts& facts) {
  const bool healthy = HealthStatus(facts) == 200;
  std::string content = std::string("<div class=\"banner") + (healthy ? "" : " bad") + "\" role=\"status\"><strong>" +
                        (healthy ? "This host is healthy" : "This host needs attention") + "</strong><span>" +
                        Escape(StateWords(facts).first) + ". Report written " + Escape(Date(facts.generated_ms)) +
                        ".</span></div>\n";
  content += Section("orchestrator", "Orchestrator", "01 / HOST",
                     "<p class=\"note\">What keeps this host running: it installs, updates and recovers the node. "
                     "Version " +
                         Escape(facts.orchestrator_version) + ".</p>" + Checks(facts.orchestrator));
  std::string node = "<p class=\"note\">" + Escape(StateWords(facts).second);
  if (!facts.node_version.empty()) node += " Release " + Escape(facts.node_version) + ".";
  node += "</p>" + (facts.node.empty() ? std::string() : Checks(facts.node));
  content += Section("node", "FortisNet node", "02 / NODE", node);
  content += Section("identity", "Identity", "03 / DID", IdentityFacts(facts));
  content += Section("updates", "Updates", "04 / RELEASES", NodeUpdates(facts));
  content += Section("machines", "For monitoring tools", "05 / JSON",
                     "<p class=\"note\">The same report is at <a href=\"/health.json\"><code>/health.json</code></a>. "
                     "Both answer 200 when the orchestrator and the node above are healthy and 503 otherwise. "
                     "Which release runs and what the host is doing about newer ones is at "
                     "<a href=\"/node.json\"><code>/node.json</code></a>; that never makes a host "
                     "unhealthy.</p>");
  return Page(facts, "FortisNet node: health", "Whether this FortisNet node host is well.", "Health",
              healthy ? "All<br><span>well.</span>" : "Needs<br><span>attention.</span>", content);
}

std::string RenderFirstPage(const HostFacts& facts) {
  std::string content = Banner(facts);
  content +=
      "<section class=\"intro\" aria-labelledby=\"about\"><p class=\"eyebrow\">A FortisNet node</p>"
      "<h2 id=\"about\">Infrastructure for<br>people and AI.</h2><p>This machine runs a FortisNet node: "
      "open infrastructure that wallets and applications connect to.</p>"
      "<a href=\"https://blockchain.fortisnet.io/\">Learn about FortisNet &#8599;</a></section>\n";
  std::string host =
      "<dl class=\"facts\"><dt>Node OS</dt><dd>" + Escape(facts.orchestrator_version) + ", " +
      Escape(facts.architecture) + ", " +
      (facts.runs_in == "container" ? "in a container" : "on a machine of its own") + "</dd><dt>Node release</dt><dd>" +
      (facts.node_version.empty() ? std::string("none installed") : Escape(facts.node_version)) + "</dd>";
  if (!facts.address.empty()) host += "<dt>Address</dt><dd>" + Escape(facts.address) + "</dd>";
  if (!facts.domain.empty()) host += "<dt>Name</dt><dd>" + Escape(facts.domain) + "</dd>";
  host += "<dt>Processors</dt><dd>" + std::to_string(facts.processors) + "</dd><dt>Memory</dt><dd>" +
          Size(facts.memory_bytes) + "</dd><dt>Disk</dt><dd>" + Size(facts.disk_bytes) + ", " +
          Size(facts.disk_free_bytes) +
          " free</dd></dl><p class=\"note\"><a href=\"/health\">Health of this host &#8594;</a></p>";
  content += Section("host", "This host", "01 / HOST", host);
  content += Section("identity", "Identity", "02 / DID", IdentityFacts(facts));

  std::string updates;
  if (facts.automatic_updates) {
    updates = NodeUpdates(facts) +
              "<p class=\"note\">This host looks for new node releases by itself. It installs one only when it is "
              "signed with the key in this image, and goes back to the release before it if the new one does not "
              "hold.</p>";
  } else if (!facts.store_configured) {
    updates = "<p class=\"note\">No release store is set. Releases are installed by the operator.</p>";
  } else if (!facts.staged.empty()) {
    updates =
        "<p class=\"note\">Downloaded, verified and waiting. Nothing is installed until the operator says so:</p>";
    for (const auto& version : facts.staged) updates += "<p><code>fortis update " + Escape(version) + "</code></p>";
  } else if (!facts.newest_release.empty() && facts.newest_release != facts.node_version) {
    updates = "<p class=\"note\">Release " + Escape(facts.newest_release) +
              " is available. To download and verify it:</p><p><code>fortis fetch " + Escape(facts.newest_release) +
              "</code></p>";
  } else {
    updates = "<p class=\"note\">The installed release is the newest one published.</p>";
  }
  content += Section("updates", "Updates", "03 / RELEASES", updates);

  // Links into the node work only while it serves.
  const bool serving = Serving(facts);
  std::string links = "<ul class=\"links\">";
  for (const auto& [address, label] :
       std::initializer_list<std::pair<const char*, const char*>>{{"/dashboard", "Dashboard"},
                                                                  {"/stats", "Statistics"},
                                                                  {"/releases", "Releases"},
                                                                  {"/doc", "API reference"}}) {
    links += serving ? std::string("<li><a href=\"") + address + "\">" + label + " &#8594;</a></li>"
                     : std::string("<li class=\"off\">") + label + "</li>";
  }
  links += "</ul>";
  if (!serving)
    links += "<p class=\"note\">These belong to the node and are not available while it is not running.</p>";
  content += Section("inside", "Inside the node", "04 / NODE", links);
  content += Section("care", "Worth knowing", "05 / NOTES",
                     "<p class=\"note\">Backups made here stay on this machine. Protection against losing the machine "
                     "itself needs the provider's backups or a copy kept elsewhere.</p>");
  const auto [headline, sentence] = StateWords(facts);
  (void)sentence;
  return Page(facts, "FortisNet node", "A FortisNet node: what this host is and how it is doing.", Escape(headline),
              "One node.<br>Many<br><span>possibilities.</span>", content);
}

void PublishPages(const fs::path& directory, const HostFacts& facts) {
  Replace(directory / kFirstPageFile, RenderFirstPage(facts));
  Replace(directory / kHealthPageFile, RenderHealthPage(facts));
  Replace(directory / kHealthJsonFile, RenderHealthJson(facts));
  Replace(directory / kNodeJsonFile, RenderNodeJson(facts));
  // Last: a reader that sees the new status also sees the new report.
  Replace(directory / kHealthStatusFile,
          std::to_string(HealthStatus(facts)) + " " + std::to_string(facts.generated_ms) + "\n");
}

}  // namespace fortis::host::updates
