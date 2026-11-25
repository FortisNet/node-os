#include "release_ledger.h"
#include <cassert>
#include <type_traits>
#include <sys/resource.h>

using namespace fortis::host::updates;
namespace {
class Temporary final {
 public:
  Temporary() {
    std::array<char, 64> name{};
    const char value[] = "/tmp/fortis-release-ledger-XXXXXX";
    std::copy(std::begin(value), std::end(value), name.begin());
    const auto* result = mkdtemp(name.data());
    assert(result);
    path = result;
  }
  ~Temporary() {
    std::error_code error;
    fs::remove_all(path, error);
  }
  Temporary(const Temporary&) = delete;
  Temporary& operator=(const Temporary&) = delete;
  fs::path path;
};
template <class F>
void Reject(F&& function) {
  bool rejected = false;
  try {
    function();
  } catch (const std::exception&) { rejected = true; }
  assert(rejected);
}
constexpr char kDigest[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
void RecordsAndRecovery() {
  Temporary temp;
  {
    ReleaseLedger ledger(temp.path);
    std::string label = "one";
    auto first = ledger.New(label, kDigest);
    label.clear();
    first.instance = ++ledger.Head().instances;
    first.uncertain = true;
    first.phase = "stable";
    first.outcome = "accepted";
    first.enabled = NowMs();
    ledger.Head().active = first.id;
    ledger.Save(first);
    assert(first.id == 1 && ledger.Load(1).version == "one");
    for (unsigned i = 0; i < 28; ++i) {
      auto next = ledger.New("next", kDigest);
      next.phase = "rejected";
      next.outcome = "not-promoted";
      ledger.Save(next);
    }
    const Json current(Read(temp.path / "public/current.json"));
    assert(current.Unsigned(current.Field(current.Root(), "latestPage")) == 1);
    const Json page(Read(temp.path / "public/history-0.json"));
    const auto records = page.Field(page.Root(), "records");
    unsigned count = 0;
    for (auto t = page.Get().token(records)->first_child; t != fortis::codec::kBoundedJsonNoToken;
         t = page.Get().token(t)->next_sibling)
      ++count;
    assert(count == 25);
    ledger.Head().sequence = INT64_MAX;
    Reject([&] { ledger.Save(first); });
  }
  // A projection/head write lost after the fsynced event is replayed exactly once.
  fs::remove(temp.path / "head");
  ReleaseLedger recovered(temp.path);
  assert(recovered.Head().deployments == 29 && recovered.Head().active == 1);
  assert(recovered.Load(1).version == "one");
  const auto body = Read(temp.path / "events/0/29.event");
  AtomicFile(temp.path / "events/0/29.event", body + "corruption");
  Reject([&] { ReleaseLedger invalid(temp.path); });
}
void UnknownsAndBounds() {
  Temporary temp;
  ReleaseLedger ledger(temp.path);
  auto record = ledger.New("unverified", "");
  record.verified = false;
  record.phase = "rejected";
  ledger.Save(record);
  const auto public_record = ReleaseLedger::PublicRecord(ledger.Load(1));
  assert(public_record.find("\"sha256\":null") != std::string::npos);
  assert(public_record.find("\"signatureVerified\":false") != std::string::npos);
  assert(public_record.find("\"trafficEnabledAtMs\":null") != std::string::npos);
  Reject([] { (void)Integer({}); });
  Reject([] { (void)Integer("-1"); });
  Reject([] { (void)Integer("18446744073709551616"); });
  Reject([] { (void)Integer("2", 1); });
  ledger.Head().deployments = INT64_MAX;
  Reject([&] { (void)ledger.New("two", kDigest); });
  assert(!Token("../escape") && !Hex("wrong"));
}
void ChildContracts() {
  const auto result = Command({"/bin/sh", "-c", "printf hello; exit 42"});
  assert(result.exit == 42 && result.output == "hello");
  Reject([] { (void)Command({"/bin/sleep", "5"}, 0); });
  Reject([] { (void)Command({"/bin/sh", "-c", "printf 123456789"}, 2, 4); });
  static_assert(!std::is_move_constructible_v<Json> && !std::is_copy_constructible_v<Json>);
  static_assert(std::is_move_constructible_v<fortis::host::FileDescriptor> &&
                !std::is_copy_constructible_v<fortis::host::FileDescriptor>);
}
}  // namespace
int main(int argc, char** argv) try {
  if (argc == 2 && std::string_view(argv[1]) == "--write-limit") {
    Temporary temporary;
    const auto path = temporary.path / "snapshot";
    AtomicFile(path, "old");
    (void)signal(SIGXFSZ, SIG_IGN);
    rlimit limit{16, 16};
    assert(setrlimit(RLIMIT_FSIZE, &limit) == 0);
    Reject([&] { AtomicFile(path, std::string(100, 'x')); });
    assert(Read(path) == "old");
    return 0;
  }
  assert(Command({argv[0], "--write-limit"}).exit == 0);
  RecordsAndRecovery();
  UnknownsAndBounds();
  ChildContracts();
} catch (const std::exception& error) {
  std::fprintf(stderr, "release ledger test failed: %s\n", error.what());
  return 1;
}
