#include "signing_log.h"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace fortis::keys {
namespace {
[[noreturn]] void Fail(const std::string& what) { throw std::runtime_error("signing log: " + what); }

using RecordBytes = std::array<uint8_t, SigningLog::kRecordSize>;

void Put64(uint8_t* out, uint64_t v) {
  for (int i = 0; i < 8; ++i) out[i] = static_cast<uint8_t>(v >> (56 - 8 * i));
}
uint64_t Get64(const uint8_t* in) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = v << 8 | in[i];
  return v;
}

RecordBytes Encode(const LogEntry& entry, const Hash& head) {
  RecordBytes r{};
  Put64(r.data(), entry.sequence);
  Put64(r.data() + 8, entry.time);
  r[16] = static_cast<uint8_t>(entry.algorithm);
  r[17] = static_cast<uint8_t>(entry.label.size());
  std::memcpy(r.data() + 18, entry.label.data(), entry.label.size());
  std::memcpy(r.data() + 18 + kLabelMax, entry.message.data(), 32);
  std::memcpy(r.data() + 18 + kLabelMax + 32, head.data(), 32);
  return r;
}

bool Decode(const RecordBytes& r, LogEntry& entry, Hash& head) {
  const auto algorithm = AlgorithmFrom(r[16]);
  const size_t length = r[17];
  if (!algorithm || length == 0 || length > kLabelMax) return false;
  for (size_t i = 18 + length; i < 18 + kLabelMax; ++i)
    if (r[i] != 0) return false;  // the padding is zero, so a record has one encoding
  entry.sequence = Get64(r.data());
  entry.time = Get64(r.data() + 8);
  entry.algorithm = *algorithm;
  entry.label.assign(reinterpret_cast<const char*>(r.data() + 18), length);
  std::memcpy(entry.message.data(), r.data() + 18 + kLabelMax, 32);
  std::memcpy(head.data(), r.data() + 18 + kLabelMax + 32, 32);
  return ValidLabel(entry.label);
}

bool Flush(int fd) {
#if defined(__linux__)
  return ::fdatasync(fd) == 0;
#else
  return ::fsync(fd) == 0;
#endif
}

uint64_t Now() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}
}  // namespace

SigningLog::SigningLog(const std::filesystem::path& folder, const std::array<uint8_t, 16>& machine)
    : machine_(machine) {
  const auto path = folder / "signing.log";
  fd_ = ::open(path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd_ < 0) Fail("cannot open signing.log");
  struct stat st {};
  if (::fstat(fd_, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != ::geteuid() || (st.st_mode & 077) != 0 ||
      st.st_nlink != 1) {
    (void)::close(fd_);
    Fail("signing.log is not a private file of this user");
  }
  const auto size = static_cast<uint64_t>(st.st_size);
  const uint64_t records = size / kRecordSize;
  // A record cut short by a crash was never on disk whole, so never answered.
  if (size % kRecordSize != 0 && (::ftruncate(fd_, static_cast<off_t>(records * kRecordSize)) != 0 || !Flush(fd_))) {
    (void)::close(fd_);
    Fail("cannot remove a record cut short");
  }
  Hash head{};
  for (uint64_t sequence = 1; sequence <= records; ++sequence) {
    LogEntry entry;
    Hash stored{};
    if (!ReadRecord(sequence, entry, stored) || entry.sequence != sequence || NextHead(head, entry) != stored) {
      (void)::close(fd_);
      Fail("signing.log is damaged at entry " + std::to_string(sequence));
    }
    head = stored;
  }
  written_ = durable_ = records;
  head_ = head;
}

SigningLog::~SigningLog() {
  if (fd_ >= 0) (void)::close(fd_);
}

bool SigningLog::ReadRecord(uint64_t sequence, LogEntry& entry, Hash& head) const {
  RecordBytes r{};
  const auto offset = static_cast<off_t>((sequence - 1) * kRecordSize);
  size_t done = 0;
  while (done < r.size()) {
    const ssize_t n = ::pread(fd_, r.data() + done, r.size() - done, offset + static_cast<off_t>(done));
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    done += static_cast<size_t>(n);
  }
  return Decode(r, entry, head);
}

std::optional<Stamp> SigningLog::Record(Algorithm algorithm, std::string_view label, View message) {
  std::unique_lock lock(mutex_);
  if (failed_) return std::nullopt;
  const Stamp stamp{machine_, written_ + 1, Now()};
  const auto entry = EntryFor(stamp, algorithm, label, message);
  const auto head = NextHead(head_, entry);
  const auto record = Encode(entry, head);
  const auto offset = static_cast<off_t>(written_ * kRecordSize);
  size_t done = 0;
  while (done < record.size()) {
    const ssize_t n = ::pwrite(fd_, record.data() + done, record.size() - done, offset + static_cast<off_t>(done));
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) {
      // A disk that is full or failing: stop signing rather than sign unrecorded.
      failed_ = true;
      synced_.notify_all();
      return std::nullopt;
    }
    done += static_cast<size_t>(n);
  }
  written_ = stamp.sequence;
  head_ = head;
  // Wait until a flush covers this record. One thread flushes everything
  // written so far; the others that wrote meanwhile wait for it.
  while (durable_ < stamp.sequence) {
    if (failed_) return std::nullopt;
    if (syncing_) {
      synced_.wait(lock);
      continue;
    }
    syncing_ = true;
    const uint64_t target = written_;
    lock.unlock();
    const bool ok = Flush(fd_);
    lock.lock();
    syncing_ = false;
    if (ok) {
      if (target > durable_) durable_ = target;
    } else {
      failed_ = true;
    }
    synced_.notify_all();
  }
  return stamp;
}

uint64_t SigningLog::Last() const {
  const std::lock_guard lock(mutex_);
  return durable_;
}

std::optional<Hash> SigningLog::HeadAt(uint64_t sequence) const {
  if (sequence == 0) return Hash{};
  if (sequence > Last()) return std::nullopt;
  LogEntry entry;
  Hash head{};
  if (!ReadRecord(sequence, entry, head)) return std::nullopt;
  return head;
}

std::optional<LogSegment> SigningLog::Read(uint64_t from, size_t count) const {
  const uint64_t last = Last();
  if (from == 0 || from > last || count == 0) return std::nullopt;
  if (count > kReadMax) count = kReadMax;
  const auto previous = HeadAt(from - 1);
  if (!previous) return std::nullopt;
  LogSegment segment{*previous, {}};
  for (uint64_t sequence = from; sequence <= last && segment.entries.size() < count; ++sequence) {
    LogEntry entry;
    Hash head{};
    if (!ReadRecord(sequence, entry, head)) return std::nullopt;
    segment.entries.push_back(std::move(entry));
  }
  return segment;
}
}  // namespace fortis::keys
