#pragma once
// The key service's signing log (docs/fortis-did.md, section 11.3).
//
// One entry per labelled signature, written to disk before the signature is
// made: nothing is signed that the log does not record, and a sequence number
// is never given twice, even across a crash. The file is signing.log in the
// store folder, a run of fixed-size records:
//
//   sequence u64 | time u64 | algorithm u8 | label length u8 | label, padded to 64 |
//   SHA-256 of the message [32] | head after this entry [32]
//
// Fixed-size records let any entry, and the head at any past entry, be read
// directly. Several signatures that arrive together share one disk flush.
#include "key_log.h"

#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>

namespace fortis::keys {
class SigningLog {
 public:
  static constexpr size_t kRecordSize = 8 + 8 + 1 + 1 + kLabelMax + 32 + 32;
  /// The most entries one LogEntries request may ask for.
  static constexpr size_t kReadMax = 256;

  /// Opens or creates signing.log in this folder. A record cut short at the
  /// end (a crash while writing it) is removed: its signature was never made.
  /// Anything else wrong (a sequence out of order, a head that does not
  /// follow) refuses the log. Throws std::runtime_error.
  SigningLog(const std::filesystem::path& folder, const std::array<uint8_t, 16>& machine);
  ~SigningLog();
  SigningLog(const SigningLog&) = delete;
  SigningLog& operator=(const SigningLog&) = delete;

  /// Records a signature about to be made, and returns once the record is on
  /// disk, with the stamp to sign. None if the log cannot be written: then
  /// nothing may be signed, and nothing will be until the service restarts.
  std::optional<Stamp> Record(Algorithm algorithm, std::string_view label, View message);
  /// The last entry on disk; 0 for an empty log.
  uint64_t Last() const;
  /// The head after entry `sequence` (32 zero bytes for 0); none beyond Last().
  std::optional<Hash> HeadAt(uint64_t sequence) const;
  /// Entries from `from` (at least 1), at most `count` and kReadMax, up to Last(),
  /// with the head before the first one. None if `from` is beyond Last().
  std::optional<LogSegment> Read(uint64_t from, size_t count) const;

 private:
  bool ReadRecord(uint64_t sequence, LogEntry& entry, Hash& head) const;
  int fd_ = -1;
  std::array<uint8_t, 16> machine_{};
  mutable std::mutex mutex_;
  std::condition_variable synced_;
  uint64_t written_ = 0;  // the last record written
  uint64_t durable_ = 0;  // the last record known to be on disk
  Hash head_{};           // the head after `written_`
  bool syncing_ = false;
  bool failed_ = false;
};
}  // namespace fortis::keys
