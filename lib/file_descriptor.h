#pragma once

#include <cerrno>
#include <utility>
#include <unistd.h>

namespace fortis::base {
/** Exclusive POSIX descriptor ownership for native and guest C interoperability.
 * There is no standard C++ descriptor owner. No allocation or exceptions occur.
 * get() borrows until reset, release, move or destruction; release transfers.
 * Cleanup closes once without retrying EINTR, preserving the caller's errno.
 * Operations on one owner require external synchronization. The descriptor's
 * I/O concurrency rules remain those of the underlying socket/file API.
 */
class FileDescriptor {
 public:
  /// Adopt a descriptor; any negative value denotes an empty owner.
  explicit FileDescriptor(int value = -1) noexcept : value_(value < 0 ? -1 : value) {}
  ~FileDescriptor() { reset(); }
  FileDescriptor(const FileDescriptor&) = delete;
  FileDescriptor& operator=(const FileDescriptor&) = delete;
  FileDescriptor(FileDescriptor&& other) noexcept : value_(other.release()) {}
  FileDescriptor& operator=(FileDescriptor&& other) noexcept {
    if (this != &other) reset(other.release());
    return *this;
  }
  /// Borrow; never close or adopt this value while the owner retains it.
  int get() const& noexcept { return value_; }
  int get() const&& = delete;
  /// Transfer ownership and become empty. No close is performed.
  [[nodiscard]] int release() noexcept { return std::exchange(value_, -1); }
  /** Adopt replacement after closing the prior descriptor; self-reset is a no-op.
   * Cleanup ignores close errors: retrying can close a reused descriptor.
   * The owner must not be destroyed from a concurrently executing I/O callback.
   */
  void reset(int replacement = -1) noexcept {
    if (replacement < 0) replacement = -1;
    if (value_ == replacement) return;
    const int previous = std::exchange(value_, replacement);
    if (previous >= 0) {
      const int saved = errno;
      (void)::close(previous);
      errno = saved;
    }
  }

 private:
  int value_;
};
}  // namespace fortis::base
