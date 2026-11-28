#pragma once
// Memory for secret keys (docs/fortis-did.md, section 13.2): its own pages,
// locked so they are never swapped to disk, left out of core dumps, and
// wiped before they are given back.
#include <cstddef>
#include <cstdint>
#include <span>

namespace fortis::keys {
class SecretBytes {
 public:
  SecretBytes() = default;
  /// Zero-filled. Throws std::bad_alloc if the pages cannot be had. Locking is
  /// best effort: Locked() says whether it worked (RLIMIT_MEMLOCK can refuse).
  explicit SecretBytes(size_t size);
  ~SecretBytes();
  SecretBytes(SecretBytes&& other) noexcept;
  SecretBytes& operator=(SecretBytes&& other) noexcept;
  SecretBytes(const SecretBytes&) = delete;
  SecretBytes& operator=(const SecretBytes&) = delete;

  std::span<uint8_t> Bytes() noexcept { return {data_, size_}; }
  std::span<const uint8_t> Bytes() const noexcept { return {data_, size_}; }
  size_t size() const noexcept { return size_; }
  bool Locked() const noexcept { return locked_; }

 private:
  void Release() noexcept;
  uint8_t* data_ = nullptr;
  size_t size_ = 0;
  size_t mapped_ = 0;
  bool locked_ = false;
};

/// Overwrite, in a way the compiler may not remove.
void Wipe(std::span<uint8_t> bytes) noexcept;
/// No core dumps of this process, and no debugger from other processes of its user.
bool ProtectProcess() noexcept;
/** Lock every page of the process, now and later, so no copy of a secret on
 * a stack or in a library's buffer reaches swap. Done only when the locked
 * memory limit is unlimited: with a limit, later allocations would fail
 * instead. The orchestrator gives the key service that limit. */
bool LockAllMemory() noexcept;
}  // namespace fortis::keys
