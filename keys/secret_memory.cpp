#include "secret_memory.h"

#include <mbedtls/platform_util.h>

#include <new>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#include <utility>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

namespace fortis::keys {
void Wipe(std::span<uint8_t> bytes) noexcept {
  if (!bytes.empty()) mbedtls_platform_zeroize(bytes.data(), bytes.size());
}

bool ProtectProcess() noexcept {
  const rlimit none{0, 0};
  bool ok = ::setrlimit(RLIMIT_CORE, &none) == 0;
#if defined(__linux__)
  ok = ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 && ok;
#endif
  return ok;
}

bool LockAllMemory() noexcept {
  rlimit limit{};
  if (::getrlimit(RLIMIT_MEMLOCK, &limit) != 0 || limit.rlim_cur != RLIM_INFINITY) return false;
  return ::mlockall(MCL_CURRENT | MCL_FUTURE) == 0;
}

SecretBytes::SecretBytes(size_t size) : size_(size) {
  const auto page = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
  mapped_ = (size + page - 1) / page * page;
  if (mapped_ == 0) mapped_ = page;
  void* p = ::mmap(nullptr, mapped_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (p == MAP_FAILED) throw std::bad_alloc();
  data_ = static_cast<uint8_t*>(p);
  locked_ = ::mlock(data_, mapped_) == 0;
#if defined(MADV_DONTDUMP)
  (void)::madvise(data_, mapped_, MADV_DONTDUMP);
#endif
}

void SecretBytes::Release() noexcept {
  if (!data_) return;
  mbedtls_platform_zeroize(data_, mapped_);
  if (locked_) (void)::munlock(data_, mapped_);
  (void)::munmap(data_, mapped_);
  data_ = nullptr;
  size_ = mapped_ = 0;
  locked_ = false;
}

SecretBytes::~SecretBytes() { Release(); }

SecretBytes::SecretBytes(SecretBytes&& other) noexcept
    : data_(std::exchange(other.data_, nullptr)),
      size_(std::exchange(other.size_, 0)),
      mapped_(std::exchange(other.mapped_, 0)),
      locked_(std::exchange(other.locked_, false)) {}

SecretBytes& SecretBytes::operator=(SecretBytes&& other) noexcept {
  if (this != &other) {
    Release();
    data_ = std::exchange(other.data_, nullptr);
    size_ = std::exchange(other.size_, 0);
    mapped_ = std::exchange(other.mapped_, 0);
    locked_ = std::exchange(other.locked_, false);
  }
  return *this;
}
}  // namespace fortis::keys
