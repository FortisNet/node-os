#pragma once

#include <stddef.h>
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <errno.h>

#include <memory>
#include <span>
#include <limits>
#include <new>
#include <type_traits>
#include <utility>

// Standard C++ byte-array storage owned by std::unique_ptr. Object factories
// construct into this storage and use a destructor-aware deleter. Allocation
// failure returns nullptr; a throwing constructor leaves the storage guarded.
namespace fortis::base {

// Releases byte-array storage; constructed objects need ObjectDeleter instead.
// Only pointers originating in AllocateStorage (or released from those owners)
// may be adopted. External C allocations use their own matching deallocator.
struct StorageDeleter {
  void operator()(void* block) const noexcept { std::default_delete<std::byte[]>{}(static_cast<std::byte*>(block)); }
};

/** Allocate unconstructed, suitably aligned byte storage under a standard owner.
 * @return An exclusive owner, or nullptr with errno = ENOMEM on failure.
 * @pre T has no extended alignment beyond max_align_t. The byte count includes
 * all array elements; constructed objects require an ObjectDeleter instead.
 * The owner is acquired before returning or transferring any storage.
 */
template <typename T>
[[nodiscard]] std::unique_ptr<T, StorageDeleter> AllocateStorage(size_t bytes) noexcept {
  using Element = std::remove_extent_t<T>;
  if constexpr (!std::is_void_v<Element>)
    static_assert(alignof(Element) <= alignof(max_align_t), "byte storage alignment");
  if (bytes > static_cast<size_t>(std::numeric_limits<ptrdiff_t>::max())) {
    errno = ENOMEM;
    return nullptr;
  }
  std::unique_ptr<std::byte[]> storage(new (std::nothrow) std::byte[bytes]);
  if (!storage) {
    errno = ENOMEM;
    return nullptr;
  }
  return std::unique_ptr<T, StorageDeleter>(reinterpret_cast<Element*>(storage.release()));
}

template <typename T>
[[nodiscard]] std::unique_ptr<T, StorageDeleter> AllocateZeroedStorage(size_t count, size_t width) noexcept {
  if (width && count > static_cast<size_t>(std::numeric_limits<ptrdiff_t>::max()) / width) {
    errno = ENOMEM;
    return nullptr;
  }
  const size_t bytes = count * width;
  auto storage = AllocateStorage<T>(bytes);
  if (storage) std::fill_n(reinterpret_cast<std::byte*>(storage.get()), bytes, std::byte{});
  return storage;
}

// Owns a C-compatible array and each individually allocated string. Null slots
// allow a partially populated array to unwind safely.
struct CStringArrayDeleter {
  size_t count = 0;
  void operator()(char** strings) const noexcept {
    for (size_t i = 0; i < count; ++i) StorageDeleter{}(strings[i]);
    StorageDeleter{}(reinterpret_cast<void*>(strings));
  }
};

[[nodiscard]] inline std::unique_ptr<char* [], CStringArrayDeleter> AllocateCStringArray(size_t count) noexcept {
  auto storage = AllocateZeroedStorage<char*[]>(count, sizeof(char*));
  return {storage.release(), CStringArrayDeleter{count}};
}

// Grow or shrink raw, trivially copyable storage. The caller supplies its live
// byte count; capacity beyond that count is deliberately left uninitialized.
// Failure retains the old owner. Zero size explicitly releases it.
template <typename T>
bool ResizeStorage(std::unique_ptr<T, StorageDeleter>& storage, size_t live_bytes, size_t bytes) noexcept {
  static_assert(std::is_trivially_copyable_v<std::remove_extent_t<T>>,
                "resizing object storage requires trivially copyable elements");
  if (!bytes) {
    storage.reset();
    return true;
  }
  if (live_bytes && !storage) return false;
  auto replacement = AllocateStorage<T>(bytes);
  if (!replacement) return false;
  const size_t copied = std::min(live_bytes, bytes);
  if (copied) std::memcpy(replacement.get(), storage.get(), copied);
  storage.swap(replacement);
  return true;
}

// Constructs a T in owned byte storage as `T(args...)`. With no arguments
// the object is value-initialized. Returns nullptr on allocation failure; a
// throwing constructor releases its storage and propagates.
template <typename T, typename... Args>
[[nodiscard]] T* New(Args&&... args) {
  static_assert(alignof(T) <= alignof(max_align_t), "byte storage cannot align this type");
  auto storage = AllocateStorage<void>(sizeof(T));
  if (!storage) return nullptr;
  new (storage.get()) T(std::forward<Args>(args)...);
  return static_cast<T*>(storage.release());
}

// As New<T>() but default-initialized, like `new (storage) T`: members without
// an initializer are left indeterminate. For large scratch objects whose
// zero-fill would be wasted work.
template <typename T>
[[nodiscard]] T* NewDefaultInit() {
  static_assert(alignof(T) <= alignof(max_align_t), "byte storage cannot align this type");
  auto storage = AllocateStorage<void>(sizeof(T));
  if (!storage) return nullptr;
  new (storage.get()) T;
  return static_cast<T*>(storage.release());
}

// Runs the destructor and frees the block. Null-safe. `object` must be the
// pointer New returned (the complete object, not a base subobject).
template <typename T>
void Delete(T* object) noexcept {
  static_assert(sizeof(T), "Delete needs the complete type");
  static_assert(std::is_nothrow_destructible_v<T>, "Owned object cleanup must not throw");
  if (!object) return;
  std::destroy_at(object);
  StorageDeleter{}(const_cast<void*>(static_cast<const void*>(object)));
}

template <typename T>
struct ObjectDeleter {
  void operator()(T* object) const noexcept { Delete(object); }
};

// New<T> into std::unique_ptr with object destruction; empty on allocation failure.
template <typename T, typename... Args>
[[nodiscard]] std::unique_ptr<T, fortis::base::ObjectDeleter<T>> MakeUnique(Args&&... args) {
  return std::unique_ptr<T, fortis::base::ObjectDeleter<T>>(New<T>(std::forward<Args>(args)...));
}

/** Move-only bounded byte owner backed by standard C++ array storage.
 * Allocation returns empty on failure; contents are uninitialized unless zeroed.
 * Borrowed pointers/spans never extend storage lifetime. Copy before queueing
 * asynchronous work; concurrent mutation/move requires external synchronization.
 */
class Buffer {
 public:
  constexpr Buffer() = default;
  Buffer(Buffer&& other) noexcept : data_(std::move(other.data_)), size_(std::exchange(other.size_, 0)) {}
  Buffer& operator=(Buffer&& other) noexcept {
    if (this != &other) {
      data_ = std::move(other.data_);
      size_ = std::exchange(other.size_, 0);
    }
    return *this;
  }
  ~Buffer() = default;
  Buffer(const Buffer&) = delete;
  Buffer& operator=(const Buffer&) = delete;

  // Uninitialized or zeroed bytes; empty on allocation failure.
  [[nodiscard]] static Buffer Allocate(size_t size) { return Buffer(AllocateStorage<unsigned char>(size), size); }
  [[nodiscard]] static Buffer AllocateZeroed(size_t size) {
    return Buffer(AllocateZeroedStorage<unsigned char>(1, size), size);
  }
  // Adopts a block released by this storage family, never an external C buffer.
  [[nodiscard]] static Buffer Adopt(void* data, size_t size) {
    return Buffer(std::unique_ptr<unsigned char, StorageDeleter>(static_cast<unsigned char*>(data)), size);
  }

  /// Borrowed bytes: invalidated by reset, release, move, or destruction.
  /// Mutable access requires a mutable lvalue; no view of a temporary owner.
  unsigned char* data() & noexcept { return data_.get(); }
  const unsigned char* data() const& noexcept { return data_.get(); }
  unsigned char* data() && = delete;
  const unsigned char* data() const&& = delete;
  char* chars() & noexcept { return reinterpret_cast<char*>(data_.get()); }
  const char* chars() const& noexcept { return reinterpret_cast<const char*>(data_.get()); }
  char* chars() && = delete;
  const char* chars() const&& = delete;
  std::span<unsigned char> bytes() & noexcept { return {data_.get(), size_}; }
  std::span<const unsigned char> bytes() const& noexcept { return {data_.get(), size_}; }
  std::span<unsigned char> bytes() && = delete;
  std::span<const unsigned char> bytes() const&& = delete;
  size_t size() const { return size_; }
  explicit operator bool() const { return data_ != nullptr; }

  // Frees the block; the buffer is empty afterwards.
  void reset() {
    data_.reset();
    size_ = 0;
  }
  // Gives up ownership: the caller frees the returned block.
  [[nodiscard]] unsigned char* release() {
    unsigned char* data = data_.release();
    size_ = 0;
    return data;
  }

 private:
  Buffer(std::unique_ptr<unsigned char, StorageDeleter> data, size_t size)
      : data_(std::move(data)), size_(data_ ? size : 0) {}

  std::unique_ptr<unsigned char, StorageDeleter> data_;
  size_t size_ = 0;
};

}  // namespace fortis::base
