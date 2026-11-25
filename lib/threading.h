#pragma once

#include "exception_boundary.h"

#include <pthread.h>
#include <atomic>
#include <new>
#include <type_traits>
#include <utility>
#include <stddef.h>
#include <cstddef>
#include <time.h>

// The shared concurrency primitives: one mutex, two scoped locks, one
// condition variable and one joinable thread owner, all thin wrappers over
// plain pthreads (the guest runs musl's pthreads on Unikraft). No dynamic
// allocation. Exceptions are contained at the thread trampoline.
//
// Static initialization. Mutex and ConditionVariable have constexpr
// constructors and trivial destructors: a global, a static local or a member
// of a constant-initialized object stays constant-initialized, exactly like
// `pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER`, with no dynamic initializer
// and no atexit entry. They are therefore never destroyed (a default-attribute
// pthread mutex or condition variable holds no resource to release). A mutex
// whose owner initializes and destroys it explicitly (pthread_mutex_init /
// pthread_mutex_destroy) stays a pthread_mutex_t; the scoped locks below
// accept either kind.
//
// A scoped lock records whether pthread_mutex_lock succeeded and unlocks only
// then. Locking a valid default mutex cannot fail, so code that never looked
// at the result behaves as it did with a bare lock/unlock pair.
//
// Only default-attribute mutexes exist in this codebase (no recursive or
// errorcheck mutex), so locking one twice from a thread deadlocks as before.
namespace fortis::base {

class Mutex {
 public:
  constexpr Mutex() = default;
  Mutex(const Mutex&) = delete;
  Mutex& operator=(const Mutex&) = delete;

  // True when the mutex is now held by the caller.
  bool Lock() { return pthread_mutex_lock(&native_) == 0; }
  // True when the mutex was free and is now held by the caller.
  bool TryLock() { return pthread_mutex_trylock(&native_) == 0; }
  void Unlock() { pthread_mutex_unlock(&native_); }

  // BasicLockable / Lockable for std::lock_guard and std::unique_lock.
  void lock() { (void)Lock(); }
  bool try_lock() { return TryLock(); }
  void unlock() { Unlock(); }

  pthread_mutex_t* native() { return &native_; }

 private:
  pthread_mutex_t native_ = PTHREAD_MUTEX_INITIALIZER;
};

// Holds a mutex for exactly one scope. The critical section is the lifetime of
// the object; when the section must end before the scope does, use an inner
// block or a UniqueLock.
class LockGuard {
 public:
  explicit LockGuard(Mutex& mutex) : LockGuard(*mutex.native()) {}
  explicit LockGuard(pthread_mutex_t& mutex) : mutex_(&mutex), locked_(pthread_mutex_lock(mutex_) == 0) {}
  ~LockGuard() {
    if (locked_) pthread_mutex_unlock(mutex_);
  }
  LockGuard(const LockGuard&) = delete;
  LockGuard& operator=(const LockGuard&) = delete;

  // False only when pthread_mutex_lock failed (an invalid mutex): the caller
  // does not hold the mutex and the destructor will not unlock it.
  bool locked() const { return locked_; }

 private:
  pthread_mutex_t* mutex_;
  bool locked_;
};

// Selects the UniqueLock constructor that takes the mutex only if it is free.
struct TryToLock {};
inline constexpr TryToLock kTryToLock{};

// A scoped lock that can be released and re-taken inside its scope: for a
// critical section that ends before a call-out (I/O, a callback, a provider
// request) or an early return, and for condition-variable waits. The
// destructor unlocks only if the lock is held at that point.
class UniqueLock {
 public:
  explicit UniqueLock(Mutex& mutex) : UniqueLock(*mutex.native()) {}
  explicit UniqueLock(pthread_mutex_t& mutex) : mutex_(&mutex), locked_(pthread_mutex_lock(mutex_) == 0) {}
  // Does not block: locked() tells whether the mutex was free and is now held.
  UniqueLock(Mutex& mutex, TryToLock) : UniqueLock(*mutex.native(), kTryToLock) {}
  UniqueLock(pthread_mutex_t& mutex, TryToLock) : mutex_(&mutex), locked_(pthread_mutex_trylock(mutex_) == 0) {}
  ~UniqueLock() {
    if (locked_) pthread_mutex_unlock(mutex_);
  }
  UniqueLock(const UniqueLock&) = delete;
  UniqueLock& operator=(const UniqueLock&) = delete;

  // Re-takes a lock released by Unlock(). True when the mutex is held.
  bool Lock() {
    if (!locked_) locked_ = pthread_mutex_lock(mutex_) == 0;
    return locked_;
  }
  // Ends the critical section now; a second call does nothing.
  void Unlock() {
    if (!locked_) return;
    locked_ = false;
    pthread_mutex_unlock(mutex_);
  }
  bool locked() const { return locked_; }
  pthread_mutex_t* native() const { return mutex_; }

 private:
  pthread_mutex_t* mutex_;
  bool locked_;
};

// A default-attribute condition variable. Timed waits take an absolute
// CLOCK_REALTIME deadline, the convention of every existing wait in the
// server (the modules build it with their own `realtime_after_ms` helpers).
// As with pthreads, a wait can wake spuriously: re-test the predicate.
class ConditionVariable {
 public:
  constexpr ConditionVariable() = default;
  ConditionVariable(const ConditionVariable&) = delete;
  ConditionVariable& operator=(const ConditionVariable&) = delete;

  // `lock` must be held; it is released while waiting and held on return.
  void Wait(UniqueLock& lock) { pthread_cond_wait(&native_, lock.native()); }
  // Returns 0 when woken, ETIMEDOUT once `realtime_deadline` has passed.
  int WaitUntil(UniqueLock& lock, const timespec& realtime_deadline) {
    return pthread_cond_timedwait(&native_, lock.native(), &realtime_deadline);
  }
  // For a caller that already holds this mutex through another scoped guard.
  void WaitLocked(Mutex& mutex) { pthread_cond_wait(&native_, mutex.native()); }
  int WaitUntilLocked(Mutex& mutex, const timespec& deadline) {
    return pthread_cond_timedwait(&native_, mutex.native(), &deadline);
  }
  void Signal() { pthread_cond_signal(&native_); }
  void Broadcast() { pthread_cond_broadcast(&native_); }

  pthread_cond_t* native() { return &native_; }

 private:
  pthread_cond_t native_ = PTHREAD_COND_INITIALIZER;
};

/** Bounded inline pthread handle for static-storage components.
 * Trivial destruction preserves startup/exit order: callers must stop/wake and
 * Join before destroying dependencies. Captures borrow owners through Join;
 * they must fit four pointers, have fundamental alignment, trivial destruction
 * and nonthrowing capture construction. Callback exceptions retain FatalBoundary.
 * No allocation occurs. Start/Join/native are owner-serialized; started and
 * IsCurrent permit concurrent observation. A failed/self join retains ownership.
 */
class ThreadHandle final {
 public:
  constexpr ThreadHandle() = default;
  ThreadHandle(const ThreadHandle&) = delete;
  ThreadHandle& operator=(const ThreadHandle&) = delete;

  template <typename Callable>
  bool Start(Callable&& callable, size_t stack_bytes = 0) {
    if (!stack_bytes) return StartWithAttributes(std::forward<Callable>(callable), nullptr);
    pthread_attr_t attributes;
    if (pthread_attr_init(&attributes) != 0) return false;
    const bool ok = pthread_attr_setstacksize(&attributes, stack_bytes) == 0 &&
                    StartWithAttributes(std::forward<Callable>(callable), &attributes);
    pthread_attr_destroy(&attributes);
    return ok;
  }

  // Retains callers' existing attribute initialization and failure ordering.
  template <typename Callable>
  bool StartWithAttributes(Callable&& callable, const pthread_attr_t* attributes) {
    using Fn = std::decay_t<Callable>;
    static_assert(sizeof(Fn) <= sizeof(callable_), "thread capture exceeds inline storage");
    static_assert(alignof(Fn) <= alignof(std::max_align_t), "thread capture alignment");
    static_assert(std::is_trivially_destructible_v<Fn>, "thread captures must borrow their owners");
    static_assert(std::is_nothrow_constructible_v<Fn, Callable&&>, "thread capture must not throw");
    if (started_) return false;
    new (callable_) Fn(std::forward<Callable>(callable));
    invoke_ = [](void* storage) { (*static_cast<Fn*>(storage))(); };
    const bool started = pthread_create(&thread_, attributes, Trampoline, this) == 0;
    started_.store(started, std::memory_order_release);
    return started;
  }

  template <typename T>
  bool Start(void (*entry)(T*), T* context, size_t stack_bytes = 0) {
    return Start([entry, context] { entry(context); }, stack_bytes);
  }

  // Migration bridge for C-shaped entries. The typed callable is still owned
  // by this handle, and the only pthread entry is the shared fatal boundary.
  template <auto Entry, typename Context>
  bool StartEntry(Context context, const pthread_attr_t* attributes = nullptr) {
    return StartWithAttributes([context] { (void)Entry(context); }, attributes);
  }

  /** Join from an external owner; true also means already idle.
   * Start and Join require external serialization; destruction requires a
   * completed join. A self-join or OS failure returns false and retains the
   * callable/thread ownership. No exception or detached execution is introduced.
   */
  bool Join() {
    if (IsCurrent()) return false;
    if (!started_.load(std::memory_order_acquire)) return true;
    if (pthread_join(thread_, nullptr) != 0) return false;
    started_.store(false, std::memory_order_release);
    return true;
  }
  /// Concurrent observation; may remain false until Start returns successfully.
  bool started() const { return started_.load(std::memory_order_acquire); }
  /// Borrowed pthread ID, only after successful Start and before successful Join.
  /// Never detach or join this ID externally; the handle retains ownership.
  pthread_t native() const { return thread_; }
  /// Safe inside the callback even before Start has returned to its caller.
  bool IsCurrent() const { return current_ == this; }

 private:
  static void* Trampoline(void* raw) noexcept {
    auto* self = static_cast<ThreadHandle*>(raw);
    const auto* previous = std::exchange(current_, self);
    FatalBoundary("Thread::Trampoline", [&] { self->invoke_(self->callable_); });
    current_ = previous;
    return nullptr;
  }
  inline static thread_local const ThreadHandle* current_ = nullptr;
  pthread_t thread_{};
  alignas(std::max_align_t) unsigned char callable_[4 * sizeof(void*)]{};
  void (*invoke_)(void*) = nullptr;
  std::atomic<bool> started_{false};
};

/** Scoped thread ownership by composition, never convertible to ThreadHandle.
 * Stop/wake the component before joining or destruction; the owner and borrowed
 * captures must not be destroyed on the callback thread. Static-storage owners
 * use ThreadHandle with explicit shutdown instead. No heap or virtual dispatch.
 */
class Thread final {
 public:
  constexpr Thread() = default;
  ~Thread() { (void)handle_.Join(); }
  Thread(const Thread&) = delete;
  Thread& operator=(const Thread&) = delete;
  template <typename Callable>
  bool Start(Callable&& callable, size_t stack_bytes = 0) {
    return handle_.Start(std::forward<Callable>(callable), stack_bytes);
  }
  template <typename T>
  bool Start(void (*entry)(T*), T* context, size_t stack_bytes = 0) {
    return handle_.Start(entry, context, stack_bytes);
  }
  template <typename Callable>
  bool StartWithAttributes(Callable&& callable, const pthread_attr_t* attributes) {
    return handle_.StartWithAttributes(std::forward<Callable>(callable), attributes);
  }
  template <auto Entry, typename Context>
  bool StartEntry(Context context, const pthread_attr_t* attributes = nullptr) {
    return handle_.template StartEntry<Entry>(context, attributes);
  }
  bool Join() { return handle_.Join(); }
  bool started() const { return handle_.started(); }
  pthread_t native() const { return handle_.native(); }
  bool IsCurrent() const { return handle_.IsCurrent(); }

 private:
  ThreadHandle handle_;
};

// The resolver context has its own reference-counted lifetime. No callable
// borrows a temporary ThreadHandle. Preserve create-then-detach ordering.
template <auto Entry, typename Context>
bool StartDetached(Context* context) {
  pthread_t thread{};
  if (pthread_create(&thread, nullptr, FatalCallback<Entry>, context) != 0) return false;
  pthread_detach(thread);
  return true;
}

}  // namespace fortis::base
