#pragma once

#include <utility>
#include <optional>
#include <memory>
#include <type_traits>
#include "ownership.h"

#include <stdint.h>
#include <stdlib.h>

// Status and Result<T>: the return types of an operation that can fail for a
// reason the caller only reports or branches on coarsely.
//
//   fortis::base::Status Start();                       // fallible, no value
//   fortis::base::Result<std::unique_ptr<T, fortis::base::ObjectDeleter<T>>> Create(); // fallible construction
//
// A Status is a code and a message. The message is a string with static
// storage duration (a literal): Status never copies or frees it, so it is two
// words wide, trivially copyable and safe to return from anywhere. Detail
// that varies per failure (an errno, a size) belongs in the log line at the
// point of failure, not in the Status.
//
// A domain outcome is not a Status. An enum whose values the caller treats
// as different results (found / missing / stale, an HTTP mapping, a provider
// verdict) stays its own enum; Status replaces `bool` + an out-parameter and
// enums that only ever meant "ok or one of a few generic errors".
//
// Inline value/error storage; constructing the result itself does not allocate.
namespace fortis::base {

enum class StatusCode : uint8_t {
  kOk = 0,
  // The caller passed something unusable (a null, an out-of-range value).
  kInvalidArgument,
  // The object is not in a state that allows the call (already started, not
  // started, a dependency missing).
  kFailedPrecondition,
  kNotFound,
  kAlreadyExists,
  // Memory, a table or a queue is full.
  kResourceExhausted,
  // A dependency (thread, lease, peer, provider) could not be reached or
  // started; trying again later may work.
  kUnavailable,
  // A read, write or sync failed.
  kIoError,
  // Stored or received bytes do not parse.
  kDataLoss,
  kDeadlineExceeded,
  kCancelled,
  // An invariant broke.
  kInternal,
};

inline const char* StatusCodeName(StatusCode code) {
  switch (code) {
    case StatusCode::kOk: return "ok";
    case StatusCode::kInvalidArgument: return "invalid argument";
    case StatusCode::kFailedPrecondition: return "failed precondition";
    case StatusCode::kNotFound: return "not found";
    case StatusCode::kAlreadyExists: return "already exists";
    case StatusCode::kResourceExhausted: return "resource exhausted";
    case StatusCode::kUnavailable: return "unavailable";
    case StatusCode::kIoError: return "I/O error";
    case StatusCode::kDataLoss: return "data loss";
    case StatusCode::kDeadlineExceeded: return "deadline exceeded";
    case StatusCode::kCancelled: return "cancelled";
    case StatusCode::kInternal: return "internal";
  }
  return "internal";
}

class [[nodiscard]] Status {
 public:
  // Ok.
  constexpr Status() = default;
  // `message` must have static storage duration; null means the code's name.
  constexpr Status(StatusCode code, const char* message) : message_(message), code_(code) {}
  constexpr explicit Status(StatusCode code) : code_(code) {}

  static constexpr Status Ok() { return Status(); }

  constexpr bool ok() const { return code_ == StatusCode::kOk; }
  constexpr StatusCode code() const { return code_; }
  // Never null: the message given, else the code's name.
  const char* message() const { return message_ ? message_ : StatusCodeName(code_); }

 private:
  const char* message_ = nullptr;
  StatusCode code_ = StatusCode::kOk;
};

constexpr bool operator==(const Status& left, StatusCode right) { return left.code() == right; }
constexpr bool operator!=(const Status& left, StatusCode right) { return left.code() != right; }

/** Move-only value-or-error owner with inline std::optional storage.
 * No allocation is performed by Result itself. T's construction, copying and
 * moving may throw; noexcept follows T. Failed move assignment leaves an
 * explicit internal failure, with T's own basic guarantee governing the source.
 * value() borrows only from retained lvalues; TakeValue returns an owned value
 * and leaves T engaged in its moved-from state. Invalid access aborts, preserving
 * existing fatal policy. Status messages must have static lifetime. Concurrent
 * mutation or moving the same Result requires external synchronization.
 */
template <typename T>
class [[nodiscard]] Result {
  static_assert(std::is_nothrow_destructible_v<T>, "Result cleanup must not throw");

 public:
  // Success. Implicit, so `return value;` works.
  Result(T&& value) : value_(std::move(value)) {}
  Result(const T& value) : value_(value) {}
  // Failure. Implicit, so `return Status(...)` works. An ok Status carries no
  // value and is therefore recorded as kInternal.
  Result(const Status& status)
      : status_(status.ok() ? Status(StatusCode::kInternal, "Result built from an ok Status") : status) {}

  // Fallible value moves intentionally propagate; noexcept follows T's contract.
  // NOLINTNEXTLINE(bugprone-exception-escape)
  Result(Result&&) noexcept(std::is_nothrow_move_constructible_v<T>) = default;
  // Basic guarantee: failed reconstruction leaves an explicit failure, never
  // an empty success. Supports movable but non-assignable value types too.
  // NOLINTNEXTLINE(bugprone-exception-escape)
  Result& operator=(Result&& other) noexcept(std::is_nothrow_move_constructible_v<T>) {
    if (this != &other) {
      value_.reset();
      status_ = Status(StatusCode::kInternal, "Result move interrupted");
      if (other.value_) value_.emplace(std::move(*other.value_));
      status_ = other.status_;
    }
    return *this;
  }
  Result(const Result&) = delete;
  Result& operator=(const Result&) = delete;
  ~Result() = default;

  bool ok() const { return value_.has_value(); }
  explicit operator bool() const { return value_.has_value(); }
  // Ok when a value is held.
  Status status() const { return status_; }

  /// Borrow only from a retained Result; TakeValue transfers from temporaries.
  T& value() & {
    if (!value_.has_value()) abort();
    return *value_;
  }
  const T& value() const& {
    if (!value_.has_value()) abort();
    return *value_;
  }
  T& value() && = delete;
  const T& value() const&& = delete;
  // Moves the value out; the Result still holds the moved-from T.
  [[nodiscard]] T TakeValue() {
    if (!value_.has_value()) abort();
    return std::move(*value_);
  }
  // The value moved out, or `fallback` when this is a failure. For a Result
  // that is going away: `Create(options).ValueOr(nullptr)`, or
  // `std::move(result).ValueOr(...)` to say that a named one is given up.
  [[nodiscard]] T ValueOr(T fallback) && { return value_.has_value() ? std::move(*value_) : std::move(fallback); }

 private:
  std::optional<T> value_;
  Status status_;
};

}  // namespace fortis::base
