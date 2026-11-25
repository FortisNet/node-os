#pragma once

#include "log.h"

#include <exception>
#include <new>

namespace fortis::base {

// RTTI is disabled. Classify the exceptions we can handle by catch type;
// never allocate while reporting a failure (including an exhausted heap).
// Context and catch classification are trusted static labels. Never log what():
// provider exceptions can contain credentials, wallet contents or response bodies.
inline void LogBoundaryException(const char* context, const char* type) noexcept {
  LogError("exception", "%s: %s", context, type);
}

// Infrastructure cannot recover by silently losing its worker or by invoking
// a completion twice: callbacks may already have consumed their context.
// Request recovery belongs in Dispatch, before an exception reaches here.
template <typename Callable>
auto FatalBoundary(const char* context, Callable&& callable) noexcept -> decltype(callable()) {
  try {
    return callable();
  } catch (const std::bad_alloc&) {
    LogBoundaryException(context, "std::bad_alloc");
  } catch (const std::exception&) {
    LogBoundaryException(context, "std::exception");
  } catch (...) {
    LogBoundaryException(context, "unknown exception");
  }
  std::terminate();
}

// Only this noexcept frame is handed to C. Catching in a caller above a C
// frame is too late: guest C libraries have no exception unwind tables.
template <auto Callback>
struct CallbackBoundary;

template <typename Result, typename... Args, Result (*Callback)(Args...)>
struct CallbackBoundary<Callback> {
  static Result Invoke(Args... args) noexcept {
    return FatalBoundary(__PRETTY_FUNCTION__, [&]() -> Result { return Callback(args...); });
  }
};

template <auto Callback>
inline constexpr auto FatalCallback = &CallbackBoundary<Callback>::Invoke;

}  // namespace fortis::base
