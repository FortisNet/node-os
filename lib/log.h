#include <atomic>
#pragma once

#include "status.h"

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// The process logger: one line per call, written to stderr.
//
//   fortis::base::LogError("kv", "KV lock open failed: errno=%d", errno);
//   fortis::base::LogErrno(fortis::base::LogLevel::kError, "app", "bind/listen", errno);
//
// Text. A line on stderr is exactly the formatted message and one '\n': no
// timestamp, level or component prefix (the lines predate the logger and
// operators and replay tests match them verbatim). The level and the component
// tag travel with the record, for the threshold and for a LogSink.
//
// Threshold. A record is emitted when its level is at or above the process
// threshold in severity. The default (kDefaultLogLevel = info) emits error,
// warn and info; debug lines need FORTIS_LOG_LEVEL=debug. The environment is
// read by LoadNativeConfig (config/), never here: SetLogThreshold is the only
// input.
//
// Concurrency. Any thread may log. A line is formatted into a stack buffer
// (no allocation, no lock) and handed to the kernel in one write(), so lines
// from different threads never interleave. A line longer than
// kLogLineCapacity - 1 bytes is cut there (and still ends in '\n').
//
// Arguments are evaluated even when the level is below the threshold; guard
// an expensive argument with LogEnabled(level).
//
// No standard library, no allocation, no exceptions. The entry points take
// plain C strings and a printf format, so they keep their shape once a
// standard library is linked.
namespace fortis::base {

enum class LogLevel : uint8_t { kError = 0, kWarn = 1, kInfo = 2, kDebug = 3 };

inline constexpr LogLevel kDefaultLogLevel = LogLevel::kInfo;
// The longest line, including its '\n'.
inline constexpr size_t kLogLineCapacity = 1024;

// "error", "warn", "info" or "debug".
inline const char* LogLevelName(LogLevel level) {
  switch (level) {
    case LogLevel::kError: return "error";
    case LogLevel::kWarn: return "warn";
    case LogLevel::kInfo: return "info";
    case LogLevel::kDebug: return "debug";
  }
  return "error";
}

// The level a configuration value names: exactly "error", "warn", "info" or
// "debug" (lower case, no padding). Anything else is kInvalidArgument.
inline Result<LogLevel> ParseLogLevel(const char* text) {
  if (text) {
    for (uint8_t value = 0; value <= static_cast<uint8_t>(LogLevel::kDebug); ++value) {
      const LogLevel level = static_cast<LogLevel>(value);
      if (strcmp(text, LogLevelName(level)) == 0) return level;
    }
  }
  return Status(StatusCode::kInvalidArgument, "log level must be error, warn, info or debug");
}

// One log line as a sink sees it. `text` is the formatted message without the
// line's '\n', NUL-terminated, `length` bytes long; it lives only for the
// duration of the Write call.
struct LogRecord {
  LogLevel level;
  const char* component;
  const char* text;
  size_t length;
};

// Receives every emitted record (those that pass the threshold) in place of,
// or in addition to, stderr: the seam tests use to capture log lines. Write
// may be called from any thread, concurrently; an implementation locks its
// own state. As with the other base seams the method is not pure and the
// destructor is not virtual: sinks are never deleted through this interface.
class LogSink {
 public:
  // True when the sink consumed the record: nothing is written to stderr.
  // False (the base body) lets the line go to stderr as well.
  // A throwing sink is never retried: the logger reports its failure directly
  // on stderr and emits the original record there without propagating.
  virtual bool Write(const LogRecord& record) { (void)record; return false; }

 protected:
  constexpr LogSink() = default;
  ~LogSink() = default;
};

namespace log_internal {

// Process-wide state. Inline variables: one instance however many units
// include this header. Read and written with the atomic builtins only.
inline std::atomic<uint8_t> g_threshold{static_cast<uint8_t>(kDefaultLogLevel)};
inline std::atomic<LogSink*> g_sink{nullptr};

// strerror_r is `int (int, char*, size_t)` (POSIX: macOS, musl) or
// `char* (int, char*, size_t)` (glibc with _GNU_SOURCE, the g++ default).
// Overload resolution picks the matching reader. The POSIX form also fills
// the buffer when it fails (EINVAL for a number it does not know: "Unknown
// error: 999", the text perror prints), so only an empty buffer is replaced.
inline const char* ErrorText(int, const char* buffer) {
  return buffer[0] ? buffer : "Unknown error";
}
inline const char* ErrorText(const char* result, const char*) {
  return result ? result : "Unknown error";
}

// Writes `line[0, length)` to stderr: one write() unless the kernel takes
// only part of it or a signal interrupts the call.
inline void WriteStderr(const char* line, size_t length) noexcept {
  const int saved_errno = errno;
  size_t written = 0;
  while (written < length) {
    const ssize_t count = write(STDERR_FILENO, line + written, length - written);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) break;
    written += static_cast<size_t>(count);
  }
  errno = saved_errno;
}

// Emits the message in `line[0, length)`; `line` has room for one more byte
// after the terminator at line[length].
inline void Emit(LogLevel level, const char* component, char* line, size_t length) noexcept {
  if (LogSink* sink = (g_sink).load(std::memory_order_acquire)) {
    const LogRecord record{level, component ? component : "", line, length};
    try {
      if (sink->Write(record)) return;
    } catch (...) {
      // Logging must not interrupt a transaction between a failed append and
      // its recovery bookkeeping. Never recurse into the failing sink or copy
      // its exception message, even under allocation failure.
      static constexpr char failure[] = "logging failed: sink exception; falling back to stderr\n";
      WriteStderr(failure, sizeof(failure) - 1);
    }
  }
  line[length] = '\n';
  WriteStderr(line, length + 1);
}

}  // namespace log_internal

// The process threshold: the least severe level still emitted.
inline void SetLogThreshold(LogLevel level) {
  (log_internal::g_threshold).store(static_cast<uint8_t>(level), std::memory_order_relaxed);
}
inline LogLevel LogThreshold() {
  return static_cast<LogLevel>((log_internal::g_threshold).load(std::memory_order_relaxed));
}
// True when a record of `level` would be emitted now.
inline bool LogEnabled(LogLevel level) {
  return static_cast<uint8_t>(level) <= (log_internal::g_threshold).load(std::memory_order_relaxed);
}

// Installs `sink` (nullptr: stderr only) and returns the one installed before.
// The caller keeps the sink alive until it has installed another and no
// thread can still be inside Write.
inline LogSink* SetLogSink(LogSink* sink) {
  return (log_internal::g_sink).exchange(sink, std::memory_order_acq_rel);
}

// The formatting entry point the level helpers below forward to. errno is
// preserved across the call.
__attribute__((format(printf, 3, 0)))
inline void LogV(LogLevel level, const char* component, const char* format, va_list arguments) noexcept {
  if (!LogEnabled(level)) return;
  const int saved_errno = errno;
  // The message, its '\n' and (for a sink) its terminator.
  char line[kLogLineCapacity + 1];
  const int needed = vsnprintf(line, kLogLineCapacity, format, arguments);
  size_t length = 0;
  if (needed < 0) {
    // An encoding error in the arguments: say so rather than drop the line.
    static const char kUnformatted[] = "log line could not be formatted";
    memcpy(line, kUnformatted, sizeof(kUnformatted));
    length = sizeof(kUnformatted) - 1;
  } else {
    length = static_cast<size_t>(needed) < kLogLineCapacity - 1 ? static_cast<size_t>(needed)
                                                                : kLogLineCapacity - 1;
    line[length] = '\0';
  }
  log_internal::Emit(level, component, line, length);
  errno = saved_errno;
}

__attribute__((format(printf, 3, 4)))
inline void Log(LogLevel level, const char* component, const char* format, ...) noexcept {
  va_list arguments;
  va_start(arguments, format);
  LogV(level, component, format, arguments);
  va_end(arguments);
}

// A failure the operator must look at: something did not happen.
__attribute__((format(printf, 2, 3)))
inline void LogError(const char* component, const char* format, ...) noexcept {
  va_list arguments;
  va_start(arguments, format);
  LogV(LogLevel::kError, component, format, arguments);
  va_end(arguments);
}

// Degraded but handled: a refusal, a retry, a pause.
__attribute__((format(printf, 2, 3)))
inline void LogWarn(const char* component, const char* format, ...) noexcept {
  va_list arguments;
  va_start(arguments, format);
  LogV(LogLevel::kWarn, component, format, arguments);
  va_end(arguments);
}

// Normal operation worth a line: startup facts, job summaries.
__attribute__((format(printf, 2, 3)))
inline void LogInfo(const char* component, const char* format, ...) noexcept {
  va_list arguments;
  va_start(arguments, format);
  LogV(LogLevel::kInfo, component, format, arguments);
  va_end(arguments);
}

// Detail for diagnosis; not emitted at the default threshold.
__attribute__((format(printf, 2, 3)))
inline void LogDebug(const char* component, const char* format, ...) noexcept {
  va_list arguments;
  va_start(arguments, format);
  LogV(LogLevel::kDebug, component, format, arguments);
  va_end(arguments);
}

// perror(prefix) for the logger: "<prefix>: <strerror(error)>". Pass errno
// as `error` at the call site, before anything can overwrite it.
inline void LogErrno(LogLevel level, const char* component, const char* prefix, int error) noexcept {
  if (!LogEnabled(level)) return;
  char text[128];
  text[0] = '\0';
  const char* description = log_internal::ErrorText(strerror_r(error, text, sizeof(text)), text);
  Log(level, component, "%s: %s", prefix ? prefix : "", description);
}

// Logs a failed Status as "<context>: <message>" at error level; an ok
// Status logs nothing. For a boundary that reports and stops.
inline void LogStatus(const char* component, const char* context, const Status& status) noexcept {
  if (status.ok()) return;
  LogError(component, "%s: %s", context ? context : "", status.message());
}

}  // namespace fortis::base
