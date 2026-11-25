#pragma once
#include "file_descriptor.h"
#include <cerrno>
#include <string>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>
#include <unistd.h>

namespace fortis::host {
/** Return a successful POSIX result or throw system_error with the saved errno. */
inline int Check(int value, const char* operation) {
  if (value < 0) throw std::system_error(errno, std::generic_category(), operation);
  return value;
}
// Host tools and guest-compatible application code share the same close/move contract.
using FileDescriptor = base::FileDescriptor;
/** Write every byte, retrying EINTR; throw on an error or a zero-progress write.
 * The descriptor and byte region are borrowed for this synchronous call.
 */
inline void WriteAll(int fd, const void* data, size_t size) {
  const auto* bytes = static_cast<const char*>(data);
  while (size) {
    const ssize_t written = ::write(fd, bytes, size);
    if (written < 0 && errno == EINTR) continue;
    if (written < 0) Check(-1, "write");
    if (written == 0) throw std::runtime_error("write made no progress");
    bytes += written;
    size -= static_cast<size_t>(written);
  }
}
/** Replace the process with a nonempty argv command using PATH lookup.
 * @throws std::system_error if execvp fails; successful execution never returns.
 * Command strings remain alive until execvp has consumed the argument array.
 */
[[noreturn]] inline void Execute(std::vector<std::string>& command) {
  std::vector<char*> arguments;
  arguments.reserve(command.size() + 1);
  for (auto& value : command) arguments.push_back(value.data());
  arguments.push_back(nullptr);
  ::execvp(arguments.front(), arguments.data());
  throw std::system_error(errno, std::generic_category(), "exec");
}
}  // namespace fortis::host
