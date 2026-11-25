#pragma once
#include "file_descriptor.h"
#include "sandbox_wire.h"
#include <string>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace fortis::compat::sandbox {
/** Owned local-control reply; payload is sanitized job status or a fixed error.
 * Accepted means durable acceptance, not application readiness or success.
 */
struct Reply {
  codec::sandbox::ReplyCode code = codec::sandbox::ReplyCode::Unavailable;
  std::string payload;
};
/** Authenticate a root broker and make one bounded local request (5s total).
 * Borrows immutable inputs only for this synchronous call; replies own bytes.
 * Thread-safe for distinct calls; throws on auth/transport/protocol failures.
 * No retries: a lost start acknowledgement may follow durable acceptance.
 * Retry the same id/spec to retrieve its idempotent result. Linux native only.
 */
Reply Request(std::string_view socket, codec::sandbox::Operation operation, std::string_view payload);
using Deadline = std::chrono::steady_clock::time_point;
/** Native Linux IPC only; guest/non-Linux implementations refuse execution.
 * All I/O borrows the descriptor/buffer synchronously and shares one absolute
 * monotonic deadline. EINTR/partial I/O never extend it; errors throw runtime_error.
 * The caller owns descriptors and must serialize I/O on each connection.
 */
void Receive(int fd, void* output, size_t size, Deadline deadline);
/// Send exactly size bytes with MSG_NOSIGNAL; see Receive for ownership/time contracts.
void Transmit(int fd, const void* input, size_t size, Deadline deadline);
/// Require peer half-close, rejecting trailing frames/bytes before dispatch.
void EndOfMessage(int fd, Deadline deadline);
/// Kernel-authenticated effective UID captured at connection establishment. Throws if unavailable.
uint32_t PeerUid(int fd);
/** Connect to an absolute pathname in root-owned, non-writable parent directories.
 * Socket must be mode 0600, owned by this process's effective UID, with a root
 * peer (SO_PEERCRED). Returns exclusive ownership; no payload is sent before auth.
 * No abstract namespace, pathname traversal, symlinks or UID fallback is accepted.
 */
base::FileDescriptor Connect(std::string_view path, Deadline deadline);
}  // namespace fortis::compat::sandbox
