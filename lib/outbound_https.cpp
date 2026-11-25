#include "ownership.h"
#include <memory>
#include <type_traits>
#include <atomic>
#include <new>
#include "exception_boundary.h"
#include "outbound_https.h"

#include "threading.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <mbedtls/entropy.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#if !defined(MBEDTLS_THREADING_C) || !defined(MBEDTLS_THREADING_PTHREAD)
#error "Concurrent provider TLS requires the Mbed TLS pthread threading backend"
#endif

#ifdef FORTIS_UNIKRAFT
extern "C" int mbedtls_hardware_poll(void*, unsigned char* output,
                                     size_t length, size_t* written) noexcept {
  if (!written) return -1;
  *written = 0;
  while (*written < length) {
    const size_t requested = length - *written > 32 ? 32 : length - *written;
    const ssize_t count = getrandom(output + *written, requested, 0);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return -1;
    *written += static_cast<size_t>(count);
  }
  return 0;
}
extern "C" int lwip_getaddrinfo(const char*, const char*, const struct addrinfo*,
                                struct addrinfo**);
extern "C" void lwip_freeaddrinfo(struct addrinfo*);
#endif

namespace fortis::http {

namespace {
constexpr size_t kMaxHost = 253;
// A 50-mint Jupiter /price/v3 request (44-byte mints joined by %2C) is 2,361
// bytes and is sent whole. Keep one fixed transport cap.
constexpr size_t kMaxPath = 8192;
constexpr size_t kMaxResponseBody = kOutboundMaxResponseBytes;
constexpr off_t kMaxCaBundleBytes = 1024 * 1024;
constexpr size_t kMaxHeaderBytes = 16 * 1024;
constexpr size_t kMaxAddresses = 8;
constexpr size_t kCaCacheEntries = 4;
constexpr size_t kTlsReadBufferBytes = 4096;

fortis::base::Mutex g_resolvers_mutex;
unsigned g_resolvers = 0;
fortis::base::Mutex g_ca_cache_mutex;
pthread_once_t g_psa_init_once = PTHREAD_ONCE_INIT;
psa_status_t g_psa_init_status = PSA_ERROR_GENERIC_ERROR;

void initialize_psa_crypto() { g_psa_init_status = psa_crypto_init(); }

struct CachedCa {
  bool used;
  char path[1024];
  mbedtls_x509_crt chain;
};
// Entries and their parsed chains are immutable after publication and live for
// process lifetime, so SSL sessions may safely share the trust chain.
CachedCa g_ca_cache[kCaCacheEntries]{};

int64_t monotonic_ms() {
  timespec value{};
  clock_gettime(CLOCK_MONOTONIC, &value);
  return int64_t(value.tv_sec) * 1000 + value.tv_nsec / 1000000;
}

// The calling thread's OutboundRequest::cancel while a request runs (every
// wait below happens on that thread, mbed TLS callbacks included).
thread_local const std::atomic<int>* active_cancel = nullptr;
constexpr int kCancelPollMs = 50;

bool cancel_raised() { return active_cancel && (*active_cancel).load(std::memory_order_acquire) != 0; }

// Clears the thread's flag on every return path of OutboundHttpsRequest.
struct CancelScope {
  explicit CancelScope(const std::atomic<int>* flag) { active_cancel = flag; }
  ~CancelScope() { active_cancel = nullptr; }
  CancelScope(const CancelScope&) = delete;
  CancelScope& operator=(const CancelScope&) = delete;
};

// A raised cancel flag reads as an expired deadline, so every bounded step
// ends the way a timeout does.
int remaining_ms(int64_t deadline) {
  if (cancel_raised()) return 0;
  const int64_t remaining = deadline - monotonic_ms();
  if (remaining <= 0) return 0;
  return remaining > 2147483647 ? 2147483647 : static_cast<int>(remaining);
}

int secure_random(void*, unsigned char* output, size_t length) {
  size_t offset = 0;
  while (offset < length) {
#ifdef __APPLE__
    const size_t requested = length - offset > 256 ? 256 : length - offset;
    if (getentropy(output + offset, requested) != 0) return -1;
    offset += requested;
#else
    const size_t requested = length - offset > 32 ? 32 : length - offset;
    const ssize_t count = getrandom(output + offset, requested, 0);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return -1;
    offset += static_cast<size_t>(count);
#endif
  }
  return 0;
}

bool safe_text(const char* value, size_t maximum, bool require_path) {
  if (!value || !*value || strnlen(value, maximum + 1) > maximum ||
      (require_path && *value != '/')) return false;
  for (const unsigned char* p = reinterpret_cast<const unsigned char*>(value); *p; ++p)
    if (*p <= 0x20 || *p == 0x7f) return false;
  return true;
}

bool valid_host(const char* host) {
  if (!safe_text(host, kMaxHost, false)) return false;
  for (const unsigned char* p = reinterpret_cast<const unsigned char*>(host); *p; ++p) {
    if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
        (*p >= '0' && *p <= '9') || *p == '.' || *p == '-') continue;
    return false;
  }
  const size_t length = strlen(host);
  return host[0] != '.' && host[0] != '-' && host[length - 1] != '.' &&
         host[length - 1] != '-';
}

// A media type such as "application/grpc-web+proto": printable ASCII
// without separators that could break the header line.
bool valid_content_type(const char* type) {
  const size_t length = strnlen(type, kOutboundContentTypeCapacity);
  if (!length || length >= kOutboundContentTypeCapacity) return false;
  for (size_t i = 0; i < length; ++i) {
    const unsigned char ch = static_cast<unsigned char>(type[i]);
    if (ch <= 0x20 || ch >= 0x7f || ch == ',' || ch == '"') return false;
  }
  return true;
}

bool valid_port(const char* port) {
  if (!safe_text(port, 5, false)) return false;
  unsigned value = 0;
  for (const char* p = port; *p; ++p) {
    if (*p < '0' || *p > '9') return false;
    value = value * 10 + static_cast<unsigned>(*p - '0');
    if (value > 65535) return false;
  }
  return value > 0;
}

bool valid_header_name(const char* name) {
  if (!name || !*name || strnlen(name, kOutboundHeaderNameCapacity) >=
                            kOutboundHeaderNameCapacity) return false;
  for (const unsigned char* p = reinterpret_cast<const unsigned char*>(name); *p; ++p) {
    const unsigned char c = *p;
    if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
        (*p >= '0' && *p <= '9')) continue;
    if (strchr("!#$%&'*+-.^_`|~", c)) continue;
    return false;
  }
  return true;
}

bool equal_ascii_case(const char* left, const char* right) {
  while (*left && *right) {
    unsigned char a = static_cast<unsigned char>(*left++);
    unsigned char b = static_cast<unsigned char>(*right++);
    if (a >= 'A' && a <= 'Z') a = static_cast<unsigned char>(a + ('a' - 'A'));
    if (b >= 'A' && b <= 'Z') b = static_cast<unsigned char>(b + ('a' - 'A'));
    if (a != b) return false;
  }
  return *left == *right;
}

bool protected_custom_header(const char* name) {
  // These are generated by the HTTP client or affect message framing and
  // connection handling. Provider credentials must not replace them.
  static const char* const names[] = {
      "host", "connection", "proxy-connection", "keep-alive",
      "content-length", "transfer-encoding", "accept-encoding",
      "content-type", "te", "trailer", "upgrade", "expect",
      "proxy-authenticate", "proxy-authorization"};
  for (const char* candidate : names)
    if (equal_ascii_case(name, candidate)) return true;
  return false;
}

bool valid_custom_headers(const OutboundRequest& request) {
  if (request.header_count > kOutboundMaxCustomHeaders) return false;
  for (size_t i = 0; i < request.header_count; ++i) {
    const OutboundHeader& header = request.headers[i];
    if (!valid_header_name(header.name) || protected_custom_header(header.name) ||
        strnlen(header.value, kOutboundHeaderValueCapacity) >=
            kOutboundHeaderValueCapacity) return false;
    for (const unsigned char* p =
             reinterpret_cast<const unsigned char*>(header.value); *p; ++p)
      if (*p < 0x20 || *p == 0x7f) return false;
    for (size_t previous = 0; previous < i; ++previous)
      if (equal_ascii_case(header.name, request.headers[previous].name)) return false;
  }
  return true;
}

// RFC 6750 section 2.1 b64token: 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" /
// "+" / "/" ) *"=", at most kOutboundMaxBearerBytes. Absent is valid; a
// bearer next to a custom Authorization header is not.
bool valid_bearer(const OutboundRequest& request) {
  const char* value = request.authorization_bearer;
  if (!value) return true;
  const size_t length = strnlen(value, kOutboundMaxBearerBytes + 1);
  if (!length || length > kOutboundMaxBearerBytes) return false;
  size_t i = 0;
  for (; i < length; ++i) {
    const unsigned char c = static_cast<unsigned char>(value[i]);
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == '/') continue;
    break;
  }
  if (i == 0) return false;
  for (; i < length; ++i)
    if (value[i] != '=') return false;
  for (size_t h = 0; h < request.header_count && h < kOutboundMaxCustomHeaders; ++h)
    if (equal_ascii_case(request.headers[h].name, "authorization")) return false;
  return true;
}

bool valid_user_agent(const char* value) {
  if (!value) return true;
  const size_t length = strnlen(value, kOutboundHeaderValueCapacity);
  if (!length || length >= kOutboundHeaderValueCapacity) return false;
  for (const unsigned char* p = reinterpret_cast<const unsigned char*>(value); *p; ++p)
    if (*p < 0x20 || *p >= 0x7f) return false;
  return true;
}

bool is_public_ipv4(uint32_t ip) {
  const uint8_t a = static_cast<uint8_t>(ip >> 24);
  const uint8_t b = static_cast<uint8_t>(ip >> 16);
  const uint8_t c = static_cast<uint8_t>(ip >> 8);
  if (a == 0 || a == 10 || a == 127 || a >= 224 ||
      (a == 100 && b >= 64 && b <= 127) || (a == 169 && b == 254) ||
      (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) ||
      (a == 192 && b == 0) || (a == 192 && b == 2) ||
      (a == 192 && b == 88 && c == 99) || (a == 192 && b == 175 && c == 48) ||
      (a == 192 && b == 31 && c == 196) || (a == 192 && b == 52 && c == 193) ||
      (a == 198 && (b == 18 || b == 19 || b == 51)) ||
      (a == 203 && b == 0 && c == 113)) return false;
  return true;
}

const mbedtls_x509_crt* cached_ca_chain(const char* path, OutboundError* error) {
  const size_t path_length = strnlen(path, sizeof(g_ca_cache[0].path));
  if (path_length == 0 || path_length >= sizeof(g_ca_cache[0].path)) {
    *error = OutboundError::kInvalidRequest;
    return nullptr;
  }

  fortis::base::UniqueLock g_ca_cache_lock(g_ca_cache_mutex);
  for (size_t i = 0; i < kCaCacheEntries; ++i) {
    if (g_ca_cache[i].used && strcmp(g_ca_cache[i].path, path) == 0) {
      g_ca_cache_lock.Unlock();
      return &g_ca_cache[i].chain;
    }
  }

  size_t free_slot = kCaCacheEntries;
  for (size_t i = 0; i < kCaCacheEntries; ++i) {
    if (!g_ca_cache[i].used) { free_slot = i; break; }
  }
  if (free_slot == kCaCacheEntries) {
    g_ca_cache_lock.Unlock();
    *error = OutboundError::kBusy;
    return nullptr;
  }

  struct stat ca_file_status{};
  if (stat(path, &ca_file_status) != 0 || ca_file_status.st_size <= 0 ||
      ca_file_status.st_size > kMaxCaBundleBytes) {
    g_ca_cache_lock.Unlock();
    *error = OutboundError::kTooLarge;
    return nullptr;
  }
  CachedCa* entry = &g_ca_cache[free_slot];
  mbedtls_x509_crt_init(&entry->chain);
  const int parsed = mbedtls_x509_crt_parse_file(&entry->chain, path);
  if (parsed != 0 || !entry->chain.raw.p) {
    mbedtls_x509_crt_free(&entry->chain);
    g_ca_cache_lock.Unlock();
    *error = OutboundError::kTls;
    return nullptr;
  }
  memcpy(entry->path, path, path_length + 1);
  entry->used = true;
  return &entry->chain;
}

struct Resolver {
  fortis::base::Mutex mutex;
  std::shared_ptr<Resolver> worker_owner;
  bool done;
  int result;
  size_t count;
  sockaddr_in addresses[kMaxAddresses];
  char host[kMaxHost + 1];
  char port[6];
};

bool reserve_resolver() {
  fortis::base::LockGuard g_resolvers_lock(g_resolvers_mutex);
  const bool available = g_resolvers < 4;
  if (available) ++g_resolvers;
  return available;
}

struct ResolverDeleter {
  void operator()(Resolver* resolver) const noexcept {
    base::Delete(resolver);
    base::LockGuard lock(g_resolvers_mutex);
    --g_resolvers;
  }
};
struct AddrinfoDeleter {
  void operator()(addrinfo* list) const noexcept {
#ifdef FORTIS_UNIKRAFT
    lwip_freeaddrinfo(list);
#else
    freeaddrinfo(list);
#endif
  }
};

void* resolve_thread(void* context) {
  auto* raw = static_cast<Resolver*>(context);
  auto resolver = std::move(raw->worker_owner);
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* list = nullptr;
#ifdef FORTIS_UNIKRAFT
  resolver->result = lwip_getaddrinfo(resolver->host, resolver->port, &hints, &list);
#else
  resolver->result = getaddrinfo(resolver->host, resolver->port, &hints, &list);
#endif
  std::unique_ptr<addrinfo, AddrinfoDeleter> addresses(list);
  if (resolver->result == 0) {
    for (addrinfo* p = addresses.get(); p && resolver->count < kMaxAddresses; p = p->ai_next) {
      if (p->ai_family == AF_INET && p->ai_addr &&
          p->ai_addrlen >= sizeof(sockaddr_in)) {
        resolver->addresses[resolver->count++] =
            *reinterpret_cast<sockaddr_in*>(p->ai_addr);
      }
    }
  }
  addresses.reset();
  fortis::base::UniqueLock lock(resolver->mutex);
  resolver->done = true;
  lock.Unlock();
  resolver.reset();
  return nullptr;
}

bool resolve_bounded(const char* host, const char* port, int64_t deadline,
                     sockaddr_in* output, size_t* count, OutboundError* error) {
  if (!reserve_resolver()) { *error = OutboundError::kBusy; return false; }
  static_assert(std::is_nothrow_default_constructible_v<Resolver>);
  std::unique_ptr<Resolver, ResolverDeleter> pending(base::New<Resolver>());
  if (!pending) {
    fortis::base::UniqueLock g_resolvers_lock(g_resolvers_mutex); --g_resolvers; g_resolvers_lock.Unlock();
    *error = OutboundError::kBusy;
    return false;
  }
  std::shared_ptr<Resolver> resolver;
  try {
    resolver = std::shared_ptr<Resolver>(std::move(pending));
  } catch (const std::bad_alloc&) {
    *error = OutboundError::kBusy;
    return false;
  }
  resolver->result = EAI_FAIL;
  snprintf(resolver->host, sizeof(resolver->host), "%s", host);
  snprintf(resolver->port, sizeof(resolver->port), "%s", port);

  // Publish one shared owner before pthread_create. Only the worker takes it;
  // a timed-out caller can leave while the bounded lookup still owns its state.
  resolver->worker_owner = resolver;
  if (!fortis::base::StartDetached<resolve_thread>(resolver.get())) {
    resolver->worker_owner.reset();
    *error = OutboundError::kResolve;
    return false;
  }

  bool done = false;
  while (!done) {
    fortis::base::UniqueLock lock(resolver->mutex);
    done = resolver->done;
    lock.Unlock();
    if (done) break;
    if (!remaining_ms(deadline)) {
      resolver.reset();
      *error = OutboundError::kTimeout;
      return false;
    }
    const timespec pause{0, 1000000};
    nanosleep(&pause, nullptr);
  }

  fortis::base::UniqueLock resolver_lock(resolver->mutex);
  const bool resolved = resolver->result == 0 && resolver->count > 0;
  *count = resolver->count;
  if (resolved) memcpy(output, resolver->addresses, resolver->count * sizeof(sockaddr_in));
  resolver_lock.Unlock();
  resolver.reset();
  if (!resolved) *error = OutboundError::kResolve;
  return resolved;
}

// With a cancel flag the wait is sliced so a raised flag ends it within
// kCancelPollMs.
bool wait_fd(int fd, bool writable, int64_t deadline) {
  for (;;) {
    int milliseconds = remaining_ms(deadline);
    if (!milliseconds) return false;
    const bool sliced = active_cancel && milliseconds > kCancelPollMs;
    if (sliced) milliseconds = kCancelPollMs;
    const short events = writable ? POLLOUT : POLLIN;
    pollfd descriptor{fd, events, 0};
    const int ready = poll(&descriptor, 1, milliseconds);
    if (ready < 0 && errno == EINTR) continue;
    if (ready != 0 || !sliced)
      return ready > 0 && (descriptor.revents & (events | POLLERR | POLLHUP));
  }
}

struct BioContext { int fd; int64_t deadline; };

int tls_send(void* context, const unsigned char* data, size_t length) {
  BioContext* bio = static_cast<BioContext*>(context);
  if (!wait_fd(bio->fd, true, bio->deadline)) return MBEDTLS_ERR_SSL_TIMEOUT;
#ifdef MSG_NOSIGNAL
  const ssize_t sent = send(bio->fd, data, length, MSG_NOSIGNAL);
#else
  const ssize_t sent = send(bio->fd, data, length, 0);
#endif
  if (sent < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  return sent > 0 ? static_cast<int>(sent) : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

int tls_receive(void* context, unsigned char* data, size_t length) {
  BioContext* bio = static_cast<BioContext*>(context);
  for (int attempt = 0; attempt < 2; ++attempt) {
    const ssize_t received = recv(bio->fd, data, length, MSG_DONTWAIT);
    if (received >= 0) return static_cast<int>(received);
    if (errno == EINTR) continue;
    if (errno != EAGAIN && errno != EWOULDBLOCK) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if (!wait_fd(bio->fd, false, bio->deadline)) return MBEDTLS_ERR_SSL_TIMEOUT;
  }
  return MBEDTLS_ERR_SSL_WANT_READ;
}

int connect_one(const sockaddr_in& address, int64_t deadline) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    close(fd);
    return -1;
  }
  int result = connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
  if (result < 0 && (errno == EINPROGRESS || errno == EWOULDBLOCK) &&
      wait_fd(fd, true, deadline)) {
    int socket_error = 0;
    socklen_t size = sizeof(socket_error);
    result = getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &size) == 0 &&
             socket_error == 0 ? 0 : -1;
  }
  if (result < 0) { close(fd); return -1; }
  return fd;
}

struct TlsSession {
  mbedtls_ssl_config config;
  mbedtls_ssl_context ssl;
  int fd;
  BioContext bio;
  TlsSession() : fd(-1), bio{-1, 0} {
    mbedtls_ssl_config_init(&config);
    mbedtls_ssl_init(&ssl);
  }
  ~TlsSession() {
    if (fd >= 0) close(fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&config);
  }
};

// `plain` set: a plaintext (http:) connection written straight to the socket.
bool send_all(mbedtls_ssl_context* ssl, BioContext* plain, const unsigned char* data,
              size_t length, int64_t deadline) {
  size_t offset = 0;
  while (offset < length) {
    if (!remaining_ms(deadline)) return false;
    const int sent = plain ? tls_send(plain, data + offset, length - offset)
                           : mbedtls_ssl_write(ssl, data + offset, length - offset);
    if (sent == MBEDTLS_ERR_SSL_WANT_READ || sent == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
    if (sent <= 0) return false;
    offset += static_cast<size_t>(sent);
  }
  return true;
}

int tls_read_some(mbedtls_ssl_context* ssl, BioContext* plain, unsigned char* data,
                  size_t capacity, int64_t deadline) {
  for (;;) {
    if (!remaining_ms(deadline)) return MBEDTLS_ERR_SSL_TIMEOUT;
    const int received = plain ? tls_receive(plain, data, capacity)
                               : mbedtls_ssl_read(ssl, data, capacity);
    if (received == MBEDTLS_ERR_SSL_WANT_READ || received == MBEDTLS_ERR_SSL_WANT_WRITE)
      continue;
    return received;
  }
}

struct TlsReader {
  mbedtls_ssl_context* ssl;
  int64_t deadline;
  unsigned char buffer[kTlsReadBufferBytes];
  size_t offset;
  size_t length;
  bool eof;
  int failure;
  BioContext* plain;  // non-null for a plaintext connection
};

int reader_read(TlsReader* reader, unsigned char* output, size_t capacity) {
  if (reader->offset == reader->length) {
    reader->offset = 0;
    reader->length = 0;
    if (reader->eof) return 0;
    const int received = tls_read_some(reader->ssl, reader->plain, reader->buffer,
                                       sizeof(reader->buffer), reader->deadline);
    if (received == 0) { reader->eof = true; return 0; }
    if (received < 0) { reader->failure = received; return -1; }
    reader->length = static_cast<size_t>(received);
  }
  const size_t available = reader->length - reader->offset;
  const size_t count = available < capacity ? available : capacity;
  memcpy(output, reader->buffer + reader->offset, count);
  reader->offset += count;
  return static_cast<int>(count);
}

bool reader_read_exact(TlsReader* reader, unsigned char* output, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    const int received = reader_read(reader, output + offset, length - offset);
    if (received <= 0) return false;
    offset += static_cast<size_t>(received);
  }
  return true;
}

// Reads CRLF-terminated text from the buffered TLS stream. The cap includes CRLF.
bool reader_read_line(TlsReader* reader, char* output, size_t capacity, size_t* length) {
  size_t used = 0;
  bool saw_cr = false;
  while (used + 2 <= capacity) {
    unsigned char byte = 0;
    const int received = reader_read(reader, &byte, 1);
    if (received != 1) { *length = used; return false; }
    if (saw_cr) {
      if (byte != '\n') return false;
      output[used] = '\0';
      *length = used;
      return true;
    }
    if (byte == '\r') { saw_cr = true; continue; }
    if (byte == '\n' || byte == 0 ||
        (byte < 0x20 && byte != '\t' && byte != ' ') || byte == 0x7f) return false;
    output[used++] = static_cast<char>(byte);
  }
  *length = used;
  return false;
}

struct HeaderState {
  bool have_content_length = false;
  size_t content_length = 0;
  bool have_transfer_encoding = false;
  bool chunked = false;
  bool connection_close = false;
  bool connection_keep_alive = false;
  bool have_content_encoding = false;
};


bool parse_decimal_size(const char* value, size_t* result) {
  if (!value || !*value) return false;
  size_t parsed = 0;
  for (const char* p = value; *p; ++p) {
    if (*p < '0' || *p > '9' || parsed > (SIZE_MAX - (*p - '0')) / 10) return false;
    parsed = parsed * 10 + static_cast<size_t>(*p - '0');
  }
  *result = parsed;
  return true;
}

bool copy_bounded_header(char* output, size_t capacity, const char* value) {
  const size_t length = strlen(value);
  if (length >= capacity) return false;
  memcpy(output, value, length + 1);
  return true;
}

bool parse_connection_tokens(const char* value, HeaderState* state) {
  const char* p = value;
  bool saw_token = false;
  while (*p) {
    while (*p == ' ' || *p == '\t') ++p;
    const char* begin = p;
    while (*p && *p != ',') ++p;
    const char* end = p;
    while (end > begin && (end[-1] == ' ' || end[-1] == '\t')) --end;
    if (end == begin) return false;
    char token[64];
    const size_t length = static_cast<size_t>(end - begin);
    if (length >= sizeof(token)) return false;
    memcpy(token, begin, length);
    token[length] = '\0';
    if (!valid_header_name(token)) return false;
    if (strcasecmp(token, "close") == 0) state->connection_close = true;
    if (strcasecmp(token, "keep-alive") == 0) state->connection_keep_alive = true;
    saw_token = true;
    if (!*p) break;
    ++p;
    if (!*p) return false;
  }
  return saw_token;
}

// Parses one already line-validated header field. Trailer fields are validated,
// but cannot overwrite framing or response metadata from the initial headers.
bool parse_header_field(char* line, bool trailer, HeaderState* state,
                        OutboundResponse* response, OutboundError* error) {
  char* colon = strchr(line, ':');
  if (!colon) { *error = OutboundError::kHttp; return false; }
  *colon = '\0';
  if (!valid_header_name(line)) { *error = OutboundError::kHttp; return false; }
  char* value = colon + 1;
  while (*value == ' ' || *value == '\t') ++value;
  char* end = value + strlen(value);
  while (end > value && (end[-1] == ' ' || end[-1] == '\t')) *--end = '\0';

  if (trailer) {
    if (strcasecmp(line, "content-length") == 0 ||
        strcasecmp(line, "transfer-encoding") == 0 ||
        strcasecmp(line, "host") == 0 || strcasecmp(line, "connection") == 0 ||
        strcasecmp(line, "content-encoding") == 0) {
      *error = OutboundError::kHttp;
      return false;
    }
    return true;
  }

  if (strcasecmp(line, "content-length") == 0) {
    size_t parsed = 0;
    if (!parse_decimal_size(value, &parsed)) { *error = OutboundError::kHttp; return false; }
    if (state->have_content_length && parsed != state->content_length) {
      *error = OutboundError::kUnsupportedFraming;
      return false;
    }
    state->have_content_length = true;
    state->content_length = parsed;
  } else if (strcasecmp(line, "transfer-encoding") == 0) {
    if (state->have_transfer_encoding || strcasecmp(value, "chunked") != 0) {
      *error = OutboundError::kUnsupportedFraming;
      return false;
    }
    state->have_transfer_encoding = true;
    state->chunked = true;
  } else if (strcasecmp(line, "content-encoding") == 0) {
    if (state->have_content_encoding || strcasecmp(value, "identity") != 0) {
      *error = OutboundError::kUnsupportedFraming;
      return false;
    }
    state->have_content_encoding = true;
  } else if (strcasecmp(line, "connection") == 0) {
    if (!parse_connection_tokens(value, state)) { *error = OutboundError::kHttp; return false; }
  } else if (strcasecmp(line, "content-type") == 0) {
    if (response->has_content_type ||
        !copy_bounded_header(response->content_type, sizeof(response->content_type), value)) {
      *error = response->has_content_type ? OutboundError::kHttp : OutboundError::kTooLarge;
      return false;
    }
    response->has_content_type = true;
  } else if (strcasecmp(line, "location") == 0) {
    if (response->has_location ||
        !copy_bounded_header(response->location, sizeof(response->location), value)) {
      *error = response->has_location ? OutboundError::kHttp : OutboundError::kTooLarge;
      return false;
    }
    response->has_location = true;
  } else if (strcasecmp(line, "retry-after") == 0) {
    if (response->has_retry_after ||
        !copy_bounded_header(response->retry_after, sizeof(response->retry_after), value)) {
      *error = response->has_retry_after ? OutboundError::kHttp : OutboundError::kTooLarge;
      return false;
    }
    response->has_retry_after = true;
  } else if (strcasecmp(line, "replay-nonce") == 0) {
    if (response->has_replay_nonce ||
        !copy_bounded_header(response->replay_nonce, sizeof(response->replay_nonce), value)) {
      *error = response->has_replay_nonce ? OutboundError::kHttp : OutboundError::kTooLarge;
      return false;
    }
    response->has_replay_nonce = true;
  }
  return true;
}

bool parse_header_block(unsigned char* block, size_t length, bool trailers,
                        HeaderState* state, OutboundResponse* response,
                        OutboundError* error) {
  size_t offset = 0;
  while (offset < length) {
    size_t end = offset;
    while (end + 1 < length && !(block[end] == '\r' && block[end + 1] == '\n')) ++end;
    if (end + 1 >= length) { *error = OutboundError::kHttp; return false; }
    if (end == offset) return true;
    block[end] = '\0';
    if (!parse_header_field(reinterpret_cast<char*>(block + offset), trailers,
                            state, response, error)) return false;
    offset = end + 2;
  }
  return false;
}

bool read_header_block(TlsReader* reader, unsigned char* block, size_t capacity,
                       size_t* length, OutboundError* error) {
  size_t used = 0;
  while (used < capacity) {
    unsigned char byte = 0;
    const int received = reader_read(reader, &byte, 1);
    if (received != 1) {
      *error = reader->failure == MBEDTLS_ERR_SSL_TIMEOUT ? OutboundError::kTimeout : OutboundError::kHttp;
      return false;
    }
    if (byte == 0 || (byte < 0x20 && byte != '\r' && byte != '\n' && byte != '\t') ||
        byte == 0x7f) { *error = OutboundError::kHttp; return false; }
    block[used++] = byte;
    if (used >= 4 && memcmp(block + used - 4, "\r\n\r\n", 4) == 0) {
      *length = used;
      return true;
    }
  }
  *error = OutboundError::kTooLarge;
  return false;
}

bool parse_status_line(unsigned char* block, size_t header_length,
                       size_t* fields_offset, bool* http_10,
                       OutboundResponse* response, OutboundError* error) {
  size_t line_end = 0;
  while (line_end + 1 < header_length &&
         !(block[line_end] == '\r' && block[line_end + 1] == '\n')) ++line_end;
  if (line_end + 1 >= header_length || line_end < 12) {
    *error = OutboundError::kHttp;
    return false;
  }
  block[line_end] = '\0';
  char* line = reinterpret_cast<char*>(block);
  if (strncmp(line, "HTTP/1.1 ", 9) == 0) *http_10 = false;
  else if (strncmp(line, "HTTP/1.0 ", 9) == 0) *http_10 = true;
  else { *error = OutboundError::kHttp; return false; }
  char* code = line + 9;
  if (code[0] < '0' || code[0] > '9' || code[1] < '0' || code[1] > '9' ||
      code[2] < '0' || code[2] > '9' || (code[3] && code[3] != ' ')) {
    *error = OutboundError::kHttp;
    return false;
  }
  for (char* p = code + 4; *p; ++p) {
    if (static_cast<unsigned char>(*p) < 0x20 || *p == 0x7f) {
      *error = OutboundError::kHttp;
      return false;
    }
  }
  response->status = (code[0] - '0') * 100 + (code[1] - '0') * 10 + (code[2] - '0');
  if (response->status < 100 || response->status > 599) {
    *error = OutboundError::kHttp;
    return false;
  }
  if (response->status < 200) {
    *error = OutboundError::kUnsupportedFraming;
    return false;
  }
  *fields_offset = line_end + 2;
  return true;
}

bool read_trailers(TlsReader* reader, HeaderState* state, OutboundResponse* response,
                   OutboundError* error) {
  char line[kMaxHeaderBytes + 1];
  size_t total = 0;
  for (;;) {
    size_t length = 0;
    if (!reader_read_line(reader, line, sizeof(line), &length)) {
      *error = length >= sizeof(line) - 2 ? OutboundError::kTooLarge :
               (remaining_ms(reader->deadline) ? OutboundError::kHttp : OutboundError::kTimeout);
      return false;
    }
    total += length + 2;
    if (total > kMaxHeaderBytes) { *error = OutboundError::kTooLarge; return false; }
    if (length == 0) return true;
    if (!parse_header_field(line, true, state, response, error)) return false;
  }
}

bool is_http_token_char(unsigned char c) {
  if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
      (c >= 'A' && c <= 'Z')) return true;
  return strchr("!#$%&'*+-.^_`|~", c) != nullptr;
}

bool parse_chunk_line(const char* line, size_t length, size_t* chunk_size) {
  size_t offset = 0;
  size_t digits = 0;
  size_t size = 0;
  while (offset < length && line[offset] != ';') {
    const unsigned char c = static_cast<unsigned char>(line[offset++]);
    unsigned digit;
    if (c >= '0' && c <= '9') digit = c - '0';
    else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
    else return false;
    if (size > (SIZE_MAX - digit) / 16) return false;
    size = size * 16 + digit;
    ++digits;
    if (digits > 16) return false;
  }
  if (digits == 0) return false;

  while (offset < length) {
    if (line[offset++] != ';') return false;
    const size_t name_start = offset;
    while (offset < length && is_http_token_char(static_cast<unsigned char>(line[offset]))) ++offset;
    if (offset == name_start) return false;
    if (offset == length || line[offset] == ';') continue;
    if (line[offset++] != '=') return false;
    if (offset == length) return false;
    if (line[offset] == '"') {
      ++offset;
      bool closed = false;
      while (offset < length) {
        const unsigned char c = static_cast<unsigned char>(line[offset++]);
        if (c == '"') { closed = true; break; }
        if (c == '\\') {
          if (offset == length) return false;
          const unsigned char escaped = static_cast<unsigned char>(line[offset++]);
          if (!(escaped == '\t' || escaped == ' ' || (escaped >= 0x21 && escaped <= 0x7e))) return false;
        } else if (!(c == '\t' || c == ' ' || c == '!' ||
                     (c >= '#' && c <= '[') || (c >= ']' && c <= '~') || c >= 0x80)) {
          return false;
        }
      }
      if (!closed) return false;
    } else {
      const size_t value_start = offset;
      while (offset < length && is_http_token_char(static_cast<unsigned char>(line[offset]))) ++offset;
      if (offset == value_start) return false;
    }
    if (offset < length && line[offset] != ';') return false;
  }
  *chunk_size = size;
  return true;
}

bool read_chunked_body(TlsReader* reader, unsigned char* body, size_t capacity,
                       size_t limit, size_t* body_length, OutboundResponse* response,
                       OutboundError* error) {
  char line[128];
  size_t total = 0;
  for (;;) {
    size_t line_length = 0;
    if (!reader_read_line(reader, line, sizeof(line), &line_length)) {
      *error = remaining_ms(reader->deadline) ? OutboundError::kHttp : OutboundError::kTimeout;
      return false;
    }
    if (line_length == 0 || line_length > 127) { *error = OutboundError::kHttp; return false; }
    size_t chunk_length = 0;
    if (!parse_chunk_line(line, line_length, &chunk_length)) {
      *error = OutboundError::kHttp;
      return false;
    }
    if (chunk_length == 0) {
      HeaderState trailer_state{};
      if (!read_trailers(reader, &trailer_state, response, error)) return false;
      *body_length = total;
      return true;
    }
    if (chunk_length > limit - total || chunk_length > capacity - total) {
      *error = OutboundError::kTooLarge;
      return false;
    }
    if (!reader_read_exact(reader, body + total, chunk_length)) {
      *error = remaining_ms(reader->deadline) ? OutboundError::kHttp : OutboundError::kTimeout;
      return false;
    }
    total += chunk_length;
    unsigned char delimiter[2];
    if (!reader_read_exact(reader, delimiter, sizeof(delimiter)) ||
        delimiter[0] != '\r' || delimiter[1] != '\n') {
      *error = remaining_ms(reader->deadline) ? OutboundError::kHttp : OutboundError::kTimeout;
      return false;
    }
  }
}

bool read_content_length_body(TlsReader* reader, unsigned char* body, size_t capacity,
                              size_t length, size_t* body_length,
                              OutboundError* error) {
  if (length > capacity) { *error = OutboundError::kTooLarge; return false; }
  if (!reader_read_exact(reader, body, length)) {
    *error = remaining_ms(reader->deadline) ? OutboundError::kHttp : OutboundError::kTimeout;
    return false;
  }
  *body_length = length;
  return true;
}

bool read_close_delimited_body(TlsReader* reader, unsigned char* body, size_t capacity,
                               size_t limit, size_t* body_length, OutboundError* error) {
  size_t total = 0;
  while (total < limit && total < capacity) {
    const size_t available = (limit - total) < (capacity - total) ?
                             (limit - total) : (capacity - total);
    const int received = reader_read(reader, body + total, available);
    if (received == 0) { *body_length = total; return true; }
    if (received < 0) {
      *error = reader->failure == MBEDTLS_ERR_SSL_TIMEOUT ? OutboundError::kTimeout : OutboundError::kHttp;
      return false;
    }
    total += static_cast<size_t>(received);
  }
  unsigned char extra = 0;
  const int received = reader_read(reader, &extra, 1);
  if (received == 0) { *body_length = total; return true; }
  if (received < 0) {
    *error = reader->failure == MBEDTLS_ERR_SSL_TIMEOUT ? OutboundError::kTimeout : OutboundError::kHttp;
    return false;
  }
  *error = OutboundError::kTooLarge;
  return false;
}

bool perform_tls_handshake(TlsSession* session, const OutboundRequest& request,
                           const mbedtls_x509_crt* ca, int64_t deadline,
                           OutboundError* error) {
  int rc = mbedtls_ssl_config_defaults(&session->config, MBEDTLS_SSL_IS_CLIENT,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT);
  if (rc == 0) {
    mbedtls_ssl_conf_authmode(&session->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&session->config,
                              const_cast<mbedtls_x509_crt*>(ca), nullptr);
    mbedtls_ssl_conf_rng(&session->config, fortis::base::FatalCallback<secure_random>, nullptr);
    mbedtls_ssl_conf_min_version(&session->config, MBEDTLS_SSL_MAJOR_VERSION_3,
                                 MBEDTLS_SSL_MINOR_VERSION_3);
    rc = mbedtls_ssl_setup(&session->ssl, &session->config);
  }
  if (rc == 0) rc = mbedtls_ssl_set_hostname(&session->ssl, request.host);
  if (rc == 0) {
    session->bio = {session->fd, deadline};
    mbedtls_ssl_set_bio(&session->ssl, &session->bio, fortis::base::FatalCallback<tls_send>, fortis::base::FatalCallback<tls_receive>, nullptr);
    do {
      if (!remaining_ms(deadline)) { rc = MBEDTLS_ERR_SSL_TIMEOUT; break; }
      rc = mbedtls_ssl_handshake(&session->ssl);
    } while (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE);
  }
  if (rc == 0 && mbedtls_ssl_get_verify_result(&session->ssl) != 0)
    rc = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
  if (rc == 0) return true;
  *error = remaining_ms(deadline) ? OutboundError::kTls : OutboundError::kTimeout;
  return false;
}

bool request_allowed(const OutboundRequest& request, const sockaddr_in& address) {
  const uint32_t ip = ntohl(address.sin_addr.s_addr);
  return request.allow_address ? request.allow_address(request.policy_context, ip) :
                                 is_public_ipv4(ip);
}
}  // namespace

bool OutboundHttpsValidateCaBundle(const char* path) {
  OutboundError error = OutboundError::kNone;
  return OutboundHttpsInitialize() && path && cached_ca_chain(path, &error) != nullptr;
}

bool OutboundHttpsInitialize() {
  return pthread_once(&g_psa_init_once, fortis::base::FatalCallback<initialize_psa_crypto>) == 0 &&
         g_psa_init_status == PSA_SUCCESS;
}

bool OutboundHttpsHeadersValid(const OutboundRequest& request) {
  return valid_custom_headers(request);
}

const char* OutboundErrorName(OutboundError error) {
  switch (error) {
    case OutboundError::kNone: return "none";
    case OutboundError::kInvalidRequest: return "invalid_request";
    case OutboundError::kPrivateAddress: return "address_policy";
    case OutboundError::kResolve: return "resolve";
    case OutboundError::kTimeout: return "timeout";
    case OutboundError::kConnect: return "connect";
    case OutboundError::kTls: return "tls";
    case OutboundError::kHttp: return "http";
    case OutboundError::kTooLarge: return "too_large";
    case OutboundError::kUnsupportedFraming: return "unsupported_framing";
    case OutboundError::kBusy: return "resource_limit";
  }
  return "unknown";
}

OutboundResponse OutboundHttpsRequest(const OutboundRequest& request,
                                     unsigned char* response_body,
                                     size_t response_capacity) {
  OutboundResponse response{};
  const bool binary = request.method == OutboundMethod::kPostBinary;
  if ((request.method != OutboundMethod::kGet &&
       request.method != OutboundMethod::kPostJson && !binary) ||
      (binary && !valid_content_type(request.content_type)) ||
      !valid_host(request.host) || !safe_text(request.path, kMaxPath, true) ||
      !valid_port(request.port) ||
      (!request.plaintext && (!request.ca_file || !*request.ca_file ||
                              strnlen(request.ca_file, 1024) >= 1024)) ||
      !valid_custom_headers(request) || !valid_user_agent(request.user_agent) ||
      !valid_bearer(request) || (request.authorization_bearer && request.plaintext) ||
      !request.timeout_ms ||
      request.timeout_ms > 60000 || !response_body || !response_capacity ||
      request.max_response_bytes == 0 || request.max_response_bytes > kMaxResponseBody ||
      request.max_response_bytes > response_capacity ||
      request.max_request_bytes > kOutboundMaxRequestBytes ||
      request.body_length > (request.max_request_bytes ? request.max_request_bytes : kOutboundDefaultRequestBytes) ||
      (request.method == OutboundMethod::kGet && request.body_length) ||
      (request.method != OutboundMethod::kGet && request.body_length && !request.body)) {
    response.error = OutboundError::kInvalidRequest;
    return response;
  }

  const CancelScope cancel_scope(request.cancel);

  // Mbed TLS 3.6 TLS 1.3 uses PSA global state. Initialize that subsystem once
  // before any parallel handshake can enter its lazy initialization path.
  if (!OutboundHttpsInitialize()) {
    response.error = OutboundError::kTls;
    return response;
  }

  const int64_t deadline = monotonic_ms() + request.timeout_ms;
  OutboundError error = OutboundError::kNone;
  const mbedtls_x509_crt* ca = nullptr;
  if (!request.plaintext) {
    ca = cached_ca_chain(request.ca_file, &error);
    if (!ca) { response.error = error; return response; }
  }
  if (!remaining_ms(deadline)) { response.error = OutboundError::kTimeout; return response; }

  sockaddr_in addresses[kMaxAddresses]{};
  size_t address_count = 0;
  if (request.connect_ipv4) {
    addresses[0].sin_family = AF_INET;
    addresses[0].sin_port = htons(static_cast<uint16_t>(strtoul(request.port, nullptr, 10)));
    addresses[0].sin_addr.s_addr = htonl(request.connect_ipv4);
    address_count = 1;
  } else if (!resolve_bounded(request.host, request.port, deadline, addresses,
                              &address_count, &response.error)) return response;

  if (request.require_all_addresses_allowed) {
    for (size_t i = 0; i < address_count; ++i) {
      if (!request_allowed(request, addresses[i])) {
        response.error = OutboundError::kPrivateAddress;
        return response;
      }
    }
  }
  TlsSession session;
  for (size_t i = 0; i < address_count; ++i) {
    if (!request_allowed(request, addresses[i])) {
      response.error = OutboundError::kPrivateAddress;
      return response;
    }
    if (remaining_ms(deadline)) session.fd = connect_one(addresses[i], deadline);
    if (session.fd >= 0) break;
  }
  if (session.fd < 0) {
    response.error = remaining_ms(deadline) ? OutboundError::kConnect : OutboundError::kTimeout;
    return response;
  }

  BioContext* plain = nullptr;
  if (request.plaintext) {
    session.bio = {session.fd, deadline};
    plain = &session.bio;
  } else if (!perform_tls_handshake(&session, request, ca, deadline, &response.error)) {
    response.error = error == OutboundError::kNone ? response.error : error;
    return response;
  }

  const char* user_agent = request.user_agent ? request.user_agent : "FortisNetWallet/1.0";
  char host_header[260];
  // The URL host: the port only when it is not the scheme's default.
  if (strcmp(request.port, request.plaintext ? "80" : "443") == 0)
    snprintf(host_header, sizeof(host_header), "%s", request.host);
  else
    snprintf(host_header, sizeof(host_header), "%s:%s", request.host, request.port);
  // 2 KiB path + host and generated fields + 8 x (63 name + 255 value)
  // plus delimiters fits comfortably in this fixed request-header buffer. A
  // bearer is not copied into it: it is sent from the caller's pointer.
  char headers[8192];
  int header_length;
  if (request.method == OutboundMethod::kGet) {
    header_length = snprintf(headers, sizeof(headers),
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
        "User-Agent: %s\r\nAccept-Encoding: identity\r\n",
        request.path, host_header, user_agent);
  } else {
    header_length = snprintf(headers, sizeof(headers),
        "POST %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
        "User-Agent: %s\r\nAccept-Encoding: identity\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n", request.path, host_header, user_agent,
        binary ? request.content_type : "application/json", request.body_length);
  }
  if (header_length <= 0 || static_cast<size_t>(header_length) >= sizeof(headers)) {
    mbedtls_platform_zeroize(headers, sizeof(headers));
    response.error = OutboundError::kInvalidRequest;
    return response;
  }
  size_t serialized_length = static_cast<size_t>(header_length);
  for (size_t i = 0; i < request.header_count; ++i) {
    const OutboundHeader& header = request.headers[i];
    const int count = snprintf(headers + serialized_length,
                               sizeof(headers) - serialized_length,
                               "%s: %s\r\n", header.name, header.value);
    if (count <= 0 || static_cast<size_t>(count) >=
                          sizeof(headers) - serialized_length) {
      mbedtls_platform_zeroize(headers, sizeof(headers));
      response.error = OutboundError::kInvalidRequest;
      return response;
    }
    serialized_length += static_cast<size_t>(count);
  }
  if (serialized_length + 2 > sizeof(headers)) {
    mbedtls_platform_zeroize(headers, sizeof(headers));
    response.error = OutboundError::kInvalidRequest;
    return response;
  }
  // With a bearer, the block ends at the last field and the validated
  // token is written from the caller's buffer, then the blank line.
  if (!request.authorization_bearer) {
    headers[serialized_length++] = '\r';
    headers[serialized_length++] = '\n';
  }
  bool headers_sent = send_all(&session.ssl, plain,
                               reinterpret_cast<unsigned char*>(headers),
                               serialized_length, deadline);
  // The header block may hold a provider key: wipe the stack copy as soon
  // as it is on the wire.
  mbedtls_platform_zeroize(headers, sizeof(headers));
  if (headers_sent && request.authorization_bearer) {
    static const char kBearerPrefix[] = "Authorization: Bearer ";
    static const char kEnd[] = "\r\n\r\n";
    headers_sent =
        send_all(&session.ssl, plain, reinterpret_cast<const unsigned char*>(kBearerPrefix),
                 sizeof(kBearerPrefix) - 1, deadline) &&
        send_all(&session.ssl, plain,
                 reinterpret_cast<const unsigned char*>(request.authorization_bearer),
                 strlen(request.authorization_bearer), deadline) &&
        send_all(&session.ssl, plain, reinterpret_cast<const unsigned char*>(kEnd),
                 sizeof(kEnd) - 1, deadline);
  }
  if (!headers_sent ||
      (request.method != OutboundMethod::kGet && request.body_length &&
       !send_all(&session.ssl, plain, request.body, request.body_length, deadline))) {
    response.error = remaining_ms(deadline) ? OutboundError::kTls : OutboundError::kTimeout;
    return response;
  }

  TlsReader reader{&session.ssl, deadline, {}, 0, 0, false, 0, plain};
  unsigned char raw_headers[kMaxHeaderBytes];
  size_t raw_header_length = 0;
  if (!read_header_block(&reader, raw_headers, sizeof(raw_headers),
                         &raw_header_length, &response.error)) return response;
  for (size_t i = 0; i < raw_header_length; ++i) {
    if ((raw_headers[i] == '\r' &&
         (i + 1 >= raw_header_length || raw_headers[i + 1] != '\n')) ||
        (raw_headers[i] == '\n' && (i == 0 || raw_headers[i - 1] != '\r'))) {
      response.error = OutboundError::kHttp;
      return response;
    }
  }

  bool http_10 = false;
  size_t fields_offset = 0;
  if (!parse_status_line(raw_headers, raw_header_length, &fields_offset,
                         &http_10, &response, &response.error)) return response;
  HeaderState header_state{};
  if (!parse_header_block(raw_headers + fields_offset,
                          raw_header_length - fields_offset, false,
                          &header_state, &response, &response.error)) return response;

  if (request.skip_non_2xx_body && (response.status < 200 || response.status >= 300)) {
    if (header_state.have_content_length &&
        header_state.content_length > request.max_response_bytes) {
      response.error = OutboundError::kTooLarge;
      response.declared_too_large = true;
    }
    return response;
  }

  if (header_state.have_content_length && header_state.have_transfer_encoding) {
    response.error = OutboundError::kUnsupportedFraming;
    return response;
  }
  const bool no_body_status = response.status == 204 || response.status == 205 ||
                              response.status == 304;
  if (no_body_status) {
    if (header_state.chunked ||
        (header_state.have_content_length && header_state.content_length != 0))
      response.error = OutboundError::kHttp;
    return response;
  }

  if (header_state.chunked) {
    if (!read_chunked_body(&reader, response_body, response_capacity,
                           request.max_response_bytes, &response.body_length,
                           &response, &response.error)) return response;
  } else if (header_state.have_content_length) {
    if (header_state.content_length > request.max_response_bytes) {
      response.error = OutboundError::kTooLarge;
      response.declared_too_large = true;
      return response;
    }
    if (!read_content_length_body(&reader, response_body, response_capacity,
                                  header_state.content_length, &response.body_length,
                                  &response.error)) return response;
  } else {
    const bool close_delimited = header_state.connection_close ||
                                 (http_10 && !header_state.connection_keep_alive);
    if (!close_delimited) {
      response.error = OutboundError::kUnsupportedFraming;
      return response;
    }
    if (!read_close_delimited_body(&reader, response_body, response_capacity,
                                   request.max_response_bytes, &response.body_length,
                                   &response.error)) return response;
  }

  response.error = OutboundError::kNone;
  return response;
}

}  // namespace fortis::http
