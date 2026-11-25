#include <atomic>
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace fortis::http {

// kPostBinary: a POST whose Content-Type is the request's inline
// content_type (the DashPay resolver's application/grpc-web+proto).
enum class OutboundMethod { kGet, kPostJson, kPostBinary };
enum class OutboundError { kNone, kInvalidRequest, kPrivateAddress, kResolve, kTimeout, kConnect, kTls, kHttp, kTooLarge, kUnsupportedFraming, kBusy };

// Custom headers are intended for provider authentication. Their storage is
// inline and fixed-size so request and adapter job memory stays deterministic.
constexpr size_t kOutboundMaxCustomHeaders = 8;
// Hard response-body ceiling. Provider adapters request far less; the media
// proxy and news feeds request up to 2 MiB.
constexpr size_t kOutboundMaxResponseBytes = 4 * 1024 * 1024;
// Request bodies default to 256 KiB; a caller that measured a larger body
// (the AI conversation request: a 40,000-unit portfolio context and 20 turns
// of up to 8,000 units, JSON-escaped twice) raises it per request, up to this.
constexpr size_t kOutboundDefaultRequestBytes = 256 * 1024;
constexpr size_t kOutboundMaxRequestBytes = 2 * 1024 * 1024;
constexpr size_t kOutboundHeaderNameCapacity = 64;  // at most 63 bytes
constexpr size_t kOutboundHeaderValueCapacity = 256;  // at most 255 bytes
constexpr size_t kOutboundContentTypeCapacity = 64;   // at most 63 bytes
// OutboundRequest::authorization_bearer: an RFC 6750 b64token of 1 to this
// many bytes. Google OAuth access tokens are documented as up to 2,048 bytes.
constexpr size_t kOutboundMaxBearerBytes = 4096;
struct OutboundHeader {
  char name[kOutboundHeaderNameCapacity]{};
  char value[kOutboundHeaderValueCapacity]{};
};

struct OutboundRequest {
  OutboundMethod method = OutboundMethod::kGet;
  const char* host = nullptr;
  const char* port = "443";
  const char* path = "/";
  const char* ca_file = nullptr;
  const unsigned char* body = nullptr;
  size_t body_length = 0;
  uint32_t timeout_ms = 10000;
  size_t max_response_bytes = 1024 * 1024;
  // Zero keeps kOutboundDefaultRequestBytes; at most kOutboundMaxRequestBytes.
  size_t max_request_bytes = 0;
  // An explicit endpoint policy hook. Production callers leave this null.
  bool (*allow_address)(void* context, uint32_t ipv4_host_order) = nullptr;
  void* policy_context = nullptr;
  // Judge every resolved address before dialling any (the SSRF guard's rule
  // for URLs the server did not choose). False keeps the
  // default: each address is judged just before it is dialled.
  bool require_all_addresses_allowed = false;
  // Non-zero: dial this IPv4 address (host byte order) instead of resolving
  // `host`. The name still goes into SNI, certificate verification and the
  // Host header, and the address policy still judges the address. The host
  // orchestrator uses it to probe its own node on loopback under the node's
  // public name.
  uint32_t connect_ipv4 = 0;
  // Replaces the default "FortisNetWallet/1.0" User-Agent value when set:
  // printable ASCII, at most 255 bytes.
  const char* user_agent = nullptr;
  // Plain HTTP/1.1 over TCP (an http: URL the media proxy or a feed redirect
  // names): no TLS, no CA file. The address policy, framing and size bounds
  // are unchanged.
  bool plaintext = false;
  // MediaFacet only: its bytes() caller decides redirects and non-2xx
  // responses from headers, without downloading their bodies. Preserve the
  // declared size signal for its 5xx failure classification.
  bool skip_non_2xx_body = false;
  // kPostBinary only: printable ASCII, stored inline so request copies (the
  // provider coordinator's) stay self-contained.
  char content_type[kOutboundContentTypeCapacity]{};
  // Optional cancellation: while the request runs, every wait polls *cancel
  // (atomically, at least every 50 ms); non-zero ends the request as a
  // timeout. The flag must outlive the call.
  const std::atomic<int>* cancel = nullptr;
  // Optional "Authorization: Bearer <token>" credential, borrowed and
  // NUL-terminated, for an access token longer than a custom header value
  // (the Play Integrity decode client's Google OAuth token). It must outlive
  // the call; the provider execution queue copies requests and refuses it.
  // The token must be an RFC 6750 b64token (ALPHA / DIGIT / "-" / "." / "_" /
  // "~" / "+" / "/", then optional trailing "="), so it can never carry
  // whitespace, CR or LF, and no custom header may also be named
  // Authorization. It is never logged or echoed.
  const char* authorization_bearer = nullptr;
  size_t header_count = 0;
  OutboundHeader headers[kOutboundMaxCustomHeaders]{};
};
struct OutboundResponse {
  int status = 0;
  size_t body_length = 0;
  OutboundError error = OutboundError::kNone;
  bool has_content_type = false;
  bool has_location = false;
  bool has_retry_after = false;
  // The certificate authority protocol (RFC 8555) hands each next request's
  // anti-replay value in this header; no other caller reads it.
  bool has_replay_nonce = false;
  // kTooLarge because the declared Content-Length exceeded
  // max_response_bytes (no body byte was read), as opposed to a body that
  // grew past it while streaming.
  bool declared_too_large = false;
  char content_type[256]{};
  char location[1024]{};
  char retry_after[128]{};
  char replay_nonce[256]{};
};

// Parse and validate a PEM CA bundle at startup. Trust chains are cached by a
// copied path and live immutably for process lifetime; changing a bundle requires
// restarting the process. The cache is bounded to four distinct paths, and
// each bundle must be at most 1 MiB on first load.
// Initializes the shared PSA crypto state once before concurrent TLS work.
bool OutboundHttpsInitialize();
bool OutboundHttpsValidateCaBundle(const char* path);
// Validates custom header bounds and syntax without performing I/O.
bool OutboundHttpsHeadersValid(const OutboundRequest& request);
// Executes one GET or JSON POST. Response body is caller-owned and bounded by
// response_capacity and request.max_response_bytes (at most
// kOutboundMaxResponseBytes). No redirects are followed; a 3xx answer is
// returned with its Location.
OutboundResponse OutboundHttpsRequest(const OutboundRequest& request,
                                      unsigned char* response_body,
                                      size_t response_capacity);
const char* OutboundErrorName(OutboundError error);

}  // namespace fortis::http
