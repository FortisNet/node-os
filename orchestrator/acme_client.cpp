#include "acme_client.h"
#include "outbound_https.h"
#include <arpa/inet.h>
#include <ctime>
#include <mbedtls/base64.h>
#include <mbedtls/ecp.h>
#include <mbedtls/oid.h>
// This header declares its conversion functions without C linkage.
extern "C" {
#include <mbedtls/psa_util.h>
}
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <sys/random.h>

namespace fortis::host::acme {
namespace {
using updates::Json;
using updates::Quote;
using updates::Require;
using Clock = std::chrono::steady_clock;

int Random(void*, unsigned char* output, size_t length) {
  while (length) {
    const ssize_t count = getrandom(output, length, 0);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return -1;
    output += count;
    length -= static_cast<size_t>(count);
  }
  return 0;
}
std::string Base64Url(std::string_view bytes) {
  std::string out((bytes.size() + 2) / 3 * 4 + 1, '\0');
  size_t length = 0;
  Require(mbedtls_base64_encode(reinterpret_cast<unsigned char*>(out.data()), out.size(), &length,
                                reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()) == 0,
          "base64 failed");
  out.resize(length);
  while (!out.empty() && out.back() == '=') out.pop_back();
  for (auto& c : out) c = c == '+' ? '-' : c == '/' ? '_' : c;
  return out;
}
std::string Sha256(std::string_view bytes) {
  const auto digest = updates::RawDigest(bytes);
  return {reinterpret_cast<const char*>(digest.data()), digest.size()};
}

/** A private key with the library's cleanup. */
struct Key {
  mbedtls_pk_context value;
  Key() { mbedtls_pk_init(&value); }
  ~Key() { mbedtls_pk_free(&value); }
  Key(const Key&) = delete;
  Key& operator=(const Key&) = delete;
};
void Generate(Key& key) {
  Require(mbedtls_pk_setup(&key.value, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) == 0 &&
              mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key.value), Random, nullptr) == 0,
          "key generation failed");
}
std::string Pem(Key& key) {
  std::string out(2048, '\0');
  Require(mbedtls_pk_write_key_pem(&key.value, reinterpret_cast<unsigned char*>(out.data()), out.size()) == 0,
          "key encoding failed");
  out.resize(std::char_traits<char>::length(out.c_str()));
  return out;
}
void Parse(Key& key, std::string_view pem) {
  const std::string text(pem);
  Require(mbedtls_pk_parse_key(&key.value, reinterpret_cast<const unsigned char*>(text.c_str()), text.size() + 1,
                               nullptr, 0, Random, nullptr) == 0,
          "private key unreadable");
}
/** The public point as the two 32-byte coordinates of a P-256 key. */
std::pair<std::string, std::string> Coordinates(const Key& key) {
  Require(mbedtls_pk_can_do(&key.value, MBEDTLS_PK_ECKEY) && mbedtls_pk_get_bitlen(&key.value) == 256,
          "a P-256 key is required");
  std::array<unsigned char, 65> point{};
  size_t length = 0;
  Require(mbedtls_ecp_write_public_key(mbedtls_pk_ec(key.value), MBEDTLS_ECP_PF_UNCOMPRESSED, &length, point.data(),
                                       point.size()) == 0 &&
              length == 65,
          "public key encoding failed");
  const auto* bytes = reinterpret_cast<const char*>(point.data());
  return {std::string(bytes + 1, 32), std::string(bytes + 33, 32)};
}
/** RFC 7638 form: exactly these members in this order, no spaces. */
std::string Jwk(const Key& key) {
  const auto [x, y] = Coordinates(key);
  return R"({"crv":"P-256","kty":"EC","x":")" + Base64Url(x) + R"(","y":")" + Base64Url(y) + "\"}";
}
/** ES256: the 64-byte r||s form, not the ASN.1 form the library produces. */
std::string Sign(Key& key, std::string_view message) {
  const auto digest = updates::RawDigest(message);
  std::array<unsigned char, MBEDTLS_PK_SIGNATURE_MAX_SIZE> der{};
  size_t der_length = 0, raw_length = 0;
  std::array<unsigned char, 64> raw{};
  Require(mbedtls_pk_sign(&key.value, MBEDTLS_MD_SHA256, digest.data(), digest.size(), der.data(), der.size(),
                          &der_length, Random, nullptr) == 0 &&
              mbedtls_ecdsa_der_to_raw(256, der.data(), der_length, raw.data(), raw.size(), &raw_length) == 0 &&
              raw_length == raw.size(),
          "signing failed");
  return {reinterpret_cast<const char*>(raw.data()), raw.size()};
}

struct Url {
  std::string host, port, path;
};
Url ParseUrl(std::string_view text) {
  constexpr std::string_view scheme = "https://";
  Require(text.size() <= 2000 && text.starts_with(scheme), "the certificate authority must use https");
  text.remove_prefix(scheme.size());
  const auto slash = text.find('/');
  const auto authority = text.substr(0, slash);
  Url url;
  url.path = slash == std::string_view::npos ? "/" : std::string(text.substr(slash));
  const auto colon = authority.rfind(':');
  url.host = std::string(authority.substr(0, colon));
  url.port = colon == std::string_view::npos ? "443" : std::string(authority.substr(colon + 1));
  Require(!url.host.empty() && !url.port.empty(), "invalid certificate authority address");
  return url;
}
bool Loopback(void*, uint32_t address) { return (address >> 24) == 127; }

struct Answer {
  int status = 0;
  std::string body, location, nonce;
  unsigned retry_after = 0;
};
/** One request to the authority. `body` absent means GET. */
Answer Send(const Settings& settings, const std::string& address, const std::string* body) {
  const auto url = ParseUrl(address);
  http::OutboundRequest request;
  request.host = url.host.c_str();
  request.port = url.port.c_str();
  request.path = url.path.c_str();
  request.ca_file = settings.ca_file.c_str();
  request.user_agent = settings.user_agent.c_str();
  request.timeout_ms = 30000;
  request.max_response_bytes = 256 * 1024;
  if (settings.allow_loopback) request.allow_address = Loopback;
  if (body) {
    request.method = http::OutboundMethod::kPostBinary;
    std::snprintf(request.content_type, sizeof(request.content_type), "application/jose+json");
    request.body = reinterpret_cast<const unsigned char*>(body->data());
    request.body_length = body->size();
  }
  std::vector<unsigned char> buffer(request.max_response_bytes);
  const auto response = http::OutboundHttpsRequest(request, buffer.data(), buffer.size());
  if (response.error != http::OutboundError::kNone)
    throw std::runtime_error(std::string("certificate authority unreachable: ") +
                             http::OutboundErrorName(response.error));
  Answer answer;
  answer.status = response.status;
  answer.body.assign(reinterpret_cast<const char*>(buffer.data()), response.body_length);
  if (response.has_location) answer.location = response.location;
  if (response.has_replay_nonce) answer.nonce = response.replay_nonce;
  if (response.has_retry_after) {
    const std::string_view text = response.retry_after;
    if (!text.empty() && text.size() <= 4 &&
        std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; }))
      answer.retry_after = static_cast<unsigned>(updates::Integer(text));
  }
  return answer;
}
/** The authority's own error type ("urn:ietf:params:acme:error:...") and its
 * explanation from one problem object, bounded and reduced to printable
 * text for the operator. */
std::string Describe(const Json& doc, uint32_t problem, std::string type) {
  std::string detail;
  if (doc.Is(doc.Field(problem, "type"), codec::BoundedJsonType::kString))
    type = doc.String(doc.Field(problem, "type"));
  if (doc.Is(doc.Field(problem, "detail"), codec::BoundedJsonType::kString))
    detail = doc.String(doc.Field(problem, "detail"));
  auto text = type + (detail.empty() ? "" : ": " + detail.substr(0, 300));
  for (auto& c : text)
    if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) >= 0x7f) c = '?';
  return text;
}
std::string Problem(const Answer& answer) {
  auto fallback = "status " + std::to_string(answer.status);
  try {
    const Json doc(answer.body);
    return Describe(doc, doc.Root(), fallback);
  } catch (const std::runtime_error&) {
    return fallback;  // Not a problem document: the status alone is reported.
  }
}
std::string Text(const Json& doc, uint32_t object, const char* field) {
  const auto value = doc.Field(object, field);
  Require(doc.Is(value, codec::BoundedJsonType::kString), "certificate authority answer lacks a field");
  return doc.String(value);
}

/** One account's conversation with the authority. */
class Session {
 public:
  Session(const Settings& settings, Key& account)
      : settings_(settings),
        account_(account),
        deadline_(Clock::now() + std::chrono::seconds(settings.timeout_seconds)) {
    const auto answer = Send(settings_, settings_.directory, nullptr);
    Require(answer.status == 200, "certificate authority directory unavailable");
    const Json doc(answer.body);
    new_nonce_ = Text(doc, doc.Root(), "newNonce");
    new_account_ = Text(doc, doc.Root(), "newAccount");
    new_order_ = Text(doc, doc.Root(), "newOrder");
    const auto meta = doc.Field(doc.Root(), "meta");
    if (doc.Is(meta, codec::BoundedJsonType::kObject)) {
      const auto profiles = doc.Field(meta, "profiles");
      short_lived_ = doc.Is(profiles, codec::BoundedJsonType::kObject) &&
                     doc.Is(doc.Field(profiles, "shortlived"), codec::BoundedJsonType::kString);
    }
  }
  bool ShortLivedOffered() const { return short_lived_; }
  const std::string& NewOrder() const { return new_order_; }
  void Register() {
    std::string payload = R"({"termsOfServiceAgreed":true)";
    if (!settings_.contact.empty()) payload += R"(,"contact":[)" + Quote("mailto:" + settings_.contact) + "]";
    const auto answer = Post(new_account_, payload + "}");
    Require(!answer.location.empty(), "certificate authority gave no account address");
    account_url_ = answer.location;
  }
  /** A signed request; `payload` empty reads the resource. Retries once when
   * the authority asks for a newer anti-replay value. */
  Answer Post(const std::string& url, const std::string& payload) {
    for (unsigned attempt = 0;; ++attempt) {
      Require(Clock::now() < deadline_ && !updates::interrupted, "certificate request timed out");
      if (nonce_.empty()) {
        nonce_ = Send(settings_, new_nonce_, nullptr).nonce;
        Require(!nonce_.empty(), "certificate authority gave no anti-replay value");
      }
      const auto identity = account_url_.empty() ? R"("jwk":)" + Jwk(account_) : R"("kid":)" + Quote(account_url_);
      const auto head =
          Base64Url(R"({"alg":"ES256",)" + identity + R"(,"nonce":)" + Quote(nonce_) + R"(,"url":)" + Quote(url) + "}");
      const auto body = Base64Url(payload);
      std::string signed_text = head;
      signed_text += '.';
      signed_text += body;
      std::string request = R"({"protected":")";
      request += head;
      request += R"(","payload":")";
      request += body;
      request += R"(","signature":")";
      request += Base64Url(Sign(account_, signed_text));
      request += "\"}";
      auto answer = Send(settings_, url, &request);
      nonce_ = answer.nonce;
      if (answer.status >= 200 && answer.status < 300) return answer;
      const auto problem = Problem(answer);
      if (attempt == 0 && problem.starts_with("urn:ietf:params:acme:error:badNonce")) continue;
      throw std::runtime_error("certificate authority refused: " + problem);
    }
  }
  /** Read `url` until its "status" leaves the waiting states. */
  std::string Await(const std::string& url, std::string_view wanted) {
    for (;;) {
      const auto answer = Post(url, "");
      const Json doc(answer.body);
      const auto status = Text(doc, doc.Root(), "status");
      if (status == wanted) return answer.body;
      if (status != "pending" && status != "processing") {
        // An authorization carries the reason inside the failed challenge.
        throw std::runtime_error("certificate authority reports " + status + ": " + Reason(doc));
      }
      updates::Pause(std::clamp(answer.retry_after, 1U, 10U) * 1000);
    }
  }
  std::string Thumbprint() const { return Base64Url(Sha256(Jwk(account_))); }

 private:
  /** Why a resource failed: an authorization carries the reason inside
   * its failed challenge, an order carries it directly. */
  static std::string Reason(const Json& doc) {
    const auto challenges = doc.Field(doc.Root(), "challenges");
    if (doc.Is(challenges, codec::BoundedJsonType::kArray))
      for (auto item = doc.Get().token(challenges)->first_child; item != codec::kBoundedJsonNoToken;
           item = doc.Get().token(item)->next_sibling) {
        const auto error = doc.Field(item, "error");
        if (doc.Is(error, codec::BoundedJsonType::kObject)) return Describe(doc, error, "no reason given");
      }
    const auto error = doc.Field(doc.Root(), "error");
    if (doc.Is(error, codec::BoundedJsonType::kObject)) return Describe(doc, error, "no reason given");
    return "no reason given";
  }
  const Settings& settings_;
  Key& account_;
  Clock::time_point deadline_;
  std::string new_nonce_, new_account_, new_order_, account_url_, nonce_;
  bool short_lived_ = false;
};

/** A certificate request (PKCS #10, DER) identified as FortisNet. */
std::string Request(Key& key, const Identifier& identifier) {
  mbedtls_x509write_csr csr;
  mbedtls_x509write_csr_init(&csr);
  const std::unique_ptr<mbedtls_x509write_csr, decltype(&mbedtls_x509write_csr_free)> owner(&csr,
                                                                                            mbedtls_x509write_csr_free);
  mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
  mbedtls_x509write_csr_set_key(&csr, &key.value);
  // A name goes in the common name as well as the alternative names. An
  // address must not: the public authority refuses a request with an address
  // there ("CSR contains IP address in Common Name"), so it is named only in
  // the alternative names.
  const auto subject = std::string("O=FortisNet,OU=FortisNet Node") + (identifier.ip ? "" : ",CN=" + identifier.value);
  in_addr address{};
  mbedtls_x509_san_list name{};
  if (identifier.ip) {
    Require(inet_pton(AF_INET, identifier.value.c_str(), &address) == 1, "invalid address");
    name.node.type = MBEDTLS_X509_SAN_IP_ADDRESS;
    name.node.san.unstructured_name.p = reinterpret_cast<unsigned char*>(&address.s_addr);
    name.node.san.unstructured_name.len = 4;
  } else {
    name.node.type = MBEDTLS_X509_SAN_DNS_NAME;
    name.node.san.unstructured_name.p = reinterpret_cast<unsigned char*>(const_cast<char*>(identifier.value.data()));
    name.node.san.unstructured_name.len = identifier.value.size();
  }
  std::array<unsigned char, 2048> buffer{};
  Require(mbedtls_x509write_csr_set_subject_name(&csr, subject.c_str()) == 0 &&
              mbedtls_x509write_csr_set_subject_alternative_name(&csr, &name) == 0,
          "certificate request could not be built");
  // The library writes the encoding at the end of the buffer.
  const int length = mbedtls_x509write_csr_der(&csr, buffer.data(), buffer.size(), Random, nullptr);
  Require(length > 0, "certificate request could not be signed");
  return {reinterpret_cast<const char*>(buffer.data()) + buffer.size() - static_cast<size_t>(length),
          static_cast<size_t>(length)};
}
bool TokenText(std::string_view value) {
  return !value.empty() && value.size() <= 128 && std::all_of(value.begin(), value.end(), [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
  });
}
/** Removes a published challenge answer when the attempt ends. */
struct Published {
  fs::path file;
  ~Published() {
    std::error_code ignored;
    if (!file.empty()) fs::remove(file, ignored);
  }
};
uint64_t Seconds(const mbedtls_x509_time& time) {
  struct tm parts {};
  parts.tm_year = time.year - 1900;
  parts.tm_mon = time.mon - 1;
  parts.tm_mday = time.day;
  parts.tm_hour = time.hour;
  parts.tm_min = time.min;
  parts.tm_sec = time.sec;
  const auto value = timegm(&parts);
  Require(value > 0, "certificate date out of range");
  return static_cast<uint64_t>(value);
}
struct Chain {
  mbedtls_x509_crt value;
  Chain() { mbedtls_x509_crt_init(&value); }
  ~Chain() { mbedtls_x509_crt_free(&value); }
  Chain(const Chain&) = delete;
  Chain& operator=(const Chain&) = delete;
};
void ParseChain(Chain& chain, std::string_view pem) {
  const std::string text(pem);
  Require(text.size() <= 64 * 1024 &&
              mbedtls_x509_crt_parse(&chain.value, reinterpret_cast<const unsigned char*>(text.c_str()),
                                     text.size() + 1) == 0,
          "certificate chain unreadable");
}
}  // namespace

Issued Issue(const Settings& settings, const Identifier& identifier) {
  Key account;
  if (!fs::exists(settings.account_key)) {
    Generate(account);
    updates::AtomicFile(settings.account_key, Pem(account), 0600);
  } else Parse(account, updates::Read(settings.account_key, 16 * 1024));
  Session session(settings, account);
  session.Register();

  // An address certificate exists only in the authority's short-lived
  // profile; a name takes the authority's default.
  auto order_request = std::string(R"({"identifiers":[{"type":")") + (identifier.ip ? "ip" : "dns") + R"(","value":)" +
                       Quote(identifier.value) + "}]";
  if (identifier.ip && session.ShortLivedOffered()) order_request += R"(,"profile":"shortlived")";
  const auto placed = session.Post(session.NewOrder(), order_request + "}");
  Require(!placed.location.empty(), "certificate authority gave no order address");
  std::string finalize;
  std::vector<std::string> authorizations;
  {
    const Json order(placed.body);
    finalize = Text(order, order.Root(), "finalize");
    const auto list = order.Field(order.Root(), "authorizations");
    Require(order.Is(list, codec::BoundedJsonType::kArray), "order lists no authorizations");
    for (auto item = order.Get().token(list)->first_child; item != codec::kBoundedJsonNoToken;
         item = order.Get().token(item)->next_sibling)
      authorizations.push_back(order.String(item));
    Require(!authorizations.empty() && authorizations.size() <= 4, "unexpected number of authorizations");
  }
  for (const auto& authorization : authorizations) {
    const auto current = session.Post(authorization, "");
    const Json doc(current.body);
    if (Text(doc, doc.Root(), "status") == "valid") continue;  // Proven recently; the authority remembers.
    std::string token, challenge;
    const auto challenges = doc.Field(doc.Root(), "challenges");
    Require(doc.Is(challenges, codec::BoundedJsonType::kArray), "authorization offers no challenges");
    for (auto item = doc.Get().token(challenges)->first_child; item != codec::kBoundedJsonNoToken;
         item = doc.Get().token(item)->next_sibling)
      if (Text(doc, item, "type") == "http-01") {
        token = Text(doc, item, "token");
        challenge = Text(doc, item, "url");
      }
    Require(TokenText(token), "the authority offers no usable HTTP challenge");
    Published published{settings.challenges / token};
    updates::AtomicFile(published.file, token + "." + session.Thumbprint(), 0644);
    (void)session.Post(challenge, "{}");
    (void)session.Await(authorization, "valid");
  }
  Key key;
  Generate(key);
  (void)session.Post(finalize, R"({"csr":")" + Base64Url(Request(key, identifier)) + "\"}");
  const auto finished = session.Await(placed.location, "valid");
  const Json order(finished);
  const auto chain = session.Post(Text(order, order.Root(), "certificate"), "");
  Require(chain.body.find("-----BEGIN CERTIFICATE-----") != std::string::npos, "no certificate was returned");
  return {chain.body, Pem(key)};
}

Validity ReadValidity(std::string_view chain_pem) {
  Chain chain;
  ParseChain(chain, chain_pem);
  return {Seconds(chain.value.valid_from), Seconds(chain.value.valid_to)};
}

Validity CheckCertificate(std::string_view chain_pem, std::string_view key_pem, const Identifier& identifier,
                          const fs::path& trust_file, uint64_t margin_seconds) {
  Chain chain, trust;
  ParseChain(chain, chain_pem);
  Key key;
  Parse(key, key_pem);
  Require(mbedtls_pk_check_pair(&chain.value.pk, &key.value, Random, nullptr) == 0,
          "certificate and private key do not match");
  Require(mbedtls_x509_crt_parse_file(&trust.value, trust_file.c_str()) == 0, "trust anchors unreadable");
  uint32_t flags = 0;
  // The name check covers both forms: a DNS name, or an address entry when
  // the expected name is an address.
  Require(mbedtls_x509_crt_verify(&chain.value, &trust.value, nullptr, identifier.value.c_str(), &flags, nullptr,
                                  nullptr) == 0 &&
              flags == 0,
          "certificate is not trusted for this name or address, or not valid now");
  Require(mbedtls_x509_crt_check_extended_key_usage(&chain.value, MBEDTLS_OID_SERVER_AUTH,
                                                    MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH)) == 0,
          "certificate does not permit server use");
  const Validity validity{Seconds(chain.value.valid_from), Seconds(chain.value.valid_to)};
  const auto now = updates::NowMs() / 1000;
  Require(validity.not_after > now && validity.not_after - now >= margin_seconds, "certificate expires too soon");
  return validity;
}

}  // namespace fortis::host::acme
