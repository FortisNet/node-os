#pragma once

#include "native_control_support.h"

/** Certificate requests to a certificate authority that speaks ACME
 * (RFC 8555), with the HTTP challenge. Everything here parses data from the
 * network and is meant to run in the unprivileged certificate process;
 * `CheckCertificate` is the one function the administrator's side calls, on
 * the finished files, before it trusts them. */
namespace fortis::host::acme {
namespace fs = std::filesystem;

struct Settings {
  std::string directory;           // https URL of the authority's directory document
  std::string ca_file;             // trust anchors for the authority's own API
  std::string contact;             // optional e-mail address for the account
  std::string user_agent;          // "FortisNet-Orchestrator/<version>"
  fs::path account_key;            // PEM private key of the account; created when absent
  fs::path challenges;             // directory served at /.well-known/acme-challenge/
  bool allow_loopback = false;     // a local test authority only
  unsigned timeout_seconds = 180;  // for one whole certificate
};
/** What a certificate is for: one IPv4 address or one DNS name. */
struct Identifier {
  bool ip = false;
  std::string value;
};
struct Issued {
  std::string chain;  // PEM, the certificate first, then its issuers
  std::string key;    // PEM private key generated for this certificate
};
struct Validity {
  uint64_t not_before = 0, not_after = 0;  // seconds since 1970, UTC
};

/** Obtain one certificate for `identifier`: register or find the account,
 * place the order, answer the HTTP challenge through a file in
 * `settings.challenges`, send a request signed by a new P-256 key and fetch
 * the chain. The challenge file is removed again in every outcome.
 * Throws runtime_error with the authority's own error type on refusal. */
Issued Issue(const Settings& settings, const Identifier& identifier);

/** Confirm that `chain` and `key` are a usable server certificate for
 * `identifier`: the key matches, the chain leads to an anchor in
 * `trust_file`, the name or address is covered, server use is permitted and
 * the certificate is valid now and for at least `margin_seconds` more.
 * Throws runtime_error naming the first check that fails. */
Validity CheckCertificate(std::string_view chain, std::string_view key, const Identifier& identifier,
                          const fs::path& trust_file, uint64_t margin_seconds);

/** Validity of the first certificate in a PEM file, without judging it. */
Validity ReadValidity(std::string_view chain);

}  // namespace fortis::host::acme
