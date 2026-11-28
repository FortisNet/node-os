#pragma once
// The key service's policy constants. Each is explained in docs/fortis-did.md;
// a change here is a change of security policy and is reviewed as one.
#include <chrono>

namespace fortis::keys {
/** How long a runtime certificate is valid (docs/fortis-did.md, section 7.1).
 *
 * One day, because:
 *  - the runtime keys are the ones the node's requests reach, so they are the
 *    most exposed: to a node that has been taken over, and to timing
 *    measurements of SQIsign signing, which is not constant-time. A key that
 *    expires tomorrow is worth one day to an attacker;
 *  - renewing costs nothing: the roots are on the host, so the key service
 *    renews by itself and no person is involved;
 *  - verifiers of the identity format accept at most 86,400 seconds. Making
 *    this longer than one day needs the same change there, in the same release.
 */
inline constexpr std::chrono::seconds kRuntimeCertificateLifetime = std::chrono::hours(24);

/// Renew when less than this is left, so a certificate in use is never close to expiry.
inline constexpr std::chrono::seconds kRuntimeRenewalMargin = kRuntimeCertificateLifetime / 4;

static_assert(kRuntimeCertificateLifetime >= std::chrono::hours(1),
              "a runtime certificate shorter than an hour would be renewed faster than peers can learn it");
// Verifiers of the identity format refuse runtime certificates longer than
// 86,400 seconds. To go beyond, raise their limit in the same release, then this one.
inline constexpr std::chrono::seconds kVerifierLifetimeLimit = std::chrono::hours(24);
static_assert(kRuntimeCertificateLifetime <= kVerifierLifetimeLimit,
              "peers would refuse these certificates: raise the verifiers' limit first");
static_assert(kRuntimeRenewalMargin > std::chrono::seconds(0) && kRuntimeRenewalMargin < kRuntimeCertificateLifetime,
              "renewal must start before expiry and not at issue");
}  // namespace fortis::keys
