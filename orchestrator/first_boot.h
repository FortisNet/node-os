#pragma once

#include "native_control_support.h"

/** Turning a bare machine into a node host without anyone logging in.
 *
 * `FirstBoot` runs once, as the administrator, before the supervisor starts.
 * It never touches the network: it creates the folders, writes the
 * configuration the rest of the orchestrator reads, and stops. Everything
 * that can fail for outside reasons (the clock, the certificate, the first
 * install) is done afterwards by the supervisor, which keeps trying and says
 * on the first page what it is waiting for. */
namespace fortis::host::updates {

/** Where everything lives on a host, below `prefix` (empty on a real host;
 * a scratch folder in tests):
 *
 *   /etc/fortis/orchestrator.conf    the configuration (given as `config`)
 *   /etc/fortis/node.env             the node's environment
 *   /etc/fortis/first-boot.conf      optional settings applied on top of the
 *                                    defaults, one KEY=VALUE per line
 *   /usr/share/fortis/release-public.pem     the key releases are signed with
 *   /usr/share/fortis/recovery-public.pem    optional second key
 *   /usr/share/fortis/node-release/          the node release in the image
 *   /var/lib/fortis/state            the orchestrator's own state
 *   /var/lib/fortis/data/kv          the node's database
 *   /var/lib/fortis/data/backups     backups of it
 *   /var/lib/fortis/certificates, challenges, acme, fetch
 *
 * Creates the folders and writes the two files when `config` does not exist
 * yet; does nothing when it does, so it is safe to run at every boot.
 * Returns true when it configured the host. Throws runtime_error when the
 * image is incomplete (no release key) or no network address can be found. */
bool FirstBoot(const fs::path& config, const fs::path& prefix);

/** Where the orchestrator runs: "container" when it was started as a
 * container on someone else's kernel (Docker, Podman and the like),
 * "machine" when it has the machine to itself (a virtual machine or real
 * hardware). The same files serve both; this only tells them apart, for the
 * log, the health report and the hints the first page gives. */
std::string_view HostKind();

/** The IPv4 address this machine uses to reach the internet: the source
 * address of its default route. No packet is sent. Empty when there is no
 * route. */
std::string RoutedAddress();
/** True for an address a certificate authority can reach: not private,
 * shared, link-local, loopback or otherwise reserved. */
bool PublicAddress(std::string_view address);
/** True when the time service has synchronised the system clock. */
bool ClockSynchronised();

}  // namespace fortis::host::updates
