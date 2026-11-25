#pragma once

#include <filesystem>

namespace fortis::host::updates {

/** Serve the public HTTP port while no node does.
 *
 *   /.well-known/acme-challenge/TOKEN   certificate challenge files, from `challenges`
 *   /                                   the first page, from `pages`
 *   /health, /health.json               the health report, from `pages`, with the
 *                                       status code the report states, or 503
 *                                       when nobody has refreshed it lately
 *   anything else                       503 with a short notice
 *
 * `pages` may be empty: then only challenges are served. The listening
 * socket is inherited (FORTIS_LISTEN_FDS names it as port 8082); the process
 * opens no other socket, writes nothing and runs until it is signalled.
 * Returns the process exit code. */
int RunPageServer(const std::filesystem::path& challenges, const std::filesystem::path& pages);

}  // namespace fortis::host::updates
