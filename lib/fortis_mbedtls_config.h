// Mbed TLS user configuration (MBEDTLS_USER_CONFIG_FILE), applied after the
// pinned library's default configuration. The Makefile passes it to its build
// of the library and to every object, so the library and its callers always
// agree. The node has its own header and its own build of the library; the
// two never mix.
//
// It starts identical to the node's. Features the orchestrator does not use
// (a TLS server, most cipher suites) are to be switched off here in a later,
// separately reviewed change.
#ifndef FORTIS_MBEDTLS_CONFIG_H
#define FORTIS_MBEDTLS_CONFIG_H

// Nothing calls the mbedtls_*_self_test functions. With them on, ecp.c also
// keeps unsynchronized global operation counters.
#undef MBEDTLS_SELF_TEST

// The HTTPS client resolves names on a helper thread. The build flags enable
// pthread threading; refuse an object built without it, whose context
// layouts would not match the library.
#if !defined(MBEDTLS_THREADING_C) || !defined(MBEDTLS_THREADING_PTHREAD)
#error "This repository builds Mbed TLS with MBEDTLS_THREADING_C and MBEDTLS_THREADING_PTHREAD"
#endif

#endif  // FORTIS_MBEDTLS_CONFIG_H
