/* Real untrusted test payload, compiled statically inside the Linux test image. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
  assert(argc == 2);
  if (!strcmp(argv[1], "inspect")) {
    assert(getuid() == 1000 && getgid() == 1000 && getpid() == 1);
    struct statvfs root; assert(statvfs("/", &root) == 0 && (root.f_flag & ST_RDONLY));
    assert(open("/host-secret", O_RDONLY) < 0);
    assert(open("/root-write", O_CREAT | O_WRONLY, 0600) < 0);
    assert(open("/tmp/allowed", O_CREAT | O_WRONLY, 0600) >= 0);
    assert(open("/sys/fs/cgroup/cgroup.procs", O_WRONLY) < 0);
    errno = 0; assert(ptrace(PTRACE_TRACEME, 0, 0, 0) == -1 && errno == EPERM);
    errno = 0; assert(syscall(SYS_unshare, 0x10000000) == -1 && errno == EPERM);
    struct rlimit limit; assert(getrlimit(RLIMIT_CORE, &limit) == 0 && limit.rlim_max == 0);
    assert(getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_max == 256);
    int fd = socket(AF_INET, SOCK_STREAM, 0); assert(fd >= 0);
    struct sockaddr_in address = {.sin_family=AF_INET, .sin_port=htons(443), .sin_addr={htonl(0x01010101)}};
    assert(connect(fd, (struct sockaddr *)&address, sizeof(address)) == -1);
    assert(errno == ENETUNREACH || errno == EHOSTUNREACH || errno == EACCES);
    close(fd);
    char ns[128]; ssize_t length = readlink("/proc/self/ns/net", ns, sizeof(ns)-1);
    assert(length > 0 && (size_t)length < sizeof(ns)); ns[length] = 0;
    printf("network-namespace=%s\n", ns);
    puts("isolation-ok");
  } else if (!strcmp(argv[1], "memory")) {
    for (;;) { volatile char *p = malloc(1024 * 1024); assert(p); for (size_t i=0;i<1024*1024;i+=4096) p[i]=1; }
  } else if (!strcmp(argv[1], "cpu")) {
    for (;;) { __asm__ volatile ("" ::: "memory"); }
  } else if (!strcmp(argv[1], "output")) {
    for (;;) puts("untrusted-output-012345678901234567890123456789");
  } else if (!strcmp(argv[1], "fork")) {
    unsigned children = 0;
    for (; children < 128; ++children) {
      pid_t pid = fork();
      if (pid < 0) { assert(errno == EAGAIN); break; }
      if (!pid) { sleep(2); _exit(0); }
    }
    assert(children < 64);
    while (wait(NULL) > 0) {}
    puts("fork-limit-ok");
  } else if (!strcmp(argv[1], "scratch")) {
    int fd = open("/tmp/fill", O_CREAT | O_WRONLY, 0600); assert(fd >= 0);
    char bytes[4096] = {0}; size_t total = 0; ssize_t n;
    while ((n=write(fd, bytes, sizeof(bytes))) > 0) { total += (size_t)n; assert(total <= 2*1024*1024); }
    assert(errno == ENOSPC); close(fd); puts("scratch-limit-ok");
  } else if (!strcmp(argv[1], "tail")) {
    for (unsigned i=0;i<2000;++i) puts("tail-line");
  } else if (!strcmp(argv[1], "fail")) return 17;
  else abort();
  return 0;
}
