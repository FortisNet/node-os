# Static native runtime notices

License texts only; no new implementation is vendored here.

- musl 1.2.6: https://git.musl-libc.org/cgit/musl/plain/COPYRIGHT?h=v1.2.6
- GCC 15.2.0 libstdc++/libgcc: https://github.com/gcc-mirror/gcc/tree/releases/gcc-15.2.0
  (`COPYING3` and `COPYING.RUNTIME`, GCC Runtime Library Exception 3.1).

The native release builder checks the compiler/musl versions and distributes
these notices with the separately mounted static executable. Upgrading either
runtime requires reviewing its license inputs too.
