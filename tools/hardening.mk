# The hardening profile of this repository's release build: musl and GCC, the same on
# x86_64 and aarch64.
# The same profile the node's release uses, held here so this repository builds alone.
NATIVE_C_HARDENING = -fPIE -fstack-protector-strong -fstack-clash-protection -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
NATIVE_CXX_HARDENING = $(NATIVE_C_HARDENING) -D_GLIBCXX_ASSERTIONS=1
NATIVE_ASM_HARDENING = -fPIE
# separate-code keeps the ELF headers out of the executable segment. The
# x86_64 linker does that by default; aarch64 needs it said.
NATIVE_LINK_HARDENING = -static-pie -Wl,-z,relro,-z,now,-z,noexecstack,-z,text,-z,separate-code
.PHONY: c cxx asm link
c:
	@echo $(NATIVE_C_HARDENING)
cxx:
	@echo $(NATIVE_CXX_HARDENING)
asm:
	@echo $(NATIVE_ASM_HARDENING)
link:
	@echo $(NATIVE_LINK_HARDENING)
