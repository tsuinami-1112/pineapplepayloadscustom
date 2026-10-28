# pagerinj — build for the Pager, and for the host so the selftest can run.
#
# The Pager is OpenWrt 24.10.1, ramips/mt76x8, target mipsel_24kc, musl, SOFT FLOAT.  The loader
# name is the thing that bites: the binary must request /lib/ld-musl-mipsel-sf.so.1.  If it comes
# out as ld-musl-mipsel.so.1 (hard float) it will not run on the device, and the error you get
# looks like a missing file rather than an ABI mismatch.  `make verify` checks this, so run it.
#
# Get the SDK (192 MB) once:
#   curl -LO https://downloads.openwrt.org/releases/24.10.1/targets/ramips/mt76x8/openwrt-sdk-24.10.1-ramips-mt76x8_gcc-13.3.0_musl.Linux-x86_64.tar.zst
#   tar --zstd -xf openwrt-sdk-24.10.1-*.tar.zst        # needs the zstd binary; tar shells out to it
#   make SDK=$PWD/openwrt-sdk-24.10.1-ramips-mt76x8_gcc-13.3.0_musl.Linux-x86_64
#
# Then:
#   make host && ./pagerinj-host --selftest     # 0 failed, no radio needed
#   make SDK=... && make SDK=... verify         # cross-build and check the ABI
#   scp pagerinj root@172.16.52.1:/tmp/

SDK     ?=
TRIPLE   = mipsel-openwrt-linux-musl
TOOLDIR  = $(SDK)/staging_dir/toolchain-mipsel_24kc_gcc-13.3.0_musl
CC_CROSS = $(TOOLDIR)/bin/$(TRIPLE)-gcc
READELF  = $(TOOLDIR)/bin/$(TRIPLE)-readelf
# The toolchain warns on every invocation without this.
export STAGING_DIR = $(SDK)/staging_dir

# -mips32r2 -msoft-float matches the target; -Os because this lives in /tmp on a small device.
#
# -static-libgcc is deliberate.  The default build wants libgcc_s.so.1 at runtime, and that is the
# one library dev/pager-prearrival.md §3 flags as *unverified* on the Pager — it is in neither
# hcxdumptool's declared deps nor its NEEDED list, so nothing guarantees it is installed.  Linking
# it in costs a few KB and removes a dependency we cannot check until the device is in hand.
# `make static` goes further and removes libc too, for when you want zero loader risk at all.
CFLAGS_COMMON = -Os -Wall -Wextra -Werror -std=gnu99
CFLAGS_CROSS  = $(CFLAGS_COMMON) -mips32r2 -msoft-float -static-libgcc

.PHONY: all host static verify clean
all: pagerinj

pagerinj: pagerinj.c
	@test -n "$(SDK)" || { echo "set SDK=/path/to/openwrt-sdk-24.10.1-ramips-mt76x8_..."; exit 1; }
	@test -x "$(CC_CROSS)" || { echo "no cross gcc at $(CC_CROSS)"; exit 1; }
	$(CC_CROSS) $(CFLAGS_CROSS) -s -o $@ $<
	@echo "built $@ ($$(stat -c %s $@) bytes)"

# Fully static: no loader, no libc.so, nothing to be absent.  Bigger, and immune to every ABI
# question in this file.  If the dynamic build ever fails on the device, reach for this.
static: pagerinj.c
	@test -n "$(SDK)" || { echo "set SDK=/path/to/openwrt-sdk-24.10.1-ramips-mt76x8_..."; exit 1; }
	@test -x "$(CC_CROSS)" || { echo "no cross gcc at $(CC_CROSS)"; exit 1; }
	$(CC_CROSS) $(CFLAGS_CROSS) -static -s -o pagerinj-static $<
	@echo "built pagerinj-static ($$(stat -c %s pagerinj-static) bytes)"

host: pagerinj-host
pagerinj-host: pagerinj.c
	$(CC) $(CFLAGS_COMMON) -o $@ $<

# The ABI gate.  A wrong answer here is an afternoon lost in a shielded chamber.
verify: pagerinj
	@echo "--- must be ELF32 / little endian / MIPS ---"
	@$(READELF) -h pagerinj | grep -E 'Class|Data|Machine|Type'
	@echo "--- interpreter must be /lib/ld-musl-mipsel-sf.so.1 ---"
	@$(READELF) -l pagerinj | grep -A1 INTERP | tail -1
	@$(READELF) -l pagerinj | grep -q 'ld-musl-mipsel-sf\.so\.1' \
	  && echo "    OK soft-float loader" \
	  || { echo "    WRONG LOADER — will not run on the Pager"; exit 1; }
	@echo "--- shared library deps (libc only; nothing exotic should appear) ---"
	@$(READELF) -d pagerinj | grep NEEDED || echo "    (static)"

clean:
	rm -f pagerinj pagerinj-static pagerinj-host
