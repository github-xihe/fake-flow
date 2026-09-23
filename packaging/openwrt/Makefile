# SPDX-License-Identifier: GPL-2.0-only
# Copy this repository to package/fakeflow/src and this file to
# package/fakeflow/Makefile inside an OpenWrt SDK with LLVM BPF support.
include $(TOPDIR)/rules.mk
PKG_NAME:=fakeflow
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_BUILD_FLAGS:=no-lto
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/fakeflow
  SECTION:=net
  CATEGORY:=Network
  TITLE:=TC eBPF TCP/UDP fake payload injection
  DEPENDS:=+libbpf +libelf +zlib +ip-full +tc-full
endef

define Package/fakeflow/description
 TC eBPF TCP/UDP fake payload injection. The running kernel must provide
 BPF, clsact, sched-bpf and dummy support (also TUN for L3 mode).
 Install matching kmod packages on native OpenWrt; containers use host modules.
endef

define Package/fakeflow/conffiles
/etc/fakeflow.toml
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

# BPF is host-compiled, userspace uses the SDK target compiler. Override
# BPF_CLANG to the SDK's clang with a BPF backend when necessary.
BPF_CLANG?=clang
define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) build/fakeflow.bpf.o CLANG=$(BPF_CLANG) \
		ARCH_INCLUDE=$(STAGING_DIR)/usr/include \
		BPF_CFLAGS="-O2 -g -target bpf$(if $(CONFIG_BIG_ENDIAN),eb,el) -I$(STAGING_DIR)/usr/include -I$(TOOLCHAIN_DIR)/include -Iebpf/include -Iebpf/bpf"
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_CPPFLAGS) -I$(PKG_BUILD_DIR)/ebpf/include \
		$(PKG_BUILD_DIR)/ebpf/user/*.c -o $(PKG_BUILD_DIR)/build/fakeflow \
		$(TARGET_LDFLAGS) -lbpf -lelf -lz
endef

define Package/fakeflow/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/usr/lib/fakeflow $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/fakeflow $(1)/usr/sbin/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/build/fakeflow.bpf.o $(1)/usr/lib/fakeflow/
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/config/fakeflow.toml $(1)/etc/fakeflow.toml
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/packaging/openwrt/fakeflow.init $(1)/etc/init.d/fakeflow
endef

$(eval $(call BuildPackage,fakeflow))
