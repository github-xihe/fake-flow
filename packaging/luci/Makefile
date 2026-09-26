# SPDX-License-Identifier: GPL-2.0-only
include $(TOPDIR)/rules.mk
PKG_NAME:=luci-app-fakeflow
PKG_VERSION:=0.1.0
# Bump together with any change under packaging/luci (view/config.js/rpcd): the
# release workflow only builds the package, so a LuCI fix shipped under an
# unchanged version number simply does not install and the device keeps running
# the old interface. .github/workflows/luci.yml enforces this against the last
# aarch64-* tag.
PKG_RELEASE:=2
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-fakeflow
  PKGARCH:=all
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI support for FakeFlow
  DEPENDS:=+fakeflow +luci-base +rpcd +jshn +jsonfilter
endef

define Build/Compile
endef

define Package/luci-app-fakeflow/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view $(1)/www/luci-static/resources/fakeflow
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/fakeflow.js $(1)/www/luci-static/resources/view/
	$(INSTALL_DATA) ./htdocs/luci-static/resources/fakeflow/config.js $(1)/www/luci-static/resources/fakeflow/
	$(INSTALL_DIR) $(1)/usr/libexec/rpcd $(1)/usr/share/rpcd/acl.d $(1)/usr/share/luci/menu.d
	$(INSTALL_BIN) ./root/usr/libexec/rpcd/fakeflow $(1)/usr/libexec/rpcd/
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-fakeflow.json $(1)/usr/share/rpcd/acl.d/
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/luci-app-fakeflow.json $(1)/usr/share/luci/menu.d/
endef

define Package/luci-app-fakeflow/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] || {
	rm -f /tmp/luci-indexcache
	/etc/init.d/rpcd reload >/dev/null 2>&1 || true
}
exit 0
endef

$(eval $(call BuildPackage,luci-app-fakeflow))
