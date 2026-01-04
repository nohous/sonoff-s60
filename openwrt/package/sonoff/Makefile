include $(TOPDIR)/rules.mk

PKG_NAME:=sonoff
PKG_VERSION:=1.0
PKG_RELEASE:=2

include $(INCLUDE_DIR)/package.mk

define Package/sonoff
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Sonoff S60TPF smart plug controller
  DEPENDS:=+libucode +libmbedtls +curl
endef

define Package/sonoff/description
  Control Sonoff S60TPF smart plugs via local HTTP API.
  Includes ucode AES-CBC crypto module and web interface.
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -shared -fPIC \
		-I$(STAGING_DIR)/usr/include \
		-o $(PKG_BUILD_DIR)/aes_cbc.so \
		$(PKG_BUILD_DIR)/aes_cbc.c \
		-L$(STAGING_DIR)/usr/lib -lmbedcrypto
endef

define Package/sonoff/install
	# CLI tool and ucode module
	$(INSTALL_DIR) $(1)/usr/lib/ucode
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/aes_cbc.so $(1)/usr/lib/ucode/
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sonoff.uc $(1)/usr/bin/sonoff
	# Web interface
	$(INSTALL_DIR) $(1)/www
	$(CP) $(PKG_BUILD_DIR)/www/lamp.html $(1)/www/
	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/www/cgi-bin/sonoff $(1)/www/cgi-bin/
endef

$(eval $(call BuildPackage,sonoff))
