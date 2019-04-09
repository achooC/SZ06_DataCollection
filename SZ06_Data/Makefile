###############################################
#OpenWrt Makefile for SZ06_Data program
##############################################
include $(TOPDIR)/rules.mk
# Name and release number of this package
PKG_NAME:=SZ06_Data
PKG_RELEASE:=1
# This specifies the directory where we're going to build the program.
# The root build directory, $(BUILD_DIR), is by default the build_mipsel
# directory in your OpenWrt SDK directory
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)
include $(INCLUDE_DIR)/package.mk
# Specify package information for this program.
# The variables defined here should be self explanatory.
# If you are running Kamikaze, delete the DESCRIPTION
# variable below and uncomment the Kamikaze define
# directive for the description below
define Package/SZ06_Data
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:= +libmosquitto +libopenssl +libpthread +libubus +ubus +libsqlite3 +ubusd +libblobmsg-json  +libubox
	TITLE:=SZ06_Data -- prints a snarky message
endef
# Uncomment portion below for Kamikaze and delete DESCRIPTION variable above
define Package/SZ06_Data/description
    If you can't figure out what this program does, you're probably
    brain-dead and need immediate medical attention.
endef

# Specify what needs to be done to prepare for building the package.
# In our case, we need to copy the source files to the build directory.
# This is NOT the default.  The default uses the PKG_SOURCE_URL and the
# PKG_SOURCE which is not defined here to download the source from the web.
# In order to just build a simple program that we have just written, it is
# much easier to do it this way.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	#$(CP) ./file/* $(PKG_BUILD_DIR)/
endef
# We do not need to define Build/Configure or Build/Compile directives
# The defaults are appropriate for compiling a simple program such as this one
# Specify where and how to install the program. Since we only have one file,
# the helloworld executable, install it by copying it to the /bin directory on
# the router. The $(1) variable represents the root directory on the router running
# OpenWrt. The $(INSTALL_DIR) variable contains a command to prepare the install
# directory if it does not already exist.  Likewise $(INSTALL_BIN) contains the
# command to copy the binary file from its current location (in our case the build
# directory) to the install directory.
define Package/SZ06_Data/install
	#$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_DIR) $(1)/usr/bin
	#$(INSTALL_DIR) $(1)/usr/lib
	#$(CP) $(PKG_BUILD_DIR)/szgwmanage $(1)/etc/init.d/
	#$(INSTALL_BIN) $(PKG_BUILD_DIR)/szgwmanage.sh $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/SZ06_Data $(1)/usr/bin/
	#$(INSTALL_DATA) $(PKG_BUILD_DIR)/libshuncomzlib.so $(1)/usr/lib/
endef
# This line executes the necessary commands to compile our program.
# The above define directives specify all the information needed, but this
# line calls BuildPackage which in turn actually uses this information to build a package.
$(eval $(call BuildPackage,SZ06_Data))
