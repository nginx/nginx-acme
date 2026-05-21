#
# Build dynamic module with custom OpenSSL
#
# This build flavor requires shared OpenSSL, because:
#
# * we use libssl objects created by nginx, and thus have to link to the same
#   library
#
# * linking static libssl.a to the nginx binary alone results in missing
#   symbols during module load
#
# * linking static libssl.a to both the binary and the module results in two
#   different sets of static globals
#

LIBSSL_SRCDIR		= $(OPENSSL_SOURCE_DIR)
LIBSSL_BUILDDIR		= $(NGINX_BUILD_DIR)/lib/openssl
LIBSSL_DESTDIR		= $(LIBSSL_BUILDDIR)/.openssl

# pass SSL library location to openssl-sys

BUILD_ENV		+= OPENSSL_INCLUDE_DIR="$(LIBSSL_DESTDIR)/include"
BUILD_ENV		+= OPENSSL_LIB_DIR="$(LIBSSL_DESTDIR)/lib"
BUILD_ENV		+= OPENSSL_STATIC=0

TEST_ENV		+= LD_LIBRARY_PATH="$(LIBSSL_DESTDIR)/lib"
TEST_NGINX_GLOBALS	+= load_module $(NGINX_BUILT_MODULE);

NGINX_CONFIGURE		= \
	$(NGINX_CONFIGURE_BASE) \
		--with-cc-opt="-I$(LIBSSL_DESTDIR)/include" \
		--with-ld-opt="-L$(LIBSSL_DESTDIR)/lib" \
		--with-debug \
		--add-dynamic-module="$(CURDIR)"


build: $(NGINX_BUILT_MODULE)

$(LIBSSL_BUILDDIR)/Makefile: $(LIBSSL_SRCDIR)/config
	mkdir -p $(LIBSSL_BUILDDIR)
	cd $(LIBSSL_BUILDDIR) && \
	$(LIBSSL_SRCDIR)/config --prefix=$(LIBSSL_DESTDIR) \
		shared no-tests

$(LIBSSL_DESTDIR)/lib/libssl$(SHLIB_EXT): $(LIBSSL_BUILDDIR)/Makefile
	cd $(LIBSSL_BUILDDIR) && \
	$(MAKE) && \
	$(MAKE) install_sw LIBDIR=lib

$(NGINX_BUILD_DIR)/Makefile: $(LIBSSL_DESTDIR)/lib/libssl$(SHLIB_EXT)
