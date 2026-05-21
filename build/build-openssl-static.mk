#
# Build static module with custom OpenSSL
#

LIBSSL_SRCDIR		= $(OPENSSL_SOURCE_DIR)
LIBSSL_BUILDDIR		= $(NGINX_BUILD_DIR)/lib/openssl
LIBSSL_DESTDIR		= $(LIBSSL_BUILDDIR)/.openssl

# pass SSL library location to openssl-sys

BUILD_ENV		+= OPENSSL_INCLUDE_DIR="$(LIBSSL_DESTDIR)/include"
BUILD_ENV		+= OPENSSL_LIB_DIR="$(LIBSSL_DESTDIR)/lib"
BUILD_ENV		+= OPENSSL_STATIC=1

NGINX_CONFIGURE		= \
	$(NGINX_CONFIGURE_BASE) \
		--with-cc-opt="-I$(LIBSSL_DESTDIR)/include" \
		--with-ld-opt="-L$(LIBSSL_DESTDIR)/lib" \
		--with-debug \
		--add-module="$(CURDIR)"


$(LIBSSL_BUILDDIR)/Makefile: $(LIBSSL_SRCDIR)/config
	mkdir -p $(LIBSSL_BUILDDIR)
	cd $(LIBSSL_BUILDDIR) && \
	$(LIBSSL_SRCDIR)/config --prefix=$(LIBSSL_DESTDIR) \
		no-shared no-tests

$(LIBSSL_DESTDIR)/lib/libssl.a: $(LIBSSL_BUILDDIR)/Makefile
	cd $(LIBSSL_BUILDDIR) && \
	$(MAKE) && \
	$(MAKE) install_sw LIBDIR=lib

$(NGINX_BUILD_DIR)/Makefile: $(LIBSSL_DESTDIR)/lib/libssl.a
