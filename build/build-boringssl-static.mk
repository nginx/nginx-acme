#
# Build static module with BoringSSL
#

LIBSSL_SRCDIR		= $(BORINGSSL_SOURCE_DIR)
LIBSSL_BUILDDIR		= $(NGINX_BUILD_DIR)/lib/boringssl

# pass SSL library location to openssl-sys

BUILD_ENV		+= OPENSSL_INCLUDE_DIR="$(LIBSSL_SRCDIR)/include"
BUILD_ENV		+= OPENSSL_LIB_DIR="$(LIBSSL_BUILDDIR)"
BUILD_ENV		+= OPENSSL_STATIC=1

NGINX_CONFIGURE		= \
	$(NGINX_CONFIGURE_BASE) \
		--with-cc=c++ \
		--with-cc-opt="-xc -I$(LIBSSL_SRCDIR)/include" \
		--with-ld-opt="-L$(LIBSSL_BUILDDIR)" \
		--with-debug \
		--add-module="$(CURDIR)"


$(LIBSSL_BUILDDIR)/CMakeCache.txt: $(LIBSSL_SRCDIR)/CMakeLists.txt
	cmake -S $(LIBSSL_SRCDIR) \
		-B $(LIBSSL_BUILDDIR) \
		-DBUILD_TESTING:BOOL=OFF \
		-DCMAKE_BUILD_TYPE=RelWithDebInfo

$(LIBSSL_BUILDDIR)/libssl.a: $(LIBSSL_BUILDDIR)/CMakeCache.txt
	cmake --build $(LIBSSL_BUILDDIR)

$(NGINX_BUILD_DIR)/Makefile: $(LIBSSL_BUILDDIR)/libssl.a
