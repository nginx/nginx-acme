#
# Build dynamic module with BoringSSL
#
# This build flavor requires shared BoringSSL, because:
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

LIBSSL_SRCDIR		= $(BORINGSSL_SOURCE_DIR)
LIBSSL_BUILDDIR		= $(NGINX_BUILD_DIR)/lib/boringssl

# pass SSL library location to openssl-sys

BUILD_ENV		+= OPENSSL_INCLUDE_DIR="$(LIBSSL_SRCDIR)/include"
BUILD_ENV		+= OPENSSL_LIB_DIR="$(LIBSSL_BUILDDIR)"
BUILD_ENV		+= OPENSSL_STATIC=0

TEST_ENV		+= LD_LIBRARY_PATH="$(LIBSSL_BUILDDIR)"
TEST_NGINX_GLOBALS	+= load_module $(NGINX_BUILT_MODULE);

NGINX_CONFIGURE		= \
	$(NGINX_CONFIGURE_BASE) \
		--with-cc=c++ \
		--with-cc-opt="-xc -I$(LIBSSL_SRCDIR)/include" \
		--with-ld-opt="-L$(LIBSSL_BUILDDIR)" \
		--with-debug \
		--add-dynamic-module="$(CURDIR)"


build: $(NGINX_BUILT_MODULE)

$(LIBSSL_BUILDDIR)/CMakeCache.txt: $(LIBSSL_SRCDIR)/CMakeLists.txt
	cmake -S $(LIBSSL_SRCDIR) \
		-B $(LIBSSL_BUILDDIR) \
		-DBUILD_SHARED_LIBS:BOOL=ON \
		-DBUILD_TESTING:BOOL=OFF \
		-DCMAKE_BUILD_TYPE=RelWithDebInfo

$(LIBSSL_BUILDDIR)/libssl$(SHLIB_EXT): $(LIBSSL_BUILDDIR)/CMakeCache.txt
	cmake --build $(LIBSSL_BUILDDIR)

$(NGINX_BUILD_DIR)/Makefile: $(LIBSSL_BUILDDIR)/libssl$(SHLIB_EXT)
