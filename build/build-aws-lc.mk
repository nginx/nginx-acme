#
# Build dynamic module with AWS-LC
#
# This build flavor requires shared AWS-LC, because:
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

LIBSSL_SRCDIR		= $(AWSLC_SOURCE_DIR)
LIBSSL_BUILDDIR		= $(NGINX_BUILD_DIR)/lib/aws-lc/build
LIBSSL_DESTDIR		= $(NGINX_BUILD_DIR)/lib/aws-lc/install

# pass SSL library location to openssl-sys

BUILD_ENV		+= OPENSSL_INCLUDE_DIR="$(LIBSSL_DESTDIR)/include"
BUILD_ENV		+= OPENSSL_LIB_DIR="$(LIBSSL_DESTDIR)/lib"
BUILD_ENV		+= OPENSSL_STATIC=0

TEST_ENV		+= LD_LIBRARY_PATH="$(LIBSSL_DESTDIR)/lib"

NGINX_CONFIGURE		= \
	$(NGINX_CONFIGURE_BASE) \
		--with-cc-opt="-I$(LIBSSL_DESTDIR)/include" \
		--with-ld-opt="-L$(LIBSSL_DESTDIR)/lib -lstdc++" \
		--with-debug \
		--add-dynamic-module="$(CURDIR)"


NGX_MODULE		= $(NGINX_BUILD_DIR)/ngx_http_acme_module.so
TEST_NGINX_GLOBALS	+= load_module $(NGX_MODULE);

.PHONY: $(NGX_MODULE)

build: $(NGX_MODULE)


$(LIBSSL_BUILDDIR)/CMakeCache.txt: $(LIBSSL_SRCDIR)/CMakeLists.txt
	cmake -S $(LIBSSL_SRCDIR) \
		-B $(LIBSSL_BUILDDIR) \
		-DBUILD_SHARED_LIBS:BOOL=ON \
		-DBUILD_TESTING:BOOL=OFF \
		-DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DCMAKE_INSTALL_LIBDIR:STRING=lib \
		-DCMAKE_INSTALL_PREFIX:STRING=$(LIBSSL_DESTDIR)

$(LIBSSL_DESTDIR)/lib/libssl.so: $(LIBSSL_BUILDDIR)/CMakeCache.txt
	cmake --build $(LIBSSL_BUILDDIR)
	cmake --install $(LIBSSL_BUILDDIR)

$(NGINX_BUILD_DIR)/Makefile: $(LIBSSL_DESTDIR)/lib/libssl.so
