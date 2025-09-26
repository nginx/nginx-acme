#
# Build static module with AWS-LC
#

LIBSSL_SRCDIR		= $(AWSLC_SOURCE_DIR)
LIBSSL_BUILDDIR		= $(NGINX_BUILD_DIR)/lib/aws-lc/build
LIBSSL_DESTDIR		= $(NGINX_BUILD_DIR)/lib/aws-lc/install

# pass SSL library location to openssl-sys

BUILD_ENV		+= OPENSSL_INCLUDE_DIR="$(LIBSSL_DESTDIR)/include"
BUILD_ENV		+= OPENSSL_LIB_DIR="$(LIBSSL_DESTDIR)/lib"
BUILD_ENV		+= OPENSSL_STATIC=1

NGINX_CONFIGURE		= \
	$(NGINX_CONFIGURE_BASE) \
		--with-cc-opt="-I$(LIBSSL_DESTDIR)/include" \
		--with-ld-opt="-L$(LIBSSL_DESTDIR)/lib -lstdc++" \
		--with-debug \
		--add-module="$(CURDIR)"


$(LIBSSL_BUILDDIR)/CMakeCache.txt: $(LIBSSL_SRCDIR)/CMakeLists.txt
	cmake -S $(LIBSSL_SRCDIR) \
		-B $(LIBSSL_BUILDDIR) \
		-DBUILD_TESTING:BOOL=OFF \
		-DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DCMAKE_INSTALL_LIBDIR:STRING=lib \
		-DCMAKE_INSTALL_PREFIX:STRING=$(LIBSSL_DESTDIR)

$(LIBSSL_DESTDIR)/lib/libssl.a: $(LIBSSL_BUILDDIR)/CMakeCache.txt
	cmake --build $(LIBSSL_BUILDDIR)
	cmake --install $(LIBSSL_BUILDDIR)

$(NGINX_BUILD_DIR)/Makefile: $(LIBSSL_DESTDIR)/lib/libssl.a
