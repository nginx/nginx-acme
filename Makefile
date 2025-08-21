MODULE		= nginx_acme
# build/build-%.mk: debug, debug-static, release, release-static, sanitize
BUILD		?= debug
TESTS		?= t/
NGX_CARGO	?= cargo

NGINX_CONFIGURE_BASE	= \
	auto/configure \
		--with-http_ssl_module \
		--with-http_v2_module \
		--with-pcre \
		--with-stream \
		--with-stream_ssl_module \
		--with-compat

NGINX_SOURCE_DIR	?= ../nginx
NGINX_TESTS_DIR		?= $(NGINX_SOURCE_DIR)/tests
NGINX_BUILD_DIR		?= $(CURDIR)/objs-$(BUILD)

TEST_NGINX_BINARY	= $(NGINX_BUILD_DIR)/nginx
TEST_NGINX_GLOBALS	+= env RUST_BACKTRACE;

# "build" always calls cargo and causes relinking.
# Clearing this var allows to skip the build step: "make test TEST_PREREQ="
TEST_PREREQ = build


.PHONY: all

all: ## Build, lint and test the module
all: build check test


# Conditionals via include, compatible with most implementations of make

# GNU make 3.81 or earlier
MAKE_FLAVOR:= gnu
# POSIX 2024, BSD, GNU make 3.82+, etc
MAKE_FLAVOR!= echo posix

include	build/compat-$(MAKE_FLAVOR).mk
include	build/build-$(BUILD).mk


# Set up environment propagation

BUILD_ENV	+= NGINX_SOURCE_DIR="$(NGINX_SOURCE_DIR)"
BUILD_ENV	+= NGINX_BUILD_DIR="$(NGINX_BUILD_DIR)"

TEST_ENV	+= RUST_BACKTRACE=1
TEST_ENV	+= TEST_NGINX_BINARY="$(TEST_NGINX_BINARY)"
TEST_ENV	+= TEST_NGINX_GLOBALS="$(TEST_NGINX_GLOBALS)"


# Build targets

.PHONY: help build check unittest test clean

help:
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "}; /^[ a-zA-Z_-]+:.*?## .*$$/ {printf "%-16s %s\n", $$1, $$2}' \
		Makefile $(MAKEFILE_LIST) | sort -u
	@echo "Pass BUILD=<configuration> to any target for desired build configuration."
	@echo "Pass NGINX_SOURCE_DIR to specify path to your NGINX source checkout."

# Always rebuild targets managed by external build tool
.PHONY: target/debug/lib$(MODULE)$(NGX_MODEXT) \
	target/release/lib$(MODULE)$(NGX_MODEXT) \
	$(TEST_NGINX_BINARY)

$(NGINX_BUILD_DIR)/Makefile: config config.make auto/rust
$(NGINX_BUILD_DIR)/Makefile: $(NGINX_SOURCE_DIR)/src/core/nginx.h
# auto/configure unconditionally generates $NGINX_SOURCE_DIR/Makefile, even for
# out-of-tree builds.  Preserve the original Makefile and restore it later.
	@-cd $(NGINX_SOURCE_DIR) && rm -f Makefile.bak \
		&& test -f Makefile && mv -f Makefile Makefile.bak
	cd $(NGINX_SOURCE_DIR) \
		&& $(BUILD_ENV) $(NGINX_CONFIGURE) --builddir=$(NGINX_BUILD_DIR) \
		&& rm -f $(NGINX_SOURCE_DIR)/Makefile
	@-mv $(NGINX_SOURCE_DIR)/Makefile.bak $(NGINX_SOURCE_DIR)/Makefile

$(TEST_NGINX_BINARY): $(NGINX_BUILD_DIR)/Makefile
	cd $(NGINX_SOURCE_DIR) \
		&& $(BUILD_ENV) $(MAKE) -f $(NGINX_BUILD_DIR)/Makefile

target/debug/lib$(MODULE)$(NGX_MODEXT): $(NGINX_BUILD_DIR)/Makefile
	$(BUILD_ENV) $(NGX_CARGO) build

target/release/lib$(MODULE)$(NGX_MODEXT): $(NGINX_BUILD_DIR)/Makefile
	$(BUILD_ENV) $(NGX_CARGO) build --release

build: $(TEST_NGINX_BINARY) ## Build the module

check: $(NGINX_BUILD_DIR)/Makefile ## Check style and lint
	$(BUILD_ENV) $(NGX_CARGO) fmt --all -- --check
	$(BUILD_ENV) $(NGX_CARGO) clippy --all-targets --verbose -- -D warnings

unittest: $(NGINX_BUILD_DIR)/Makefile  ## Run unit-tests
	$(BUILD_ENV) $(NGX_CARGO) test

test: $(TEST_PREREQ) ## Run the integration test suite
	env $(TEST_ENV) prove -I $(NGINX_TESTS_DIR)/lib -v $(TESTS)

full-test: $(TEST_PREREQ) ## Run the module and NGINX integration test suites
	env $(TEST_ENV) prove -I $(NGINX_TESTS_DIR)/lib --state=save \
		-j $(TEST_JOBS) $(TESTS) $(NGINX_TESTS_DIR) ||\
	env $(TEST_ENV) prove -I $(NGINX_TESTS_DIR)/lib --state=failed -v

clean: ## Cleanup everything
	rm -rf $(NGINX_BUILD_DIR)
	$(NGX_CARGO) clean

# GNU make convenience targets. Will be ignored by other implementations.

build-%: ## Build with the specified configuration. E.g. make build-sanitize.
	$(MAKE) build BUILD="$*"

test-%: ## Test with the specified configuration.
	$(MAKE) test BUILD="$*"
