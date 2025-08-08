HOST_TUPLE	:= $(shell $(NGX_CARGO) -vV | awk '/^host: / { print $$2; }')

# extension for Rust cdylib targets
ifeq ($(shell uname), Darwin)
NGX_MODEXT	= .dylib
else
NGX_MODEXT	= .so
endif

# resolve paths

NGINX_SOURCE_DIR	:= $(shell CDPATH='' cd $(NGINX_SOURCE_DIR) && pwd)
NGINX_TESTS_DIR		:= $(shell CDPATH='' cd $(NGINX_TESTS_DIR) && pwd)
NGINX_BUILD_DIR		:= $(shell CDPATH='' mkdir -p $(NGINX_BUILD_DIR) && cd $(NGINX_BUILD_DIR) && pwd)
