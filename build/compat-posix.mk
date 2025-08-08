HOST_TUPLE	!= $(NGX_CARGO) -vV | awk '/^host: / { print $$2; }'

# bsd make compatibility
CURDIR		?= $(.CURDIR)
# extension for Rust cdylib targets
NGX_MODEXT	!= if [ `uname` = Darwin ]; then echo ".dylib"; else echo ".so"; fi

# resolve paths

NGINX_SOURCE_DIR	!= CDPATH='' cd $(NGINX_SOURCE_DIR) && pwd
NGINX_TESTS_DIR		!= CDPATH='' cd $(NGINX_TESTS_DIR) && pwd
NGINX_BUILD_DIR		!= CDPATH='' mkdir -p $(NGINX_BUILD_DIR) && cd $(NGINX_BUILD_DIR) && pwd
