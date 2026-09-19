TEST_NGINX_GLOBALS	+= load_module $(CURDIR)/$(CARGO_DEBUG_MODULE);

NGINX_CONFIGURE_ARGS	+= \
	--with-debug \
	--add-dynamic-module="$(MODULE_SOURCE_DIR)"

build: $(CARGO_DEBUG_MODULE) $(NGINX_BUILT_MODULE)
