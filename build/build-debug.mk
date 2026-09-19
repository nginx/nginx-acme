TEST_NGINX_GLOBALS	+= load_module $(CURDIR)/$(CARGO_DEBUG_MODULE);

NGINX_CONFIGURE_ARGS	+= \
	--with-debug \
	--add-dynamic-module="$(CURDIR)"

build: $(CARGO_DEBUG_MODULE) $(NGINX_BUILT_MODULE)
