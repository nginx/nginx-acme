TEST_NGINX_GLOBALS	+= load_module $(CURDIR)/$(CARGO_DEBUG_MODULE);

NGINX_CONFIGURE		= \
	$(NGINX_CONFIGURE_BASE) \
		--with-debug \
		--add-dynamic-module="$(CURDIR)"

build: $(CARGO_DEBUG_MODULE) $(NGINX_BUILT_MODULE)
