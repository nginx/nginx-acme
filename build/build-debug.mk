NGX_MODULE		= target/debug/lib$(MODULE)$(NGX_MODEXT)
TEST_NGINX_GLOBALS	+= load_module $(CURDIR)/$(NGX_MODULE);

NGINX_CONFIGURE		= \
	$(NGINX_CONFIGURE_BASE) \
		--with-debug \
		--add-dynamic-module="$(CURDIR)"

# always rebuild targets managed by external build tool
.PHONY: $(NGX_MODULE)

build: $(NGX_MODULE)
