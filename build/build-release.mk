NGX_MODULE		= target/release/lib$(MODULE)$(NGX_MODEXT)
TEST_NGINX_GLOBALS	+= load_module $(CURDIR)/$(NGX_MODULE);

NGINX_CONFIGURE		= \
	$(NGINX_CONFIGURE_BASE) \
		--add-dynamic-module="$(CURDIR)"

# always rebuild targets managed by external build tool
.PHONY: $(NGX_MODULE)

build: $(NGX_MODULE)
