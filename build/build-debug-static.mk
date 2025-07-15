NGINX_CONFIGURE	= \
	$(NGINX_CONFIGURE_BASE) \
		--with-debug \
		--add-module="$(CURDIR)"
