# nginx-acme

nginx-acme is an [NGINX] module with the implementation of the automatic
certificate management ([ACME]) protocol.

[NGINX]: https://nginx.org/
[ACME]: https://www.rfc-editor.org/rfc/rfc8555.html

## Building

### Requirements

* Regular nginx build dependencies
* System-wide installation of OpenSSL 1.1.1 or later 
* Rust toolchain (1.81.0 or later)

### Commands

One way to build the module is to export a path to a pre-built nginx source
tree and run `cargo`.

```sh
# checkout, configure and build nginx at ../nginx
cd nginx-acme
export NGINX_BUILD_DIR=$(realpath ../nginx/objs)
cargo build --release
```
The result will be located at `target/release/libnginx_acme.so`.

Another way is to use the provided config script:
```sh
# in the nginx source directory
auto/configure \
    --with-compat \
    --with-http_ssl_module \
    --add-[dynamic-]module=/path/to/nginx-acme
```
The result will be located at `$NGX_OBJS/ngx_http_acme_module.so`.

Currently this method produces a slightly larger library, as we don't instruct
the linker to perform dead code elimination.

## How to Use

To be added later.

## License

[Apache License, Version 2.0](/LICENSE)

&copy; [F5, Inc.](https://www.f5.com/) 2025
