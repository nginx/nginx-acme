[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![Community Support](https://badgen.net/badge/support/community/cyan?icon=awesome)](/SUPPORT.md)
[![Community Forum](https://img.shields.io/badge/community-forum-009639?logo=discourse&link=https%3A%2F%2Fcommunity.nginx.org)](https://community.nginx.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/license/apache-2-0)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](/CODE_OF_CONDUCT.md)

# nginx-acme

nginx-acme is an [NGINX] module with the implementation of the automatic
certificate management (ACMEv2) protocol.

The module implements following specifications:

 * [RFC8555] (Automatic Certificate Management Environment) with limitations:
     * Only HTTP-01 challenge type is supported

[NGINX]: https://nginx.org/
[RFC8555]: https://www.rfc-editor.org/rfc/rfc8555.html

## Getting Started

### Requirements

- Regular NGINX build dependencies: C compiler, make, PCRE2, Zlib
- System-wide installation of OpenSSL 1.1.1 or later
- Rust toolchain (1.81.0 or later)
- [libclang] for rust-bindgen

[libclang]: https://rust-lang.github.io/rust-bindgen/requirements.html

### Building

One way to build the module is to export a path to a configured NGINX source
tree and run `cargo`.

```sh
# checkout, configure and build NGINX at ../nginx
cd nginx-acme
export NGINX_BUILD_DIR=$(realpath ../nginx/objs)
cargo build --release
```

The result will be located at `target/release/libnginx_acme.so`.

Another way is to use the provided config script:

```sh
# in the NGINX source directory
auto/configure \
    --with-compat \
    --with-http_ssl_module \
    --add-[dynamic-]module=/path/to/nginx-acme
```

The result will be located at `objs/ngx_http_acme_module.so`.

Currently this method produces a slightly larger library, as we don't instruct
the linker to perform LTO and remove unused code.

### Testing

The repository contains an integration test suite based on the [nginx-tests].
The following command will build the module and run the tests:

```sh
# Path to the nginx source checkout, defaults to ../nginx if not specified.
export NGINX_SOURCE_DIR=$(realpath ../nginx)
# Path to the nginx-tests checkout; defaults to ../nginx/tests if not specified.
export NGINX_TESTS_DIR=$(realpath ../nginx-tests)

make test
```

Most of the tests require [pebble] test server binary in the path, or in a
location specified via `TEST_NGINX_PEBBLE_BINARY` environment variable.

[nginx-tests]: https://github.com/nginx/nginx-tests
[pebble]: https://github.com/letsencrypt/pebble

## How to Use

Add the module to the NGINX configuration and configure as described below.
Note that this module requires a [resolver] configuration in the `http` block.

[resolver]: https://nginx.org/en/docs/http/ngx_http_core_module.html#resolver

## Example Configuration

```nginx
resolver 127.0.0.1:53;

acme_issuer example {
    uri         https://acme.example.com/directory;
    # contact     admin@example.test;
    state_path  /var/cache/nginx/acme-example;
    accept_terms_of_service;
}

acme_shared_zone zone=ngx_acme_shared:1M;

server {
    listen 443 ssl;
    server_name  .example.test;

    acme_certificate example;

    ssl_certificate       $acme_certificate;
    ssl_certificate_key   $acme_certificate_key;

    # do not parse the certificate on each request
    ssl_certificate_cache max=2;
}

server {
    # listener on port 80 is required to process ACME HTTP-01 challenges
    listen 80;

    location / {
        return 404;
    }
}
```

## Directives

### acme_issuer

**Syntax:** acme_issuer `name` { ... }

**Default:** -

**Context:** http

Defines an ACME certificate issuer object.

### uri

**Syntax:** uri `uri`

**Default:** -

**Context:** acme_issuer

The [directory URL](https://www.rfc-editor.org/rfc/rfc8555#section-7.1.1)
of the ACME server. This is the only mandatory directive in the
[acme_issuer](#acme_issuer) block.

### account_key

**Syntax:** account_key `alg[:size]` | `file`

**Default:** -

**Context:** acme_issuer

The account's private key used for request authentication.

Accepted values:

- `ecdsa:256/384/521` for `ES256`, `ES384` or `ES512` JSON Web Signature
  algorithms
- `rsa:2048/3072/4096` for `RS256`.
- File path for an existing key, using one of the algorithms above.

The generated account keys are preserved across reloads, but will be lost on
restart unless [state_path](#state_path) is configured.

### contact

**Syntax:** contact `url`

**Default:** -

**Context:** acme_issuer

Sets an array of URLs that the ACME server can use to contact the client
regarding account issues.
The `mailto:` scheme will be assumed unless specified
explicitly.

### external_account_key

**Syntax:** external_account_key `kid` `file`

**Default:** -

**Context:** acme_issuer

A key identifier and a file with the MAC key for external account authorization
([RFC8555 § 7.3.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.4)).

The value `data:key` can be specified instead of the `file` to load the key
directly from the configuration without using intermediate files.

In both cases, the key is expected to be encoded as base64url.

### ssl_trusted_certificate

**Syntax:** ssl_trusted_certificate `file`

**Default:** system CA bundle

**Context:** acme_issuer

Specifies a `file` with trusted CA certificates in the PEM format
used to [verify](#ssl_verify)
the certificate of the ACME server.

### ssl_verify

**Syntax:** ssl_verify `on` | `off`

**Default:** on

**Context:** acme_issuer

Enables or disables verification of the ACME server certificate.

### state_path

**Syntax:** state_path `path`

**Default:** -

**Context:** acme_issuer

Defines a directory for storing the module data that can be persisted across
restarts. This can significantly improve the time until the server is ready
and help with rate-limiting ACME servers.

The directory contains sensitive content, such as the account key, issued
certificates, and private keys.

### accept_terms_of_service

**Syntax:** accept_terms_of_service

**Default:** -

**Context:** acme_issuer

Agrees to the terms of service under which the ACME server will be used.
Some servers require accepting the terms of service before account registration.
The terms are usually available on the ACME server's website and the URL will
be printed to the error log if necessary.

### acme_shared_zone

**Syntax:** acme_shared_zone `zone` = `name:size`

**Default:** ngx_acme_shared:256k

**Context:** http

Allows increasing the size of in-memory storage of the module.
The shared memory zone will be used to store the issued certificates, keys and
challenge data for all the configured certificate issuers.

The default zone size is sufficient to hold ~50 ECDSA prime256v1 keys or
~35 RSA 2048 keys.

### acme_certificate

**Syntax:** acme_certificate `issuer` [`identifier` ...] [ `key` = `alg[:size]` ]

**Default:** -

**Context:** server

Defines a certificate with the list of `identifier`s requested from
issuer `issuer`.

The explicit list of identifiers can be omitted. In this case, the identifiers
will be taken from the [server_name] directive in the same `server` block.
Not all values accepted in the [server_name] are valid certificate identifiers:
regular expressions and wildcards are not supported.

[server_name]: https://nginx.org/en/docs/http/ngx_http_core_module.html#server_name

The `key` parameter sets the type of a generated private key.
Supported key algorithms and sizes:
`ecdsa:256` (default), `ecdsa:384`, `ecdsa:521`,
`rsa:2048`, `rsa:3072`, `rsa:4096`.

## Embedded Variables

The `ngx_http_acme_module` module defines following embedded
variables, valid in the `server` block with the
[acme_certificate](#acme_certificate) directive:

### `$acme_certificate`

SSL certificate that can be passed to the
[ssl_certificate](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate).

### `$acme_certificate_key`

SSL certificate private key that can be passed to the
[ssl_certificate_key](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate_key).

## Contributing

Please see the [contributing guide](/CONTRIBUTING.md) for guidelines on how to best contribute to this project.

## License

[Apache License, Version 2.0](/LICENSE)

&copy; [F5, Inc.](https://www.f5.com/) 2025
