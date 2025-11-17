[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![Community Support](https://badgen.net/badge/support/community/cyan?icon=awesome)](/SUPPORT.md)
[![Community Forum](https://img.shields.io/badge/community-forum-009639?logo=discourse&link=https%3A%2F%2Fcommunity.nginx.org)](https://community.nginx.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/license/apache-2-0)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](/CODE_OF_CONDUCT.md)

# nginx-acme

nginx-acme is an [NGINX] module with the implementation of the automatic
certificate management (ACMEv2) protocol.

The module implements following specifications:

- [RFC8555] (Automatic Certificate Management Environment) with limitations:
    - Only HTTP-01 challenge type is supported
- [RFC8737] (ACME TLS Application-Layer Protocol Negotiation (ALPN) Challenge
  Extension)
- [RFC8738] (ACME IP Identifier Validation Extension)
- [draft-ietf-acme-profiles] (ACME Profiles Extension, version 00)

[NGINX]: https://nginx.org/
[RFC8555]: https://datatracker.ietf.org/doc/html/rfc8555
[RFC8737]: https://datatracker.ietf.org/doc/html/rfc8737
[RFC8738]: https://datatracker.ietf.org/doc/html/rfc8738
[draft-ietf-acme-profiles]: https://datatracker.ietf.org/doc/draft-ietf-acme-profiles/

## Getting Started

### Requirements

- NGINX sources, 1.25.0 or later.
- Regular NGINX build dependencies: C compiler, make, PCRE2, Zlib
- System-wide installation of OpenSSL 1.1.1 or later
- Rust toolchain (1.81.0 or later)
- `pkg-config` or `pkgconf`
- [libclang] for rust-bindgen

The NGINX and its dependency versions should match the ones you plan to deploy,
including any patches that change the API.

> [!TIP]
> The module built against a specific release of unmodified NGINX Open Source
> with `--with-compat --with-http_ssl_module` is compatible with a corresponding
> release of NGINX Plus.
> Refer to https://www.f5.com/company/blog/nginx/compiling-dynamic-modules-nginx-plus

[libclang]: https://rust-lang.github.io/rust-bindgen/requirements.html

#### Important note on SSL libraries

It is important to ensure that the module uses the same SSL implementation as
NGINX. SSL contexts and certificate objects are passed between the module and
NGINX code, and any mismatches in types can cause memory issues and crashes.

The best way to guarantee this is to build both with a system-provided shared
library.

If you absolutely have to use an alternative SSL implementation, ensure that
the module uses it during build by setting appropriate
[`OPENSSL_*` variables](https://docs.rs/openssl/latest/openssl/#manual) for the
Rust bindings to OpenSSL.  Check [build-aws-lc.mk](build/build-aws-lc.mk) and
[build-aws-lc-static.mk](build/build-aws-lc-static.mk) CI configurations for
examples.

Also, note that dynamic build of the module must use dynamic linking for the SSL
library. Static linking in that scenario will result in two copies of the
library code with independent global state.

See [SSL library compatibility](https://github.com/nginx/nginx-acme/wiki/Compatibility#ssl-libraries)
in the project wiki for the state of support of alternative SSL implementations.

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

#### Build options

As there is no mechanism to add third-party module configuration options to
auto/configure, all the module build-time options are set via environment
variables passed to the `cargo build` or `make` commands.
Currently accepted options are:

- `NGX_ACME_STATE_PREFIX`: sets a default prefix for per-issuer state paths.
  If unset, state paths are created relative to the NGINX prefix directory.
  The prefix directory should exist and be readable to the worker processes.

Example:

```sh
export NGX_ACME_STATE_PREFIX=/var/cache/nginx
auto/configure \
    ... \
    --with-compat \
    --with-http_ssl_module \
    --add-dynamic-module=/path/to/nginx-acme
make
```

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
    server_name  .example.test
                 192.0.2.1      # not supported by some ACME servers
                 2001:db8::1    # not supported by some ACME servers
                 ;

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

> [!IMPORTANT]
> The reference below reflects the current development version. See
> [ngx_http_acme_module](https://nginx.org/en/docs/http/ngx_http_acme_module.html)
> documentation on [nginx.org](https://nginx.org) for the latest released version.

### acme_issuer

**Syntax:** **`acme_issuer`** _`name`_ { ... }

**Default:** -

**Context:** http

Defines an ACME certificate issuer object.

### uri

**Syntax:** **`uri`** _`uri`_

**Default:** -

**Context:** acme_issuer

The [directory URL](https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1)
of the ACME server.
This directive is mandatory.

### account_key

**Syntax:** **`account_key`** _`alg`_\[:_`size`_] | _`file`_

**Default:** -

**Context:** acme_issuer

The account's private key used for request authentication.

Accepted values:

- `ecdsa`:`256`/`384`/`521` for `ES256`, `ES384` or `ES512` JSON Web Signature
  algorithms
- `rsa`:`2048`/`3072`/`4096` for `RS256`.
- File path for an existing key, using one of the algorithms above.

The generated account keys are preserved across reloads,
but will be lost on restart unless [state_path](#state_path) is configured.

### challenge

**Syntax:** **`challenge`** _`type`_

**Default:** http-01

**Context:** acme_issuer

_This directive appeared in version 0.2.0._

Specifies the ACME challenge type to be used for the issuer.

Accepted values:

- `http-01` (`http`)
- `tls-alpn-01` (`tls-alpn`)

_ACME challenges are versioned. If an unversioned name is specified,
the module automatically selects the latest implemented version._

### contact

**Syntax:** **`contact`** _`URL`_

**Default:** -

**Context:** acme_issuer

Sets an array of URLs that the ACME server can use to contact the client
regarding account issues.
The `mailto:` scheme will be used unless specified explicitly.

### external_account_key

**Syntax:** **`external_account_key`** _`kid`_ _`file`_

**Default:** -

**Context:** acme_issuer

_This directive appeared in version 0.2.0._

Specifies a key identifier _`kid`_ and a _`file`_ with the MAC key for
[external account authorization][RFC8555#eab].

The value `data`:_`key`_ can be specified instead of the _`file`_, which loads
a key directly from the configuration without using intermediate files.

In both cases, the key is expected to be encoded in
[base64url](https://datatracker.ietf.org/doc/html/rfc4648#section-5).

[RFC8555#eab]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.4

### preferred_chain

**Syntax:** **`preferred_chain`** _`name`_

**Default:** -

**Context:** acme_issuer

_This directive appeared in version 0.3.0._

Specifies the preferred certificate chain.

If the ACME server offers multiple certificate chains,
prefer the chain with the topmost certificate issued from the
Subject Common Name _`name`_.
If there are no matches, the default chain will be used.

### profile

**Syntax:** **`profile`** _`name`_ \[`require`]

**Default:** -

**Context:** acme_issuer

_This directive appeared in version 0.3.0._

Requests the [certificate profile][draft-ietf-acme-profiles]
_`name`_ from the ACME server.

The `require` parameter will cause certificate renewals
to fail if the server does not support the specified profile.

### ssl_trusted_certificate

**Syntax:** **`ssl_trusted_certificate`** _`file`_

**Default:** system CA bundle

**Context:** acme_issuer

Specifies a _`file`_ with trusted CA certificates in the PEM format
used to [verify](#ssl_verify) the certificate of the ACME server.

### ssl_verify

**Syntax:** **`ssl_verify`** `on` | `off`

**Default:** on

**Context:** acme_issuer

Enables or disables verification of the ACME server certificate.

### state_path

**Syntax:** **`state_path`** _`path`_ | `off`

**Default:** acme_&lt;name&gt;

**Context:** acme_issuer

Defines a directory for storing the module data that can be persisted
across restarts.
This can improve the load time by skipping some requests on startup,
and avoid hitting request rate limits on the ACME server.

The directory contains sensitive content, such as
the account key, issued certificates, and private keys.

The `off` parameter (0.2.0) disables storing the account
information and issued certificates on disk.

_Prior to version 0.2.0, the state directory was not created by default._

### accept_terms_of_service

**Syntax:** **`accept_terms_of_service`**

**Default:** -

**Context:** acme_issuer

Agrees to the terms of service under which the ACME server will be used.
Some servers require accepting the terms of service before account registration.
The terms are usually available on the ACME server's website,
and the URL will be printed to the error log if necessary.

### acme_shared_zone

**Syntax:** **`acme_shared_zone`** `zone`=_`name`_:_`size`_

**Default:** zone=ngx_acme_shared:256k

**Context:** http

Allows increasing the size of in-memory storage of the module.
The shared memory zone will be used to store the issued certificates,
keys and challenge data for all the configured certificate issuers.

The default zone size is sufficient to hold approximately
50 ECDSA prime256v1 keys or 35 RSA 2048 keys.

### acme_certificate

**Syntax:** **`acme_certificate`** _`issuer`_ \[_`identifier`_ ...] \[`key`=_`alg`_\[:_`size`_]]

**Default:** -

**Context:** server

Defines a certificate with the list of _`identifiers`_ requested from
issuer _`issuer`_.

The explicit list of identifiers can be omitted. In this case, the identifiers
will be taken from the [server_name] directive in the same [server] block.
Not all values accepted in the [server_name] are valid certificate identifiers:
regular expressions and wildcards are not supported.

[server_name]: https://nginx.org/en/docs/http/ngx_http_core_module.html#server_name
[server]: https://nginx.org/en/docs/http/ngx_http_core_module.html#server

The `key` parameter sets the type of a generated private key.
Supported key algorithms and sizes:
`ecdsa:256` (default), `ecdsa:384`, `ecdsa:521`,
`rsa:2048`, `rsa:3072`, `rsa:4096`.

## Embedded Variables

The `ngx_http_acme_module` module supports embedded variables, valid in the
[server] block with the [acme_certificate](#acme_certificate) directive:

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
