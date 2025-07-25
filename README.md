# nginx-acme

nginx-acme is an [NGINX] module with the implementation of the automatic
certificate management ([ACME]) protocol.

[NGINX]: https://nginx.org/
[ACME]: https://www.rfc-editor.org/rfc/rfc8555.html

## Building

### Requirements

- Regular nginx build dependencies
- System-wide installation of OpenSSL 1.1.1 or later
- Rust toolchain (1.81.0 or later)

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
the linker to perform LTO and dead code elimination.

## How to Use

Add the module to the nginx configuration and configure as described below.

## Example Configuration

```nginx
resolver 127.0.0.1:53;

acme_issuer example {
    uri         https://acme.example.com/directory;
    contact     mailto:admin@example.test;
    state_path  /var/lib/nginx/acme-example;
}

acme_shared_zone zone=acme_shared:1M;

server {
    listen 443 ssl;
    server_name  .example.test;

    acme_certificate example;

    ssl_certificate       $acme_certificate;
    ssl_certificate_key   $acme_certificate_key;

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
of the ACME server. This is the only mandatory parameter in the
[](#acme_issuer) block.

### account_key

**Syntax:** account_key `alg[:size]` | `file`

**Default:** -

**Context:** acme_issuer

The account's private key used for request authentication.
Accepted values:

- `ecdsa:256/384/521` for `ES256` / `ES384` / `ES512` JSON Web Signature algorithms
- `rsa:2048..4096` for `RS256` .
- File path for an existing key, using one of the algorithms above.

The generated account keys are preserved across reloads, but will be lost on
restart unless [](#state_path) is configured.

### contact

**Syntax:** contact `url`

**Default:** -

**Context:** acme_issuer

An array of URLs that the ACME server can use to contact the client for issues
related to this account.

Can be specified multiple times.

### resolver

**Syntax:** resolver `address` ... [ `valid` = `time` ] [ `ipv4` = `on` | `off` ] [ `ipv6` = `on` | `off` ] [ `status_zone` = `zone` ]

**Default:** -

**Context:** acme_issuer

Configures name servers used to resolve names of upstream servers into
addresses.
See [resolver](https://nginx.org/en/docs/http/ngx_http_core_module.html#resolver)
for the parameter reference.

Required, but can be inherited from the `http` block.
### resolver_timeout

**Syntax:** resolver_timeout `time`

**Default:** 30s

**Context:** acme_issuer

Sets a timeout for name resolution, for example:

```nginx
resolver_timeout 5s;

```

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

Enables or disables verification of the ACME servier certificate.

### state_path

**Syntax:** state_path `path`

**Default:** -

**Context:** acme_issuer

Defines a directory for storing the module data that can be persisted across
restarts. This could greatly improve the time until the server is ready and
help with rate-limiting ACME servers.

The directory, if configured, will contain sensitive content:
the account key, the issued certificates and private keys.

### acme_shared_zone

**Syntax:** acme_shared_zone `zone` = `name:size`

**Default:** ngx_acme_shared:256k

**Context:** http

An optional directive that allows increasing the size of in-memory storage of
the module.
The shared memory zone will be used to store the issued certificates, keys and
challenge data for all the configured certificate issuers.

### acme_certificate

**Syntax:** acme_certificate `issuer` [`identifier` ...] [ `key` = `alg[:size]` ]

**Default:** -

**Context:** server

Defines a certificate with the list of `identifier`s requested from
issuer `issuer`.

The explicit list of identifiers can be omitted. In this case the identifiers
will be taken from the [server_name] directive in the same `server` block.
Not all the values accepted by [server_name] are valid certificate identifiers:
regular expressions and wildcards are not supported.

[server_name]: https://nginx.org/en/docs/http/ngx_http_core_module.html#server_name

The `key` parameter sets the type of a generated private key. Supported key
algorithms and sizes:
`ecdsa:256` (default), `ecdsa:384`,
`ecdsa:521`,
`rsa:2048` .. `rsa:4096`.

## Embedded Variables

The `ngx_http_acme_module` module defines following embedded
variables, valid in the `server` block with the
[acme_certificate](#acme_certificate) directive:

### ``$acme_certificate``

SSL certificate that can be passed to the
[ssl_certificate](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate).

### ``$acme_certificate_key``

SSL certificate private key that can be passed to the
[ssl_certificate_key](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate_key).

## License

[Apache License, Version 2.0](/LICENSE)

&copy; [F5, Inc.](https://www.f5.com/) 2025
