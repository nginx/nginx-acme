# Changelog

## 0.2.0 (October 8, 2025)

Breaking changes:

* Per-issuer state directory is now created even if not configured.
  To change the prefix for default state paths, set `NGX_ACME_STATE_PREFIX`
  environment variable during build (e.g. to `/var/lib/nginx`).
  To disable the persistent state in configuration, use `state_path off`.

Features:

* The `external_account_key` directive allows configuring external account
  binding.
* Support for the `tls-alpn-01` challenge. The `challenge` directive in the
  `acme_issuer` block now allows specifying a challenge to use.
* Account URL now can be read from a file under state path.

Bugfixes:

* Compatibility with Dogtag PKI, EJBCA, OpenBao and Vault.
* Improved logs and error reporting.
* Stability and memory usage improvements.
* Updated ngx-rust from git dependency to a released version.

## 0.1.1 (August 11, 2025)

Initial release.

* Base ACME protocol.
* HTTP-01 challenge support.
