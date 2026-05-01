# Changelog

## 0.4.1 (May 1, 2026)

Bugfixes:

* Possible crash during name resolution (via ngx v0.5.1).

## 0.4.0 (April 20, 2026)

Changes:

* Subject Common Name is no longer included in CSRs, as it is optional,
  cannot accommodate long domain names and can be rejected by some ACME issuers.
  This may result in issuing certificates with empty Subject Common Name. Such
  certificates are valid and should be accepted by any user agents.
  The `common_name_in_csr` directive allows restoring the previous behavior.
* Renewal time for short-lived (less than 10 days) certificates is adjusted
  to the half of the certificate lifetime.
* Some user-facing log messages (info, notices, warnings and errors) were
  modified.

Features:

* ACME Renewal Information checking is now supported and always enabled with
  compatible ACME CAs.

Bugfixes:

* Default acme_shared_zone size was insufficient on systems with 64k page size.
* Log messages were not emitted on an expected log level.
* Server certificate names were not verified when connecting to an issuer
  specified with IP address.
* Server connection could fail when either IPv6 or IPv4 network is unreachable.
* tls-alpn-01 challenge could generate an invalid certificate for domain names
  longer than 64 characters.

## 0.3.1 (December 8, 2025)

Bugfixes:

* Build error with NGINX 1.29.4.
* Directory URI without path could not be fetched.

## 0.3.0 (November 18, 2025)

Features:

* The `preferred_chain` directive allows selecting alternative certificate
  chains.
* The `profile` directive allows specifying preferred certificate profile.
* Requesting certificates for IP addresses is now documented and officially
  supported.

Bugfixes:

* Directory metadata could not be parsed with certain fields set to `null`.
  Thanks to Marian Degel.
* Directory requests failed to handle HTTP redirects.
  Thanks to Marian Degel.
* Relative `state_path` was not using `NGX_ACME_STATE_PREFIX`.
* Build error with BoringSSL (via rust-openssl update).
* Build error on NetBSD 10 (via rust-openssl update).

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
