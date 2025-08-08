#!/usr/bin/perl

# Copyright (c) F5, Inc.
#
# This source code is licensed under the Apache License, Version 2.0 license
# found in the LICENSE file in the root directory of this source tree.

# Tests for ACME client: configuration parsing and validation.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_ssl/)->plan(7);

use constant TEMPLATE_CONF => <<'EOF';

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  example.test;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  example.test;

        acme_certificate example example.test;

        ssl_certificate $acme_certificate;
        ssl_certificate_key $acme_certificate_key;
    }

    %%ACME_ISSUER%%
}

EOF

###############################################################################

is(check($t, <<'EOF' ), undef, 'valid');

acme_shared_zone zone=ngx_acme_shared:1M;

acme_issuer example {
    uri https://localhost:%%PORT_9000%%/dir;
    account_key ecdsa:256;
    contact admin@example.test;
    ssl_verify off;
    state_path %%TESTDIR%%;
    accept_terms_of_service;
}

resolver 127.0.0.1:%%PORT_8980_UDP%%;
resolver_timeout 5s;

EOF


like(check($t, <<'EOF' ), qr/\[emerg].*"resolver" is not/, 'no resolver');

acme_issuer example {
    uri https://localhost:%%PORT_9000%%/dir;
    ssl_verify off;
}

EOF


like(check($t, <<'EOF' ), qr/\[emerg].*must have "zone"/, 'bad zone value');

acme_shared_zone bad-value;

acme_issuer example {
    uri https://localhost:%%PORT_9000%%/dir;
    ssl_verify off;
}

resolver 127.0.0.1:%%PORT_8980_UDP%%;

EOF


like(check($t, <<'EOF' ), qr/\[emerg].*invalid zone size/, 'bad zone size');

acme_shared_zone zone=test:bad-size;

acme_issuer example {
    uri https://localhost:%%PORT_9000%%/dir;
    ssl_verify off;
}

resolver 127.0.0.1:%%PORT_8980_UDP%%;

EOF


like(check($t, <<'EOF' ), qr/\[emerg].*cannot load/, 'bad key file');

acme_issuer example {
    uri https://localhost:%%PORT_9000%%/dir;
    account_key no-such-file.key;
    ssl_verify off;
}

resolver 127.0.0.1:%%PORT_8980_UDP%%;

EOF


like(check($t, <<'EOF' ), qr/\[emerg].*unsupported curve/, 'bad key curve');

acme_issuer example {
    uri https://localhost:%%PORT_9000%%/dir;
    account_key ecdsa:234;
    ssl_verify off;
}

resolver 127.0.0.1:%%PORT_8980_UDP%%;

EOF


like(check($t, <<'EOF' ), qr/\[emerg].*unsupported key size/, 'bad key size');

acme_issuer example {
    uri https://localhost:%%PORT_9000%%/dir;
    account_key rsa:1024;
    ssl_verify off;
}

resolver 127.0.0.1:%%PORT_8980_UDP%%;

EOF

# stop and clear the log to avoid triggering sanitizer checks

$t->stop()->write_file('error.log', '');

###############################################################################

sub check {
	my ($t, $issuer) = @_;

	$t->write_file_expand('nginx.conf',
		TEMPLATE_CONF =~ s/%%ACME_ISSUER%%/$issuer/r);

	return try_run($t);
}

sub try_run {
	my $t = shift;

	# clean up after a successfull try

	$t->stop();
	unlink $t->testdir() . '/error.log';

	eval {
		open OLDERR, ">&", \*STDERR; close STDERR;
		$t->run();
		open STDERR, ">&", \*OLDERR;
	};

	return unless $@;

	my $log = $t->read_file('error.log');

	if ($ENV{TEST_NGINX_VERBOSE}) {
		map { Test::Nginx::log_core($_) } split(/^/m, $log);
	}

	return $log;
}
