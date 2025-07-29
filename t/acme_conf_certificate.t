#!/usr/bin/perl

# (C) Aleksei Bavshin
# (C) Nginx, Inc.

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

my $t = Test::Nginx->new()->has(qw/http http_ssl/)->plan(4);

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

        %%ACME_CERTIFICATE%%

        ssl_certificate $acme_certificate;
        ssl_certificate_key $acme_certificate_key;
    }

    acme_issuer example {
        uri https://localhost:%%PORT_9000%%/dir;
        ssl_verify off;
    }

    resolver 127.0.0.1:%%PORT_8980_UDP%%;
}

EOF

###############################################################################

is(check($t, <<'EOF' ), undef, 'valid');

acme_certificate example .example.test;

EOF


is(check($t, <<'EOF' ), undef, 'valid - server_name');

server_name .example.test;
acme_certificate example;

EOF


like(check($t, <<'EOF' ), qr/\[emerg].*no identifiers/, 'no identifiers');

acme_certificate example;

EOF


like(check($t, <<'EOF'), qr/\[emerg].*issuer "[^"]+" is missing/, 'no issuer');

acme_certificate no-such-issuer .example.test;

EOF

# stop and clear the log to avoid triggering sanitizer checks

$t->stop()->write_file('error.log', '');

###############################################################################

sub check {
	my ($t, $cert) = @_;

	$t->write_file_expand('nginx.conf',
		TEMPLATE_CONF =~ s/%%ACME_CERTIFICATE%%/$cert/r);

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
