#!/usr/bin/perl

# Copyright (c) F5, Inc.
#
# This source code is licensed under the Apache License, Version 2.0 license
# found in the LICENSE file in the root directory of this source tree.

# Tests for ACME client: ACME Profiles Extension.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::ACME;
use Test::Nginx::DNS;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_ssl socket_ssl/)
	->has_daemon('openssl');

$t->todo_alerts() if $^O eq 'netbsd';

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver 127.0.0.1:%%PORT_8980_UDP%%;

    acme_issuer default {
        uri https://acme.test:%%PORT_9000%%/dir;
        profile default;
        ssl_trusted_certificate acme.test.crt;
        state_path %%TESTDIR%%/acme_default;
        accept_terms_of_service;
    }

    acme_issuer shortlived {
        uri https://acme.test:%%PORT_9000%%/dir;
        profile shortlived require;
        ssl_trusted_certificate acme.test.crt;
        state_path %%TESTDIR%%/acme_shortlived;
        accept_terms_of_service;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  example.test;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  example.test;

        acme_certificate default;

        ssl_certificate $acme_certificate;
        ssl_certificate_key $acme_certificate_key;
    }

    server {
        listen       127.0.0.1:8444 ssl;
        server_name  shortlived.test;

        acme_certificate shortlived;

        ssl_certificate $acme_certificate;
        ssl_certificate_key $acme_certificate_key;
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('acme.test') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

my $dp = port(8980, udp => 1);
my @dc = (
	{ name => 'acme.test', A => '127.0.0.1' },
	{ name => 'example.test', A => '127.0.0.1' },
	{ name => 'shortlived.test', A => '127.0.0.1' },
);

my $acme = Test::Nginx::ACME->new($t, port(9000), port(9001),
	$t->testdir . '/acme.test.crt',
	$t->testdir . '/acme.test.key',
	http_port => port(8080),
	dns_port => $dp,
	nosleep => 1,
	conf => {
		profiles => {
			default => {
				description => "The default profile",
				validityPeriod => 777600,
			},
			shortlived => {
				description => "A short-lived cert profile",
				validityPeriod => 86400,
			},
		},
	},
)->has(qw/profile/);

$t->run_daemon(\&Test::Nginx::DNS::dns_test_daemon, $t, 8980, \@dc, tcp => 1);
$t->waitforfile($t->testdir . '/' . $dp);
port(8980, socket => 1)->close();

$t->run_daemon(\&Test::Nginx::ACME::acme_test_daemon, $t, $acme);
$t->waitforsocket('127.0.0.1:' . $acme->port());

$t->plan(2)->run();

###############################################################################

$acme->wait_certificate('acme_default/example.test') or die "no certificate";
$acme->wait_certificate('acme_shortlived/shortlived.test')
	or die "no certificate";

my $valid = get(8443, 'example.test');

ok(defined $valid && $valid > 2 * 86400, 'default profile');

$valid = get(8444, 'shortlived.test');

ok(defined $valid && $valid < 86400, 'shortlived profile');

###############################################################################

sub get {
	my ($port, $host) = @_;

	my $cert = $acme->peer_certificate($host, format => 'hash',
		PeerAddr => '127.0.0.1:' . port($port));

	return $cert->{not_after} - time() if $cert;
}

###############################################################################
