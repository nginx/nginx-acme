#!/usr/bin/perl

# Copyright (c) F5, Inc.
#
# This source code is licensed under the Apache License, Version 2.0 license
# found in the LICENSE file in the root directory of this source tree.

# Tests for ACME client: ACME Renewal Info (RFC 9773).

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

# shutdown() failed (22: Invalid argument)
$t->todo_alerts() if $^O eq 'netbsd';

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    # suppress error logs from test connection attempts
    error_log %%TESTDIR%%/error.log warn;

    resolver 127.0.0.1:%%PORT_8980_UDP%%;

    acme_issuer default {
        uri https://acme.test:%%PORT_9000%%/dir;
        ssl_trusted_certificate acme.test.crt;
        state_path %%TESTDIR%%;
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
);

my $acme = Test::Nginx::ACME->new($t, port(9000), port(9001),
	$t->testdir . '/acme.test.crt',
	$t->testdir . '/acme.test.key',
	http_port => port(8080),
	dns_port => $dp,
	nosleep => 1,
	validity => 3600,
)->has(qw/ari/);

$t->run_daemon(\&Test::Nginx::DNS::dns_test_daemon, $t, 8980, \@dc, tcp => 1);
$t->waitforfile($t->testdir . '/' . $dp);
port(8980, socket => 1)->close();

$t->run_daemon(\&Test::Nginx::ACME::acme_test_daemon, $t, $acme);
$t->waitforsocket('127.0.0.1:' . $acme->port());

$t->plan(3)->run();

###############################################################################

select undef, undef, undef, 2.0;

my $cert1 = wait_certificate('example.test') or die "no certificate";
my $now = time();

like($acme->set_renewal_info($cert1, $now - 60, $now),
	qr/200 OK/, 'set ARI response');

# Pebble sets Retry-After to 6h for the initial ARI response.
# The only way to make the check sooner is to do a full restart.

$t->stop()->run();

is(wait_certificate('example.test'), $cert1, 'restart - restored');

select undef, undef, undef, 2.0;

my $cert2;

for (1 .. 30) {
	$cert2 = $acme->peer_certificate('example.test');
	last if defined $cert2 && $cert2 ne $cert1;
	select undef, undef, undef, 0.5;
}

ok(defined $cert2 && $cert2 ne $cert1, 'restart - expired and reissued');

###############################################################################

sub wait_certificate {
	my ($host) = @_;
	my $cert;

	for (1 .. 30) {
		return $cert if $cert = $acme->peer_certificate($host);
		select undef, undef, undef, 0.5;
	}
}

###############################################################################
