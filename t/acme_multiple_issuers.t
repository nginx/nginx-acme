#!/usr/bin/perl

# Copyright (c) F5, Inc.
#
# This source code is licensed under the Apache License, Version 2.0 license
# found in the LICENSE file in the root directory of this source tree.

# Tests for ACME client: configuration with multiple ACME issuers.

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

my $t = Test::Nginx->new()->has(qw/http http_ssl sni socket_ssl_sni/)
	->has_daemon('openssl');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver 127.0.0.1:%%PORT_8980_UDP%%;

    acme_issuer first {
        uri https://acme.test:%%PORT_9000%%/dir;
        ssl_trusted_certificate acme.test.crt;
        state_path %%TESTDIR%%/first;
        accept_terms_of_service;
    }

    acme_issuer second {
        uri https://acme.test:%%PORT_9002%%/dir;
        ssl_trusted_certificate acme.test.crt;
        state_path %%TESTDIR%%/second;
        accept_terms_of_service;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  .first.test .second.test;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  .first.test;

        acme_certificate first;

        ssl_certificate $acme_certificate;
        ssl_certificate_key $acme_certificate_key;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  .second.test;

        acme_certificate second;

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

my $dp = port(8980, udp=>1);
my @dc = (
	{ name => 'acme.test', A => '127.0.0.1' },
	{ match => qr/^(www\.)?first.test$/, A => '127.0.0.1' },
	{ match => qr/^(www\.)?second.test$/, A => '127.0.0.1' },
);

my $acme1 = Test::Nginx::ACME->new($t, port(9000), port(9001),
	$t->testdir . '/acme.test.crt',
	$t->testdir . '/acme.test.key',
	http_port => port(8080),
	dns_port => $dp,
	nosleep => 1,
	state => $t->testdir . '/first',
);

my $acme2 = Test::Nginx::ACME->new($t, port(9002), port(9003),
	$t->testdir . '/acme.test.crt',
	$t->testdir . '/acme.test.key',
	http_port => port(8080),
	dns_port => $dp,
	nosleep => 1,
	state => $t->testdir . '/second',
);


$t->run_daemon(\&Test::Nginx::DNS::dns_test_daemon, $t, $dp, \@dc);
$t->waitforfile($t->testdir . '/' . $dp);

$t->run_daemon(\&Test::Nginx::ACME::acme_test_daemon, $t, $acme1);
$t->waitforsocket('127.0.0.1:' . $acme1->port());
$t->write_file('acme-root-1.crt', $acme1->trusted_ca());

$t->run_daemon(\&Test::Nginx::ACME::acme_test_daemon, $t, $acme2);
$t->waitforsocket('127.0.0.1:' . $acme2->port());
$t->write_file('acme-root-2.crt', $acme2->trusted_ca());

$t->write_file('index.html', 'SUCCESS');
$t->plan(2)->run();

###############################################################################

$acme1->wait_certificate('first.test') or die "no certificate";
$acme2->wait_certificate('second.test') or die "no certificate";

like(get(8443, 'first.test', 'acme-root-1'), qr/SUCCESS/, 'tls request - 1');
like(get(8443, 'second.test', 'acme-root-2'), qr/SUCCESS/, 'tls request - 2');

###############################################################################

sub get {
	my ($port, $host, $ca) = @_;

	$ca = undef if $IO::Socket::SSL::VERSION < 2.062
		|| !eval { Net::SSLeay::X509_V_FLAG_PARTIAL_CHAIN() };

	http_get('/',
		PeerAddr => '127.0.0.1:' . port($port),
		SSL => 1,
		SSL_hostname => $host,
		$ca ? (
		SSL_ca_file => "$d/$ca.crt",
		SSL_verifycn_name => $host,
		SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
		) : ()
	);
}

###############################################################################
