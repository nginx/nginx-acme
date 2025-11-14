#!/usr/bin/perl

# Copyright (c) F5, Inc.
#
# This source code is licensed under the Apache License, Version 2.0 license
# found in the LICENSE file in the root directory of this source tree.

# Tests for ACME client: preferred chain support.

###############################################################################

use warnings;
use strict;

use Test::More;

use Net::SSLeay qw/ die_now /;

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

my $conf = <<'EOF';

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver 127.0.0.1:%%PORT_8980_UDP%%;

    acme_issuer default {
        uri https://acme.test:%%PORT_9000%%/dir;
        ssl_trusted_certificate acme.test.crt;
        state_path %%TESTDIR%%/acme_default;
        accept_terms_of_service;
    }

    acme_issuer chain1 {
        uri https://acme.test:%%PORT_9000%%/dir;
        preferred_chain "%%ISSUER_NAME_1%%";
        ssl_trusted_certificate acme.test.crt;
        state_path %%TESTDIR%%/acme_chain1;
        accept_terms_of_service;
    }

    acme_issuer chain2 {
        uri https://acme.test:%%PORT_9000%%/dir;
        preferred_chain "%%ISSUER_NAME_2%%";
        ssl_trusted_certificate acme.test.crt;
        state_path %%TESTDIR%%/acme_chain2;
        accept_terms_of_service;
    }

    ssl_certificate $acme_certificate;
    ssl_certificate_key $acme_certificate_key;

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  example.test;

        acme_certificate  default;
    }

    server {
        listen       127.0.0.1:8444 ssl;
        server_name  example.test;

        acme_certificate  chain1;
    }

    server {
        listen       127.0.0.1:8445 ssl;
        server_name  example.test;

        acme_certificate  chain2;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  example.test;
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
	{ name => 'example.test', A => '127.0.0.1' }
);

my $acme = Test::Nginx::ACME->new($t, port(9000), port(9001),
	$t->testdir . '/acme.test.crt',
	$t->testdir . '/acme.test.key',
	alternate_roots => 2,
	http_port => port(8080),
	dns_port => $dp,
	nosleep => 1,
);

$t->run_daemon(\&Test::Nginx::DNS::dns_test_daemon, $t, $dp, \@dc);
$t->waitforfile($t->testdir . '/' . $dp);

$t->run_daemon(\&Test::Nginx::ACME::acme_test_daemon, $t, $acme);
$t->waitforsocket('127.0.0.1:' . $acme->port());
$t->write_file('acme-root-0.crt', $acme->trusted_ca(0));
$t->write_file('acme-root-1.crt', $acme->trusted_ca(1));
$t->write_file('acme-root-2.crt', $acme->trusted_ca(2));

# Pebble Root name is randomly generated

my $cn = cert_name($t->testdir . '/acme-root-1.crt')
	or die "Can't get CA certificate name: $!";
$conf =~ s/%%ISSUER_NAME_1%%/$cn/;

$cn = cert_name($t->testdir . '/acme-root-2.crt')
	or die "Can't get CA certificate name: $!";
$conf =~ s/%%ISSUER_NAME_2%%/$cn/;

$t->write_file_expand('nginx.conf', $conf);

$t->write_file('index.html', 'SUCCESS');
$t->plan(5)->run();

###############################################################################

$acme->wait_certificate('acme_default/example.test') or die "no certificate";
$acme->wait_certificate('acme_chain1/example.test') or die "no certificate";
$acme->wait_certificate('acme_chain2/example.test') or die "no certificate";

like(get(8443, 'example.test', 'acme-root-0'), qr/SUCCESS/, 'default');

like(get(8444, 'example.test', 'acme-root-1'), qr/SUCCESS/, 'chain 1');
is(get(8444, 'example.test', 'acme-root-0'), undef, 'chain 1 - wrong root');

like(get(8445, 'example.test', 'acme-root-2'), qr/SUCCESS/, 'chain 2');
is(get(8445, 'example.test', 'acme-root-0'), undef, 'chain 2 - wrong root');

###############################################################################

sub get {
	my ($port, $host, $ca) = @_;

	$ca = undef if $IO::Socket::SSL::VERSION < 2.062
		|| !eval { Net::SSLeay::X509_V_FLAG_PARTIAL_CHAIN() };

	http_get('/',
		PeerAddr => '127.0.0.1:' . port($port),
		SSL => 1,
		$ca ? (
		SSL_ca_file => "$d/$ca.crt",
		SSL_verifycn_name => $host,
		SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
		) : ()
	);
}

sub cert_name {
	my ($filename) = @_;

	my $bio = Net::SSLeay::BIO_new_file($filename, 'r')
		or die_now("BIO_new_file() failed: $!");

	my $cert = Net::SSLeay::PEM_read_bio_X509($bio)
		or die_now("PEM_read_bio_X509() failed: $!");

	my $name = Net::SSLeay::X509_get_subject_name($cert)
		or die_now("X509_get_subject_name() failed: $!");

	return Net::SSLeay::X509_NAME_get_text_by_NID(
		$name,
		Net::SSLeay::NID_commonName()
	);
}

###############################################################################
