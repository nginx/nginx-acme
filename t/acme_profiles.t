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

eval { require Date::Parse; };
plan(skip_all => 'Date::Parse is not installed') if $@;

eval { defined &Net::SSLeay::P_ASN1_TIME_get_isotime or die; };
plan(skip_all => 'no P_ASN1_TIME_get_isotime, old Net::SSLeay') if $@;

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

my $dp = port(8980, udp=>1);
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

$t->run_daemon(\&Test::Nginx::DNS::dns_test_daemon, $t, $dp, \@dc);
$t->waitforfile($t->testdir . '/' . $dp);

$t->run_daemon(\&Test::Nginx::ACME::acme_test_daemon, $t, $acme);
$t->waitforsocket('127.0.0.1:' . $acme->port());
$t->write_file('acme-root.crt', $acme->trusted_ca());

$t->write_file('index.html', 'SUCCESS');
$t->plan(2)->run();

###############################################################################

$acme->wait_certificate('acme_default/example.test') or die "no certificate";
$acme->wait_certificate('acme_shortlived/shortlived.test')
	or die "no certificate";

my $valid = get(8443, 'example.test', 'acme-root');

ok(defined $valid && $valid > 2 * 86400, 'default profile');

$valid = get(8444, 'shortlived.test', 'acme-root');

ok(defined $valid && $valid < 86400, 'shortlived profile');

###############################################################################

sub get {
	my ($port, $host, $ca) = @_;

	$ca = undef if $IO::Socket::SSL::VERSION < 2.062
		|| !eval { Net::SSLeay::X509_V_FLAG_PARTIAL_CHAIN() };

	my $s = http_get(
		'/', start => 1, PeerAddr => '127.0.0.1:' . port($port),
		SSL => 1,
		$ca ? (
		SSL_ca_file => "$d/$ca.crt",
		SSL_verifycn_name => $host,
		SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
		) : ()
	);

	return $s unless $s;

	my $ssl = $s->_get_ssl_object();
	my $cert = Net::SSLeay::get_peer_certificate($ssl);

	return cert_validity($cert);
}

sub cert_validity {
	my ($cert) = @_;

	my $notAfter = Net::SSLeay::X509_get_notAfter($cert) or return;
	$notAfter = Net::SSLeay::P_ASN1_TIME_get_isotime($notAfter) or return;
	$notAfter = Date::Parse::str2time($notAfter) or return;
	return $notAfter - time();
}

###############################################################################
