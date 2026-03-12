#!/usr/bin/perl

# Copyright (c) F5, Inc.
#
# This source code is licensed under the Apache License, Version 2.0 license
# found in the LICENSE file in the root directory of this source tree.

# Tests for ACME client: key algorithm configuration.

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

$t->todo_alerts() if $^O eq 'netbsd';

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver 127.0.0.1:%%PORT_8980_UDP%%;

    server_names_hash_bucket_size 64;

    acme_issuer default {
        uri https://acme.test:%%PORT_9000%%/dir;
        ssl_trusted_certificate acme.test.crt;
        state_path %%TESTDIR%%;
        accept_terms_of_service;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  .example.test;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  ecdsa.example.test;

        acme_certificate default
                         ecdsa.example.test
                         example.test
                         key=ecdsa;

        ssl_certificate $acme_certificate;
        ssl_certificate_key $acme_certificate_key;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  rsa.example.test;

        acme_certificate default
                         rsa.example.test
                         example.test
                         key=rsa;

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
	{ match => qr/^(\w+\.)?example.test$/, A => '127.0.0.1' }
);

my $acme = Test::Nginx::ACME->new($t, port(9000), port(9001),
	$t->testdir . '/acme.test.crt',
	$t->testdir . '/acme.test.key',
	http_port => port(8080),
	dns_port => $dp,
	nosleep => 1,
);

$t->run_daemon(\&Test::Nginx::DNS::dns_test_daemon, $t, 8980, \@dc, tcp => 1);
$t->waitforfile($t->testdir . '/' . $dp);
port(8980, socket => 1)->close();

$t->run_daemon(\&Test::Nginx::ACME::acme_test_daemon, $t, $acme);
$t->waitforsocket('127.0.0.1:' . $acme->port());

$t->plan(2)->run();

###############################################################################

$acme->wait_certificate('ecdsa.example.test') or die "no certificate";
$acme->wait_certificate('rsa.example.test') or die "no certificate";

is(get('rsa.example.test'), 'rsaEncryption', 'RSA certificate');
is(get('ecdsa.example.test'), 'id-ecPublicKey', 'ECDSA certificate');

###############################################################################

sub get {
	my ($host) = @_;

	return $acme->peer_certificate($host, format => \&x509_pubkey_alg);
}

sub x509_pubkey_alg {
	my ($x509) = @_;

	my $alg = Net::SSLeay::P_X509_get_pubkey_alg($x509);
	return Net::SSLeay::OBJ_obj2txt($alg);
}

###############################################################################
