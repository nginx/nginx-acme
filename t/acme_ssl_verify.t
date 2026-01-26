#!/usr/bin/perl

# Copyright (c) F5, Inc.
#
# This source code is licensed under the Apache License, Version 2.0 license
# found in the LICENSE file in the root directory of this source tree.

# Tests for ACME client: ssl server verification option.

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

my $t = Test::Nginx->new()->has(qw/http http_ssl proxy sni socket_ssl_sni/)
	->has_daemon('openssl');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    # suppress error logs from test connection attempts
    error_log stderr emerg;

    resolver 127.0.0.1:%%PORT_8980_UDP%%;

    acme_issuer verify-off {
        uri https://bad.acme.test:%%PORT_9000%%/dir;
        ssl_verify off;

        account_key %%TESTDIR%%/account.key;
        state_path %%TESTDIR%%;
        accept_terms_of_service;
    }

    server {
        listen       127.0.0.1:8443 ssl;

        server_name       verify-off.example.test;
        acme_certificate  verify-off;

        ssl_certificate $acme_certificate;
        ssl_certificate_key $acme_certificate_key;
    }


    acme_issuer verify-off-ip {
        uri https://127.0.0.1:%%PORT_9002%%/dir;
        ssl_trusted_certificate %%TESTDIR%%/second.acme.test.crt;
        ssl_verify off;

        account_key %%TESTDIR%%/account.key;
        state_path %%TESTDIR%%;
        accept_terms_of_service;
    }

    server {
        listen       127.0.0.1:8443 ssl;

        server_name       verify-off-ip.example.test;
        acme_certificate  verify-off-ip;

        ssl_certificate $acme_certificate;
        ssl_certificate_key $acme_certificate_key;
    }


    acme_issuer verify-bad-ca {
        uri https://first.acme.test:%%PORT_9000%%/dir;
        ssl_trusted_certificate %%TESTDIR%%/first.ca.crt;

        account_key %%TESTDIR%%/account.key;
        state_path %%TESTDIR%%;
        accept_terms_of_service;
    }

    server {
        listen       127.0.0.1:8443 ssl;

        server_name       verify-bad-ca.example.test;
        acme_certificate  verify-bad-ca;

        ssl_certificate $acme_certificate;
        ssl_certificate_key $acme_certificate_key;
    }


    acme_issuer verify-bad-name {
        uri https://bad.acme.test:%%PORT_9000%%/dir;
        ssl_trusted_certificate %%TESTDIR%%/first.acme.test.crt;

        account_key %%TESTDIR%%/account.key;
        state_path %%TESTDIR%%;
        accept_terms_of_service;
    }

    server {
        listen       127.0.0.1:8443 ssl;

        server_name       verify-bad-name.example.test;
        acme_certificate  verify-bad-name;

        ssl_certificate $acme_certificate;
        ssl_certificate_key $acme_certificate_key;
    }


    acme_issuer verify-bad-ip {
        uri https://127.0.0.1:%%PORT_9002%%/dir;
        ssl_trusted_certificate %%TESTDIR%%/second.acme.test.crt;

        account_key %%TESTDIR%%/account.key;
        state_path %%TESTDIR%%;
        accept_terms_of_service;
    }

    server {
        listen       127.0.0.1:8443 ssl;

        server_name       verify-bad-ip.example.test;
        acme_certificate  verify-bad-ip;

        ssl_certificate $acme_certificate;
        ssl_certificate_key $acme_certificate_key;
    }


    acme_issuer verify-good {
        uri https://first.acme.test:%%PORT_9000%%/dir;
        ssl_trusted_certificate %%TESTDIR%%/first.acme.test.crt;

        account_key %%TESTDIR%%/account.key;
        state_path %%TESTDIR%%;
        accept_terms_of_service;
    }

    server {
        listen       127.0.0.1:8443 ssl;

        server_name       verify-good.example.test;
        acme_certificate  verify-good;

        ssl_certificate $acme_certificate;
        ssl_certificate_key $acme_certificate_key;
    }


    acme_issuer verify-good-alt {
        uri https://alt.acme.test:%%PORT_9000%%/dir;
        ssl_trusted_certificate %%TESTDIR%%/first.acme.test.crt;

        account_key %%TESTDIR%%/account.key;
        state_path %%TESTDIR%%;
        accept_terms_of_service;
    }

    server {
        listen       127.0.0.1:8443 ssl;

        server_name       verify-good-alt.example.test;
        acme_certificate  verify-good-alt;

        ssl_certificate $acme_certificate;
        ssl_certificate_key $acme_certificate_key;
    }


    acme_issuer verify-good-ip {
        uri https://127.0.0.1:%%PORT_9000%%/dir;
        ssl_trusted_certificate %%TESTDIR%%/first.acme.test.crt;

        account_key %%TESTDIR%%/account.key;
        state_path %%TESTDIR%%;
        accept_terms_of_service;
    }

    server {
        listen       127.0.0.1:8443 ssl;

        server_name       verify-good-ip.example.test;
        acme_certificate  verify-good-ip;

        ssl_certificate $acme_certificate;
        ssl_certificate_key $acme_certificate_key;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  example.test;
    }
}

EOF

$t->write_file('first.acme.test.openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
x509_extensions = v3_req
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
[ v3_req ]
subjectAltName = DNS:first.acme.test,DNS:alt.acme.test,IP:127.0.0.1,IP:::1
EOF

$t->write_file('second.acme.test.openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
x509_extensions = v3_req
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
[ v3_req ]
subjectAltName = DNS:second.acme.test
EOF


my $d = $t->testdir();

foreach my $name ('first.acme.test', 'second.acme.test') {
	system('openssl req -x509 -new '
		. "-config $d/$name.openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

system("openssl ecparam -genkey -out $d/account.key -name prime256v1 "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create account key: $!\n";

my $dp = port(8980, udp=>1);
my @dc = (
	{ match => qr/^(\w[\w-]*\.)?acme\.test$/, A => '127.0.0.1' },
	{ match => qr/^(\w[\w-]*\.)?example\.test$/, A => '127.0.0.1' },
);

my $first = Test::Nginx::ACME->new($t, port(9000), port(9001),
	$t->testdir . '/first.acme.test.crt',
	$t->testdir . '/first.acme.test.key',
	http_port => port(8080),
	dns_port => $dp,
	noncereject => 0,
	nosleep => 1,
);

my $second = Test::Nginx::ACME->new($t, port(9002), port(9003),
	$t->testdir . '/second.acme.test.crt',
	$t->testdir . '/second.acme.test.key',
	http_port => port(8080),
	dns_port => $dp,
	noncereject => 0,
	nosleep => 1,
);

$t->run_daemon(\&Test::Nginx::DNS::dns_test_daemon, $t, $dp, \@dc);
$t->waitforfile($t->testdir . '/' . $dp);

$t->run_daemon(\&Test::Nginx::ACME::acme_test_daemon, $t, $first);
$t->waitforsocket('127.0.0.1:' . $first->port());
$t->write_file('first.ca.crt', $first->trusted_ca());

$t->run_daemon(\&Test::Nginx::ACME::acme_test_daemon, $t, $second);
$t->waitforsocket('127.0.0.1:' . $second->port());
$t->write_file('second.ca.crt', $second->trusted_ca());

$t->write_file('index.html', 'SUCCESS');
$t->plan(8)->run();

###############################################################################

ok(check('verify-off.example.test', 'first.ca'), 'verify off - name');
ok(check('verify-off-ip.example.test', 'second.ca'), 'verify off - ip');
ok(check('verify-good.example.test', 'first.ca'), 'verify ok - name');
ok(check('verify-good-alt.example.test', 'first.ca'), 'verify ok - alt name');
ok(check('verify-good-ip.example.test', 'first.ca'), 'verify ok - ip');

select undef, undef, undef, 5.0;

$t->stop();

my $log = $t->read_file('error.log');

like($log, qr/\[warn].*upstream SSL certificate.*"verify-bad-ca"/m,
	'no verify - bad ca');
like($log, qr/\[warn].*upstream SSL certificate.*"verify-bad-name"/m,
	'no verify - bad name');
like($log, qr/\[warn].*upstream SSL certificate.*"verify-bad-ip"/m,
	'no verify - bad ip');

###############################################################################

sub get {
	my ($host, $ca) = @_;

	$ca = undef if $IO::Socket::SSL::VERSION < 2.062
		|| !eval { Net::SSLeay::X509_V_FLAG_PARTIAL_CHAIN() };

	http_get('/',
		PeerAddr => '127.0.0.1:' . port(8443),
		SSL => 1,
		$ca ? (
		SSL_ca_file => "$d/$ca.crt",
		SSL_hostname => $host,
		SSL_verifycn_name => $host,
		SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
		) : ()
	);
}

sub check {
	my ($host, $ca) = @_;
	my $s;

	for (1 .. 100) {
		return 1 if defined get($host, $ca);

		select undef, undef, undef, 0.2;
	}
}

###############################################################################
