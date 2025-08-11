package Test::Nginx::ACME;

# Copyright (c) F5, Inc.
#
# This source code is licensed under the Apache License, Version 2.0 license
# found in the LICENSE file in the root directory of this source tree.

# Module for nginx ACME tests.

###############################################################################

use warnings;
use strict;

use base qw/ Exporter /;
our @EXPORT_OK = qw/ acme_test_daemon /;

use File::Spec;
use Test::Nginx qw//;

our $PEBBLE = $ENV{TEST_NGINX_PEBBLE_BINARY} // 'pebble';

sub new {
	my $self = {};
	bless $self, shift @_;

	my ($t, $port, $mgmt, $cert, $key, %extra) = @_;

	$t->has_daemon($PEBBLE);

	my $http_port = $extra{http_port} || 80;
	my $tls_port = $extra{tls_port} || 443;
	my $validity = $extra{validity} || 3600;

	$self->{dns_port} = $extra{dns_port} || Test::Nginx::port(8980, udp=>1);
	$self->{noncereject} = $extra{noncereject};
	$self->{nosleep} = $extra{nosleep};

	$self->{port} = $port;
	$self->{mgmt} = $mgmt;

	$self->{state} = $extra{state} // $t->testdir();

	$t->write_file("pebble-$port.json", <<EOF);
{
    "pebble": {
        "listenAddress": "127.0.0.1:$port",
        "managementListenAddress": "127.0.0.1:$mgmt",
        "certificate": "$cert",
        "privateKey": "$key",
        "httpPort": $http_port,
        "tlsPort": $tls_port,
        "ocspResponderURL": "",
        "certificateValidityPeriod": $validity,
        "profiles": {
            "default": {
                "description": "The default profile",
                "validityPeriod": $validity
            }
        }
    }
}
EOF

	return $self;
}

sub port {
	my $self = shift;
	$self->{port};
}

sub trusted_ca {
	my $self = shift;
	Test::Nginx::log_core('|| Fetching certificate from port ', $self->{mgmt});
	my $cert = _get_body($self->{mgmt}, '/roots/0');
	$cert =~ s/(BEGIN|END) C/$1 TRUSTED C/g;
	$cert;
}

sub wait_certificate {
	my ($self, $cert, %extra) = @_;

	my $file = File::Spec->catfile($self->{'state'},
		'{www.,}' . $cert . '*.crt');

	my $timeout = ($extra{'timeout'} // 20) * 5;

	for (1 .. $timeout) {
		return 1 if defined glob($file);
		select undef, undef, undef, 0.2;
	}
}

###############################################################################

sub _get_body {
	my ($port, $uri) = @_;

	my $r = Test::Nginx::http_get($uri,
		PeerAddr => '127.0.0.1:' . $port,
		SSL => 1,
	);

	return $r =~ /.*?\x0d\x0a?\x0d\x0a?(.*)/ms && $1;
}

###############################################################################

sub acme_test_daemon {
	my ($t, $acme) = @_;
	my $port = $acme->{port};
	my $dnsserver = '127.0.0.1:' . $acme->{dns_port};

	$ENV{PEBBLE_VA_NOSLEEP} = 1 if $acme->{nosleep};
	$ENV{PEBBLE_WFE_NONCEREJECT} = $acme->{noncereject} if $acme->{noncereject};

	open STDOUT, ">", $t->testdir . '/pebble-' . $port . '.out'
		or die "Can't reopen STDOUT: $!";

	open STDERR, ">", $t->testdir . '/pebble-' . $port . '.err'
		or die "Can't reopen STDERR: $!";

	exec($PEBBLE, '-config', $t->testdir . '/pebble-' . $port . '.json',
		'-dnsserver', $dnsserver);
}

###############################################################################

1;

###############################################################################
