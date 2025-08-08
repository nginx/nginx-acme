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
use Test::More qw//;

use Test::Nginx qw//;

eval { require JSON::PP; };
Test::More::plan(skip_all => "JSON::PP not installed") if $@;

our $PEBBLE = $ENV{TEST_NGINX_PEBBLE_BINARY} // 'pebble';

my %features = (
	'eab' => '2.5.2', # broken in 2.5.0
	'profile' => '2.7.0',
	'validity' => '2.4.0',
);

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

	my %conf = (
		listenAddress => '127.0.0.1:' . $port,
		managementListenAddress => '127.0.0.1:' . $mgmt,
		certificate => $cert,
		privateKey => $key,
		httpPort => $http_port + 0,
		tlsPort => $tls_port + 0,
		ocspResponderURL => '',
		certificateValidityPeriod => $validity + 0,
		profiles => {
			default => {
				validityPeriod => $validity + 0,
			}
		},
	);

	# merge custom configuration

	@conf { keys %{$extra{conf}} } = values %{$extra{conf}};

	my $conf = JSON::PP->new()->canonical()->encode({ pebble => \%conf });
	$t->write_file("pebble-$port.json", $conf);

	return $self;
}

sub port {
	my $self = shift;
	$self->{port};
}

sub trusted_ca {
	my $self = shift;
	Test::Nginx::log_core('|| ACME: get certificate from', $self->{mgmt});
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

sub has {
	my ($self, @requested) = @_;

	foreach my $feature (@requested) {
		Test::More::plan(skip_all => "no $feature support in pebble")
			unless $self->has_feature($feature);
	}

	return $self;
}

sub has_feature {
	my ($self, $feature) = @_;
	my $ver;

	if (defined $features{$feature}) {
		$ver = $features{$feature};
	} elsif ($feature =~ /^pebble:([\d.]+)$/) {
		$ver = $1;
	} else {
		return 0;
	}

	$self->{_version} //= _pebble_version();
	return 0 unless $self->{_version};

	my @v = split(/\./, $self->{_version});
	my ($n, $v);

	for my $n (split(/\./, $ver)) {
		$v = shift @v || 0;
		return 0 if $n > $v;
		return 1 if $v > $n;
	}

	return 1;
}

###############################################################################

sub _pebble_version {
	my $ver = `$PEBBLE -version 2>&1`;

	if ($ver =~ /version: v?([\d.]+)/) {
		Test::Nginx::log_core('|| ACME: pebble version', $1);
		return $1;
	} elsif (defined $ver) {
		# The binary is available, but does not have the version info.
		Test::Nginx::log_core('|| ACME: pebble version unknown');
		return '0';
	}
}

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
	$ENV{PEBBLE_WFE_NONCEREJECT} =
		$acme->{noncereject} if $acme->{noncereject};

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
