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
use POSIX qw/ gmtime strftime /;
use Socket qw/ CRLF /;
use Test::More qw//;

use Test::Nginx qw//;

eval { require IO::Socket::SSL::Utils; };
Test::More::plan(skip_all => "IO::Socket::SSL not installed") if $@;

eval { require JSON::PP; };
Test::More::plan(skip_all => "JSON::PP not installed") if $@;

our $PEBBLE = _which($ENV{TEST_NGINX_PEBBLE_BINARY} // 'pebble');

my %features = (
	'ari' => '2.8.0', # custom ARI responses (pebble#501)
	'eab' => '2.5.2', # broken in 2.5.0
	'ml-dsa' => ['2.10.2', 'go1.27'], # requires "crypto/mldsa"
	'profile' => '2.7.0',
	'validity' => '2.4.0',
);

sub new {
	my $self = {};
	bless $self, shift @_;

	Test::More::plan(skip_all => 'pebble not found') unless $PEBBLE;

	my ($t, $port, $mgmt, $cert, $key, %extra) = @_;

	my $http_port = $extra{http_port} || 80;
	my $tls_port = $extra{tls_port} || 443;
	my $validity = $extra{validity} || 3600;

	$self->{alternate_roots} = $extra{alternate_roots};
	$self->{dns_port} = $extra{dns_port} || Test::Nginx::port(8980, udp=>1);
	$self->{noncereject} = $extra{noncereject};
	$self->{nosleep} = $extra{nosleep};

	$self->{port} = $port;
	$self->{mgmt} = $mgmt;

	$self->{state} = $extra{state} // $t->testdir();
	$self->{_roots} = {};
	$self->{_testdir} = $t->testdir();

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

sub set_renewal_info {
	my ($self, $cert, $start, $end, %extra) = @_;

	my $response = JSON::PP->new->encode({
		suggestedWindow => {
			start => _time_to_rfc3339($start),
			end => _time_to_rfc3339($end),
		},
		explanationURL => $extra{url} // 'http://acme.test/ari',
	});

	my $json = JSON::PP->new->encode({
		Certificate => $cert,
		ARIResponse => $response,
	});

	return _post($self->{mgmt}, '/set-renewal-info/', $json);
}

sub trusted_ca {
	my ($self, $chain) = @_;

	$chain //= 0;

	return $self->{_roots}->{$chain} if $self->{_roots}->{$chain};

	log2c('ACME: get certificate from ' . $self->{mgmt});

	my $cert = _get_body($self->{mgmt}, '/roots/' . $chain)
		or die "Can't get trusted CA certificate $chain from pebble";

	my $name = File::Spec->catfile($self->{_testdir},
		sprintf('pebble-%s-%s.ca.crt', $self->{port}, $chain));

	open my $fh, '>', $name or die "Can't create $name: $!";
	binmode $fh;
	print $fh $cert;
	close $fh;

	return $self->{_roots}->{$chain} = $name;
}

sub peer_certificate {
	my ($self, $host, %extra) = @_;

	my $chain = delete($extra{chain}) // 0;
	my $format = delete($extra{format}) // 'pem';
	my $is_ip = $host =~ /^[[:xdigit:]:.]+$/; # accurate enough

	my $s = Test::Nginx::http('/',
		start => 1,
		SSL => 1,
		SSL_ca_file => $self->trusted_ca($chain),
		SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
		SSL_verifycn_name => $host,
		$is_ip ? () : ( SSL_hostname => $host ),
		%extra
	);

	return unless $s;

	my $x509 = $s->peer_certificate();

	# Convert the result, as X509 will be destroyed with the socket.

	return $format->($x509) if ref($format) eq 'CODE';
	return IO::Socket::SSL::Utils::CERT_asHash($x509) if $format eq 'hash';
	return IO::Socket::SSL::Utils::PEM_cert2string($x509);
}

sub wait_certificate {
	my ($self, $cert, %extra) = @_;

	my $file = File::Spec->catfile($self->{'state'},
		'{www.,}' . $cert . '*.crt');

	my $timeout = ($extra{'timeout'} // 20) * 5;
	my @found;

	for (1 .. $timeout) {
		return @found if scalar(@found = glob $file);
		select undef, undef, undef, 0.2;
	}

	return;
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
	my $f = $features{$feature} // $feature;

	if (ref $f eq 'ARRAY') {
		return @{$f} == grep { $self->has_feature($_) } @{$f};
	}

	return _vercmp(_golang_version(), $1) >= 0 if $f =~ /^go(\d[\d.]*)$/;
	return _vercmp(_pebble_version(), $f) >= 0 if $f =~ /^\d[\d.]*$/;
}

###############################################################################

my $golang_ver;
my $pebble_ver;

sub log2c { Test::Nginx::log_core('||', @_); }

sub _golang_version {
	return $golang_ver if defined $golang_ver;

	my ($b, $fh);

	unless (open($fh, '<:raw', $PEBBLE)) {
		log2c("ACME: failed to get Go version from $PEBBLE: $!");
		return ($golang_ver = '0');
	}

	# Look for a version in the Go buildinfo section.
	# The proper way to check this is `go version $PEBBLE`, but we don't
	# want to rely on the presence of Go toolchain in the test environment.

	while ($fh && read($fh, $b, 4 * 1024, $b ? 48 : 0)) {
		if ($b =~ /\xff Go buildinf:.{18}.go(\d+\.[\d.]+)[^\d.]/s) {
			log2c("ACME: pebble built with Go $1");
			return ($golang_ver = $1);
		}

		$b = substr($b, -48);
	}

	log2c("ACME: failed to read Go version from $PEBBLE");
	return ($golang_ver = '0');
}

sub _pebble_version {
	return $pebble_ver if defined $pebble_ver;

	my $ver = '';

	if (open(my $fh, '-|', $PEBBLE, '-version')) {
		local $/;
		$ver = <$fh> // '';
		close($fh);
	}

	if ($ver =~ /version: v?([\d.]+)/) {
		log2c("ACME: pebble version $1 ($PEBBLE)");
		return ($pebble_ver = $1);
	}

	log2c("ACME: pebble version unknown ($PEBBLE)");
	return ($pebble_ver = '0');
}

sub _vercmp {
	my ($x, $y) = @_;

	my @x = split(/\./, $x // '');

	foreach (split(/\./, $y)) {
		my $v = shift @x;
		return -1 if !defined($v) || $v < $_;
		return  1 if $v > $_;
	}

	return scalar(@x) ? 1 : 0;
}

sub _which {
	my ($name) = @_;

	my @paths = scalar(File::Spec->splitdir($name)) > 1
		? (File::Spec->rel2abs($name))
		: map { File::Spec->rel2abs($name, $_) } File::Spec->path();

	foreach my $path (@paths) {
		return $path if -f $path && -x _;
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

sub _post {
	my ($port, $uri, $body) = @_;

	my $p = "POST $uri HTTP/1.0" . CRLF .
		"Connection: close" . CRLF .
		"Content-Length: " . length($body) . CRLF .
		"User-Agent: Test::Nginx::ACME/0" . CRLF .
		CRLF .
		$body;

	Test::Nginx::http($p, PeerAddr => '127.0.0.1:' . $port, SSL => 1);
}

sub _time_to_rfc3339 {
	strftime '%Y-%m-%dT%H:%M:%SZ', gmtime(shift);
}

###############################################################################

sub acme_test_daemon {
	my ($t, $acme) = @_;
	my $port = $acme->{port};
	my $dnsserver = '127.0.0.1:' . $acme->{dns_port};

	$ENV{PEBBLE_ALTERNATE_ROOTS} =
		$acme->{alternate_roots} if $acme->{alternate_roots};
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
