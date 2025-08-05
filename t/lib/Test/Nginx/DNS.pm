package Test::Nginx::DNS;

# Copyright (c) F5, Inc.
#
# This source code is licensed under the Apache License, Version 2.0 license
# found in the LICENSE file in the root directory of this source tree.

# DNS server module for nginx tests.

###############################################################################

use warnings;
use strict;

use base qw/ Exporter /;
our @EXPORT_OK = qw/ dns_test_daemon /;

use Test::More qw//;
use IO::Select;
use IO::Socket;
use Socket qw/ CRLF /;

use Test::Nginx qw//;

use constant NOERROR	=> 0;
use constant FORMERR	=> 1;
use constant SERVFAIL	=> 2;
use constant NXDOMAIN	=> 3;

use constant A		=> 1;
use constant CNAME	=> 5;
use constant PTR	=> 12;
use constant AAAA	=> 28;
use constant SRV	=> 33;

use constant IN		=> 1;


###############################################################################

sub reply_handler {
	my ($recv_data, $zone) = @_;

	my (@name, @rdata);

	# default values

	my ($hdr, $rcode, $ttl) = (0x8180, NOERROR, 1);

	# decode name

	my ($len, $offset) = (undef, 12);
	while (1) {
		$len = unpack("\@$offset C", $recv_data);
		last if $len == 0;
		$offset++;
		push @name, unpack("\@$offset A$len", $recv_data);
		$offset += $len;
	}

	$offset -= 1;
	my ($id, $type, $class) = unpack("n x$offset n2", $recv_data);

	my $name = join('.', @name);

	foreach my $h (@$zone) {
		next if (defined $h->{'name'}  && $name ne $h->{'name'});
		next if (defined $h->{'match'} && $name !~ $h->{'match'});

		if ($h->{ERROR}) {
			$rcode = SERVFAIL;

		} elsif ($type == A && $h->{A}) {
			push @rdata, rd_addr($ttl, $h->{A});

		} elsif ($type == AAAA && $h->{AAAA}) {
			push @rdata, rd_addr6($ttl, $h->{AAAA});

		} elsif ($type == CNAME && $h->{CNAME}) {
			push @rdata, rd_name(CNAME, $ttl, $h->{CNAME});

		} elsif ($type == PTR && $h->{PTR}) {
			push @rdata, rd_name(PTR, $ttl, $h->{PTR});

		} elsif ($type == SRV && $h->{SRV}) {
			push @rdata, rd_srv($ttl, (split ' ', $_));
		}

		last;
	}

	Test::Nginx::log_core('||', "DNS: $name $type $rcode");

	$len = @name;
	pack("n6 (C/a*)$len x n2", $id, $hdr | $rcode, 1, scalar @rdata,
		0, 0, @name, $type, $class) . join('', @rdata);
}

sub rd_addr {
	my ($ttl, $addr) = @_;

	my $code = 'split(/\./, $addr)';

	return pack 'n3N', 0xc00c, A, IN, $ttl if $addr eq '';

	pack 'n3N nC4', 0xc00c, A, IN, $ttl, eval "scalar $code", eval($code);
}

sub expand_ip6 {
	my ($addr) = @_;

	substr ($addr, index($addr, "::"), 2) =
		join "0", map { ":" } (0 .. 8 - (split /:/, $addr) + 1);
	map { hex "0" x (4 - length $_) . "$_" } split /:/, $addr;
}

sub rd_addr6 {
	my ($ttl, $addr) = @_;

	pack 'n3N nn8', 0xc00c, AAAA, IN, $ttl, 16, expand_ip6($addr);
}

sub rd_name {
	my ($type, $ttl, $name) = @_;
	my @rdname = split /\./, $name;
	my $rdlen = length(join '', @rdname) + @rdname + 1;

	pack 'n3N n (C/a*)* x', 0xc00c, $type, IN, $ttl, $rdlen, @rdname;
}

sub rd_srv {
	my ($ttl, $pri, $w, $port, $name) = @_;
	my @rdname = split /\./, $name;
	my $rdlen = length(join '', @rdname) + @rdname + 7;	# pri w port x

	pack 'n3N n n3 (C/a*)* x',
		0xc00c, SRV, IN, $ttl, $rdlen, $pri, $w, $port, @rdname;
}

sub dns_test_daemon {
	my ($t, $port, $h, %extra) = @_;

	my $handler = ref($h) eq 'CODE' ? $h : sub { reply_handler(@_, $h) };

	my ($data, $recv_data);
	my $socket = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Proto => 'udp',
	)
		or die "Can't create listening socket: $!\n";

	my $sel = IO::Select->new($socket);

	local $SIG{PIPE} = 'IGNORE';

	# signal we are ready

	open my $fh, '>', $t->testdir() . '/' . $port;
	close $fh;

	while (my @ready = $sel->can_read) {
		foreach my $fh (@ready) {
			if ($socket == $fh) {
				$fh->recv($recv_data, 65536);
				$data = $handler->($recv_data);
				$fh->send($data);
			}
		}
	}
}

###############################################################################

1;

###############################################################################
