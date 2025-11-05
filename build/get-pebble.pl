#!/usr/bin/perl

# Copyright (c) F5, Inc.
#
# This source code is licensed under the Apache License, Version 2.0 license
# found in the LICENSE file in the root directory of this source tree.

# Find, download or build letsencrypt/pebble of at least the specified version.

###############################################################################

use strict;
use warnings;
use utf8;

use Cwd qw/ realpath /;
use Digest::SHA;
use File::Copy qw/ copy /;
use File::Path qw/ rmtree /;
use File::Spec;
use File::Temp;
use IPC::Open3;
use POSIX qw/ uname waitpid /;

BEGIN { use FindBin; chdir($FindBin::Bin) }

###############################################################################

my $GO      = $ENV{GO} // 'go';
my $NAME    = 'pebble';
my $TARGET  = File::Spec->join( realpath('..'), 'bin', $NAME );
my $URL     = 'https://github.com/letsencrypt/pebble';
my $VERSION = '2.8.0';

my %PREBUILT = (
    linux => {
        amd64 =>
          '34595d915bbc2fc827affb3f58593034824df57e95353b031c8d5185724485ce',
        arm64 =>
          '0e70f2537353f61cbf06aa54740bf7f7bb5f963ba00e909f23af5f85bc13fd1a',
    },
    darwin => {
        amd64 =>
          '9b9625651f8ce47706235179503fec149f8f38bce2b2554efe8c0f2a021f877c',
        arm64 =>
          '39e07d63dc776521f2ffe0584e5f4f081c984ac02742c882b430891d89f0c866',
    },
);

my %ARCH = (
    aarch64 => 'arm64',
    x86_64  => 'amd64',
);

###############################################################################

my ( $bin, $version ) = do_check();
if ( defined $version ) {
    print STDERR "found pebble $version at $bin\n";
    print $bin;
    exit 0;
}

my $arch = ( uname() )[4];
$arch = $ARCH{$arch} if defined $ARCH{$arch};

my $tempdir = File::Temp->newdir( 'get-pebble-XXXXXXXXXX', TMPDIR => 1 )
  or die "Can't create temp directory: $!\n";

if ( my $hash = $PREBUILT{$^O}{$arch} ) {
    print STDERR "downloading pebble $VERSION for $^O $arch\n";
    print do_download( $^O, $arch, $hash );
}
else {
    print STDERR "building pebble $VERSION\n";
    print do_compile();
}

###############################################################################

sub do_check {
    my @names = which($NAME);
    unshift @names, $TARGET;

  BIN: foreach my $bin (@names) {
        my $version;
        $version = $1
          if qx{ $bin -version 2>/dev/null } =~ /version:\s+v?(\d[\d\.]+)/;
        next unless $version;

        my @v = split /\./, $version;
        foreach my $n ( split /\./, $VERSION ) {
            my $v = shift @v || 0;
            last     if $v > $n;
            next BIN if $v < $n;
        }

        return ( $bin, $version );
    }
}

sub do_compile {
    my @GO = which($GO) or die "Can't find Go toolchain: $!\n";

    my $repo = $ENV{PEBBLE_SOURCE_DIR}
      // File::Spec->join( $tempdir, 'pebble' );

    run( 'git', 'clone', '--depth=1', '-b', "v${VERSION}", $URL, $repo )
      unless -d File::Spec->join( $repo, '.git' );

    chdir($repo) or die "chdir failed: $!\n";

    run( 'git', 'fetch', '--depth=1', 'origin', 'tag', "v${VERSION}" );
    run( 'git', 'checkout', "v${VERSION}" );

    my $commit  = run( 'git', 'rev-parse', 'HEAD' );
    my $ldflags = "-X 'main.version=v${VERSION} ($commit)'";

    run( $GO[0], 'build', '-ldflags=' . $ldflags, './cmd/pebble' );

    chdir($FindBin::Bin);
    return copy_binary( File::Spec->join( $repo, 'pebble' ) );
}

sub do_download {
    my ( $os, $arch, $hash ) = @_;

    chdir($tempdir) or die "chdir failed: $!\n";

    my $archive = "pebble-$os-$arch.tar.gz";
    run( 'curl', '--fail', '--silent', '-L', '-o', $archive,
        "$URL/releases/download/v${VERSION}/${archive}" );
    die "Checksum verification failed\n" if sha256sum($archive) ne $hash;

    run( 'tar', 'xzf', $archive );

    chdir($FindBin::Bin);
    return copy_binary(
        File::Spec->join( $tempdir, "pebble-$os-$arch", $os, $arch, 'pebble' )
    );
}

sub copy_binary {
    my ($src) = @_;
    mkdir dirname($TARGET);
    copy $src, $TARGET or die "copy $src, $TARGET: $!\n";
    chmod 0755, $TARGET or die "chmod $TARGET: $!\n";
    return $TARGET;
}

sub dirname {
    my ($filename) = @_;
    my ( $vol, $dir ) = File::Spec->splitpath($filename);
    return File::Spec->catpath( $vol, $dir, '' );
}

sub run {
    my $pid = open3( undef, my $fh, '>&STDERR', @_ );
    waitpid( $pid, 0 );
    die "$_[0] failed: $! $?\n" unless $? == 0;

    $fh->read( my $out, 32768 );
    chomp($out);
    return $out;
}

sub sha256sum {
    my ($filename) = @_;
    my $sha = Digest::SHA->new('SHA-256');
    $sha->addfile( $filename, 'b' );
    return lc( $sha->hexdigest() );
}

sub which {
    my ($name) = @_;
    my @paths = File::Spec->path();
    return grep { -x } map { File::Spec->join( $_, $name ) } @paths;
}

###############################################################################
