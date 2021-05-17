#!/usr/bin/env perl

use Digest::MD5;
use Digest::SHA1;
use MIME::Base64;
use Compress::Zlib;

my $file = $ARGV[0];
open(FILE,$file) or die("Unable to open $file\n");
my $contents = <FILE>;
close FILE;

die("Bad file format\n") if ( $contents !~ /__halt_compiler/ );

my $firsteval = index($contents,"eval");
my $firstsemi = index($contents,";",$firsteval);
my $evalexpr = substr($contents,$firsteval, ($firstsemi - $firsteval));
$evalexpr =~ s/eval\(base64_decode\(['"]//;
$evalexpr =~ s/['"\);]+//;

my $len = -1;
my $substr = 0;
my $type = decode_base64($evalexpr);

###
# If we are dealing with one of the phpencoders that performs integrity checks
# on the decoding part of the file
if ( $type =~ /preg_replace\(['"]\@\\\(\.\*\\\(/ ) {
    my $tmp = index($contents,"eval",$firstsemi);
    my $tmp2 = index($contents,";",$tmp);
    $evalexpr = substr($contents,$tmp,($tmp2 - $tmp));
    $evalexpr =~ s/eval\(base64_decode\(['"]//;
    my $offsets = decode_base64($evalexpr);
    if ( $offsets =~ /array\((\d+),(\d+),(32|40),(\d+)\)/ ) {
      $len = $4;
      $substr = $1 + $2 + $3;
      warn "Integrity check is on front of file\n";
    }
}
###
# If we are dealing with one of the phpencoders that deals with integrity checks
# on the payload in the file
if ( $type =~ /if\(\!function_exists/ ) {
    if ( $type =~ /array\((\d+),(\d+),(32|40)\)/ ) {
      $substr = $1 + $2 + $3;
      warn "Integrity check is on end of file\n";
    }
}
###
# If we didn't get a hash type (32 bit or 40 bits
die("Bad file format") if ( $substr < 32 );

###
# Decode the base64 content into the compressed datastream
$newcontent = decode_base64(substr($contents,$substr,$len));
my $i = inflateInit( -WindowBits => -MAX_WBITS);
my $realdata;
while ( $newcontent ) {
    # Loop over the compressed data and inflate it as long as it uncompresses
    # correctly, until we reach the end of the stream
    ($output, $status) = $i->inflate($newcontent);
    print $output if $status == Z_OK or $status == Z_STREAM_END ;
    last if $status != Z_OK ;
}
# If we didn't reach the end of the stream, there was a problem
die("Bad gzip data") if $status != Z_STREAM_END;
print "\n";
