#!/usr/bin/env perl

use Digest::MD5 qw( md5_hex );
use Digest::SHA qw( sha1_hex );
use MIME::Base64;
use Compress::Zlib;

my $file = $ARGV[0];
open(FILE,$file) or die("Unable to open $file\n");
my $contents = <FILE>;
close FILE;

chomp $contents;

if ( index($contents,"__halt_compiler") < 600 ) {
    warn("Possibly bad file format.\n");
}
die("Wrong file format. __halt_compiler not found\n") if ( $contents !~ /__halt_compiler/ );

if ( split(/eval\(base64_decode/, $contents) < 3 ) {
    warn("Possibly bad file format.\n");
    brute_md5($contents);
    brute_sha1($contents);
} else {
    my $firsteval = index($contents,"eval(base64_decode");
    my $firstsemi = index($contents,";",$firsteval);
    my $evalexpr = substr($contents,$firsteval, ($firstsemi - $firsteval));
    $evalexpr =~ s/eval\(base64_decode\(['"]//;
    $evalexpr =~ s/['"\);]+//;

    my $debug = 0;
    my $len = -1;
    my $substr = 0;
    my $type = decode_base64($evalexpr);

    ###
    # If we are dealing with one of the phpencoders that performs integrity checks
    # on the decoding part of the file
    if ( $type =~ /preg_replace\(['"]\@\\\(\.\*\\\(/ ) {
        warn "Found preg_replace in first eval\n";
        my $tmp = index($contents,"eval",$firstsemi);
        my $tmp2 = index($contents,";",$tmp);
        $evalexpr = substr($contents,$tmp,($tmp2 - $tmp));
        $evalexpr =~ s/eval\(base64_decode\(['"]//;
        my $offsets = decode_base64($evalexpr);
        if ( $offsets =~ /array\((\d+),(\d+),(32|40),(\d+)\)/ ) {
          $len = $4;
          $substr = $1 + $2 + $3;
          warn "Integrity check is on front of file\n" if ( $debug );
        }
    }
    ###
    # If we are dealing with one of the phpencoders that deals with integrity checks
    # on the payload in the file
    if ( $type =~ /if\(\!function_exists/ ) {
        warn "Found function_exists in first eval\n";
        if ( $type =~ /array\((\d+),(\d+),(32|40)\)/ ) {
          $substr = $1 + $2 + $3;
          warn "Integrity check is on end of file\n" if ( $debug );
        }
    }

    ###
    # If we didn't get a hash type (32 bit or 40 bits
    warn("Odd file format: substring is $substr.\n") if ( $substr < 32 );

    uncompress_content($contents,$substr,$len);
}

###
# Decode the base64 content into the compressed datastream
sub uncompress_content {
    my ( $contents, $substr, $len ) = @_;

    my $newcontent = decode_base64(substr($contents,$substr,$len));

    my $i = inflateInit( -WindowBits => -&MAX_WBITS);
    my $realdata;
    while ( $newcontent ) {
        # Loop over the compressed data and inflate it as long as it uncompresses
        # correctly, until we reach the end of the stream
        ($output, $status) = $i->inflate($newcontent);
        print $output if $status == Z_OK or $status == Z_STREAM_END ;
        last if $status != Z_OK ;
    }
    if ( $status != Z_STREAM_END ) {
        warn "Bailed out of decompressing early. Attempting bruteforce.\n";
        brute_md5( $contents );
        brute_sha1( $contents );
    }
}

sub brute_sha1 {
    my ( $contents ) = @_;
    chomp $contents;

    my $halt_idx = index($contents,"__halt_compiler");
    my $payload = substr($contents, $halt_idx);
    $payload =~ s/.*__halt_compiler\(\);//;
    my $offset = 0;
    while ( $offset < length($payload) ) {
        if ( substr( $payload, $offset, 40 ) =~ /[[:^xdigit:]]/ ) {
            $offset++;
            next;
        }
        $testchksum = substr( $payload, $offset, 40 );
        my ( $junk, $testpayload ) = split /$testchksum/, $payload;
        if ( $testchksum == sha1_hex($testpayload) ) {
            my $newcontent = decode_base64($testpayload);

            my $i = inflateInit( -WindowBits => -&MAX_WBITS);
            my $realdata;
            while ( $newcontent ) {
                # Loop over the compressed data and inflate it as long as it uncompresses
                # correctly, until we reach the end of the stream
                ($output, $status) = $i->inflate($newcontent);
                print $output . "\n" if $status == Z_OK or $status == Z_STREAM_END ;
                last if $status != Z_OK ;
            }
            last if $status == Z_STREAM_END;
        }
        $offset++;
    }
}

sub brute_md5 {
    my ( $contents ) = @_;
    chomp $contents;

    my $halt_idx = index($contents,"__halt_compiler");
    my $payload = substr($contents,$halt_idx);
    $payload =~ s/.*__halt_compiler\(\);//;
    my $offset = 0;
    while ( $offset < length($payload) ) {
        if ( substr( $payload, $offset, 32 ) =~ /[[:^xdigit:]]/ ) {
            $offset++;
            next;
        }
        $testchksum = substr( $payload, $offset, 32 );
        my ( $junk, $testpayload ) = split /$testchksum/, $payload;
        if ( $testchksum == md5_hex($testpayload) ) {
            my $newcontent = decode_base64($testpayload);

            my $i = inflateInit( -WindowBits => -&MAX_WBITS);
            my $realdata;
            while ( $newcontent ) {
                # Loop over the compressed data and inflate it as long as it uncompresses
                # correctly, until we reach the end of the stream
                ($output, $status) = $i->inflate($newcontent);
                print $output . "\n" if $status == Z_OK or $status == Z_STREAM_END ;
                last if $status != Z_OK ;
            }
            last if $status == Z_STREAM_END;
        }
        $offset++;
    }
}

