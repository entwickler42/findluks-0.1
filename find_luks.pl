#!/usr/bin/perl -w

use Math::BigInt;

%SETUP = (
	BEGIN => 0x0,
	DEVICE => "/dev/sda",
	PATTERN => "LUKS\xBA\xBE"
);

open(DEVICE,$SETUP{'DEVICE'}) or die "Can't open Disk!\n";
seek(DEVICE,0,2) or die "Can't seek on disk!\n";
my $size = tell(DEVICE);
seek(DEVICE,$SETUP{'BEGIN'},0) or die "Can't seek on disk!\n";
binmode(DEVICE);

sub read_luks_phdr{
	my $phdrs;
	my $origin = tell(DEVICE);
	seek(DEVICE,$origin-5,0);
	if(read(DEVICE,$phdr,208,0) == 208){
		my (
			$magic, $version, $cipher_name, $cipher_mode, $hash_spec, $payload_offset, 
			$key_bytes,	$mk_digest, $mk_digest_salt, $mk_digest_iter, $uuid
		) =	unpack('a6 n Z32 Z32 Z32 N2 a20 a32 N a40',$phdr);
		my $bigint = Math::BigInt->new($origin-5);
		printf(	"LUKS Candidate found:\n\t".
				"- Version:\t%u\n\t".
				"- Cipher mame:\t%s\n\t".
				"- Cipher mode:\t%s\n\t".
				"- PHDR Offset:\t".$bigint->as_hex()."\n\t".
				"- Payload loc:\t0x%08X (%i)\a\n\n",
				$version,$cipher_name,$cipher_mode,$payload_offset,$payload_offset);
	}
	seek(DEVICE,$origin,0);
}

sub search_pattern{
	my ($pattern,@callback) = @_;
	my $ch;
	my $position=0;
	my $pos = tell(DEVICE);

	while(read(DEVICE,$ch,1,0)){
		if($pos++ % 1048576 == 0) {
			printf("Processing Disk: [%i MB / %i MB]\033[K\n\033[1A",$size/1024/1024,$pos/1024/1024);
		}
		if($ch eq substr($pattern,$position,1)){
			if($position++ == length($pattern)-1){			
				foreach $call (@callback){
					$call->($pattern);
				}
				$pos = tell(DEVICE);
			}
		}elsif($position > 0) {
			seek(DEVICE,-$position,1);
			$pos-=$position;
			$position = 0;
		}
	}
}

search_pattern($SETUP{'PATTERN'},\(&read_luks_phdr));
close(DEVICE);
