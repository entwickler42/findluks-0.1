#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1048576*512

// ----- SNIP CRYPTSETUP -----
#define LUKS_CIPHERNAME_L 32
#define LUKS_CIPHERMODE_L 32
#define LUKS_HASHSPEC_L 32
#define LUKS_DIGESTSIZE 20 
#define LUKS_HMACSIZE 32
#define LUKS_SALTSIZE 32
#define LUKS_NUMKEYS 8
#define LUKS_MKD_ITER 10
#define LUKS_KEY_DISABLED_OLD 0
#define LUKS_KEY_ENABLED_OLD 0xCAFE
#define LUKS_KEY_DISABLED 0x0000DEAD
#define LUKS_KEY_ENABLED  0x00AC71F3
#define LUKS_STRIPES 4000
#define LUKS_MAGIC {'L','U','K','S', 0xba, 0xbe};
#define LUKS_MAGIC_L 6
#define UUID_STRING_L 40
#define LUKS_PHDR_SIZE (sizeof(struct luks_phdr))

struct luks_phdr {
	char		magic[LUKS_MAGIC_L];
	uint16_t	version;
	char		cipherName[LUKS_CIPHERNAME_L];
	char		cipherMode[LUKS_CIPHERMODE_L];
	char            hashSpec[LUKS_HASHSPEC_L];
	uint32_t	payloadOffset;
	uint32_t	keyBytes;
	char		mkDigest[LUKS_DIGESTSIZE];
	char		mkDigestSalt[LUKS_SALTSIZE];
	uint32_t	mkDigestIterations;
	char            uuid[UUID_STRING_L];

	struct {
		uint32_t active;

		/* parameters used for password processing */
		uint32_t passwordIterations;
		char     passwordSalt[LUKS_SALTSIZE];

		/* parameters used for AF store/load */		
		uint32_t keyMaterialOffset;
		uint32_t stripes;		
	} keyblock[LUKS_NUMKEYS];
};
// ----- SNAP CRYPTSETUP -----

static char ___DONT_TOUCH_ME__[BUFFER_SIZE];
static FILE *DEVICE;
static uint64_t DEVICE_SIZE;

void read_luks_phdr(){
	/* Read whatever and if its size is that of a LUKS PHDR, claim it is a phdr :)
	 * The devices position is restored afterwards */
	struct luks_phdr phdr;
	off_t origin = ftello(DEVICE);
	off_t offset = origin - LUKS_MAGIC_L;
	fseeko(DEVICE,offset,0);
	if(fread(&phdr,1,LUKS_PHDR_SIZE,DEVICE)==LUKS_PHDR_SIZE){
		printf("\033[1A\033[KLUKS FS Candidate found:\n");
		printf("\t- Version     : %u\n",ntohs(phdr.version));
		printf("\t- Cipher name : %s\n",phdr.cipherName);
		printf("\t- Cipher mode : %s\n",phdr.cipherMode);
		printf("\t- Hash Specc. : %s\n",phdr.hashSpec);
		printf("\t- Payload Off : 0x%08X ( %i byte )\n",ntohl(phdr.payloadOffset),phdr.payloadOffset);
		printf("\t- Offset      : 0x%016llX\n",offset);
		printf("\t- Offset byte : %llu ( %llu MegaByte )\n",offset,offset/1024/1024);
		printf("\t- Offset sec. : %llu\n",offset/512);
		printf("\n\n");
	}
	fseeko(DEVICE,origin,0);
}

void search_pattern(const char* pattern, void (*callback)() ){
	/* Read byte by byte and yell at the callback if some data matches the pattern 
	 * move back IIn CCase of SSuuCChh wiredness */
	char ch;
	off_t index=0,pos=ftello(DEVICE);
	while(fread(&ch,1,1,DEVICE)==1){
		if(pos++ % 1048576 == 0){
			printf("\033[1A\033[KProcessing Disk: [%llu MB / %llu MB]\n",DEVICE_SIZE/1024/1024,pos/1024/1024);
		}
		if(ch == pattern[index]){
			if(index++ == strlen(pattern)-1){
				callback();
			}
		}else if(index > 0){
			fseeko(DEVICE,-index,1);
			pos -= index;
			index = 0;
		}
	}
}

uint64_t get_device_size(FILE* dev){
	/* seeks end of dev, returns the offset and restores dev position */
	off_t origin = ftello(dev);
	uint64_t size;
	fseeko(DEVICE,0,2);
	size = ftello(DEVICE);
	fseeko(DEVICE,origin,0);
	return size;
}

int main(int argc, char* argv[]){
	/* Prepare DEVICE if there are some usefull command line parameters */
	uint64_t disk_offset=0;
	if(argc < 2){
		printf("USAGE %s [DEVICE] ([OFFSET])\n",argv[0]);
		return 0;
	}else if(argc == 3){
		disk_offset = atoll(argv[2]);
		printf("Setting offset to: %llu\n",disk_offset);
	}
	if((DEVICE=fopen(argv[1],"rb")) == NULL){
		printf("Can't open Device: %s\n",argv[1]);
		return 0;
	}
	setvbuf(DEVICE,___DONT_TOUCH_ME__,_IOFBF,BUFFER_SIZE);
	DEVICE_SIZE = get_device_size(DEVICE);
	if(disk_offset != 0) fseeko(DEVICE,disk_offset,0);
	search_pattern("LUKS\xba\xbe",read_luks_phdr);	
	fclose(DEVICE);
	return 0;
}
