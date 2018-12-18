#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>


// static uint8_t *opt_hybrid = "\x7a\x20\x03\x12\x03mps\007CABOTVA\003NET\000";
static uint8_t *opt_gap = "pktc*"; 


static uint8_t *opt_basic = "\x7A\x20" 
			     "\x03\x13\x00\004mps0\007CABOTVA\003NET\x00"
			     "\x06\x09\005BASIC\001\x31\x00";


static uint8_t *opt_hybrid = "\x7A\x20" 
			     "\x03\x12\x00\003mps\007CABOTVA\003NET\x00"
			     "\x06\x0a\006HYBRID\001\x32\x00";


int opt_len = 0x20 + 2 ;  // data len  + len( x7a, 0x20)
int gap_len = 0x05;


int main (int argc, char** argv) {

	//fprintf(stderr, "opt_hybrid len=%d\n", opt_hybrid_len);
	
	uint8_t *p; 
	int i;

	p = opt_gap;
	for (i= 0; i < gap_len; i++) {
		putchar(*p);
		p++;
	}
	
	p = opt_hybrid;
	//p = opt_basic;
	for (i= 0; i < opt_len; i++) {
		putchar(*p);
		p++;
	}
	
	//printf(p);
	

	return 0;
}

