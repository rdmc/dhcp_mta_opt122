#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>


static uint8_t *opt_gap = "pktc*"; 

static uint8_t *opt_init = "\x7A\x20";

static uint8_t *opt_basic =  "\x03\x13\x00\004mps0\007CABOTVA\003NET\x00"
			     "\x06\x09\005BASIC\001\x31\x00";

static uint8_t *opt_hybrid = "\x03\x12\x00\003mps\007CABOTVA\003NET\x00"
			     "\x06\x0a\006HYBRID\001\x32\x00";

static uint8_t *opt_end = "!!!!!!!!!";

static uint8_t buf[100];


int init_len = 0x02;
int opt_len  = 0x20;  
int gap_len  = 0x05;
int end_len  = 0x09;

// forward func declaration
void write_opt(uint8_t *start, int len); 
void mcopy(uint8_t *dst, const uint8_t *src, int len);

int main (int argc, char** argv) 
{

	memcpy(buf, opt_basic, opt_len );

	write_opt(opt_gap, gap_len);
	write_opt(opt_init, init_len);
	write_opt(buf, opt_len);
	write_opt(opt_end, end_len);

	//memcpy(buf, opt_hybrid, opt_len);
	mcopy(buf, opt_hybrid, opt_len);

	write_opt(opt_gap, gap_len);
	write_opt(opt_init, init_len);
	write_opt(buf, opt_len);
	write_opt(opt_end, end_len);


	return 0;
}

void write_opt(uint8_t *start, int len) 
{
	uint8_t *p;
	int i;

	p = start;
	for (i = 0; i < len; i++, p++) 
		putchar(*p);
}


void mcopy(uint8_t *dst, const uint8_t *src, int len)
{
	//uint8_t *p;
	int i;

	for (i = 0; i < len; i++)
		dst[i] = src[i];
}

