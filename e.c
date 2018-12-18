#include <stdio.h>
#include <stdlib.h>

#include<arpa/inet.h>

//#include <ctype.h>
#include<string.h>
//#include<unistd.h>
//#include<signal.h>
//#include<sys/wait.h>
//#include<sys/types.h>
//#include<sys/socket.h>
//#include<netinet/in.h>
//#include<arpa/inet.h>
//#include<errno.h>
//#include<sys/file.h>
//#include<sys/msg.h>
//#include<sys/ipc.h>
//#include<time.h>


#define OK                0
#define ERROR             -1

#define FALSE             0
#define TRUE              1


/**** DHCP definitions ****/

#define MAX_DHCP_CHADDR_LENGTH           16
#define MAX_DHCP_SNAME_LENGTH            64
#define MAX_DHCP_FILE_LENGTH             128
#define MAX_DHCP_OPTIONS_LENGTH          312


struct dhcpmessage
{
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    char chaddr[16];
    char sname[64];
    char file[128];
    char magic[4];
    char opt[3];
} __attribute__((__packed__));


#define DHCP_CHADDR_LEN (16)
#define DHCP_SNAME_LEN  (64)
#define DHCP_FILE_LEN   (128)
#define DHCP_VEND_LEN   (308)
#define DHCP_OPTION_MAGIC_NUMBER (0x63825363)


typedef struct dhcp_packet {
         uint8_t     opcode;
         uint8_t     htype;      // 1 =ethernet
         uint8_t     hlen;       // 6 =48 MAC
         uint8_t     hops;
         uint32_t    xid;    /* 4 */
         uint16_t    secs;   /* 8 */
         uint16_t    flags;
         uint32_t    ciaddr; /* 12 */
         uint32_t    yiaddr; /* 16 */
         uint32_t    siaddr; /* 20 */
         uint32_t    giaddr; /* 24 */
         uint8_t     chaddr[DHCP_CHADDR_LEN]; /* 28 */  // <=== start of mac adddr
         uint8_t     sname[DHCP_SNAME_LEN]; /* 44 */
         uint8_t     file[DHCP_FILE_LEN]; /* 108 */
         uint32_t    option_format; /* 236 */  // Magic Cookie
         uint8_t     options[DHCP_VEND_LEN];
} dhcp_packet_t;
 
 typedef struct dhcp_option_t {
         uint8_t     code;
         uint8_t     length;
} dhcp_option_t;
 


#define ETHERNET_HARDWARE_ADDRESS            1     /* used in htype field of dhcp packet */
#define ETHERNET_HARDWARE_ADDRESS_LENGTH     6     /* length of Ethernet hardware addresses */

unsigned char client_hardware_address[MAX_DHCP_CHADDR_LENGTH]="";
unsigned int my_client_mac[MAX_DHCP_CHADDR_LENGTH];
int mymac = 0;


//OUI TABLE
typedef struct oui {
	uint8_t data[3];
} oui_t;

oui_t thg540_oui[] =  { {"\x00\x18\x9b"},
	   		{"\x00\x1e\x99"},
			{"\x00\x25\xab"} };

// NOTE: the above typedef struct is safer the the thg540 used in is_thg540 functiuon.
// read some 3rd party code to decide the safest and more eficient option.


// OPTION 122 
uint8_t *opt122_basic = "\172\024\003\017mps0.cabotva.net\006\007BASIC.1";
	//opt 122,len 28, sub-opt 3, len 15, "mps0.cabota.net", sup-opt 6, len 7, "BASIC.1"

uint8_t *opt122_hybrid = "\x7a\x1d\x03\x0emps.cabotva.net\x06\x08HYBRID.2";
	//opt 122,len 28, sub-opt 3, len 14=x0f, "mps.cabota.net", sup-opt=6, len=8, "HYBRID.2"

//memcpy(discover_packet.chaddr,client_hardware_address,ETHERNET_HARDWARE_ADDRESS_LENGTH);

int8_t is_thg540(uint8_t *chaddr);


int main(int argc, char** argv) {

	//printf("opt1: %d\nopt2: %d\n", strlen(opt122_basic), strlen(opt122_hybrid));
	//printf(opt122_basic);
	//printf(opt122_hybrid);
/*	
	for (int i =0; i<3; i++) {
	       printf("%2.2x%2.2x%2.2x\n", thg540_oui[i].data[0],
			       		   thg540_oui[i].data[1],
					   thg540_oui[i].data[2]);
	}
*/
	uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}; 

	if (is_thg540(mac) == TRUE) {
		printf("mac is a THG540\n");
	} else {
		printf("mac unknow\n");
	}

	return 0;
}



int8_t is_thg540(uint8_t *chaddr) {

	//THG540 OUI TABLE
	uint8_t *thg540[] =  { "\x00\x18\x9b",
		   	       "\x00\x1e\x99",
			       "\x00\x25\xab", 
			       "\x00\x00\x11",
			       "\x00\x11\x22" };

	size_t thg540_len =  sizeof(thg540)/sizeof(thg540[0]);
	
	uint8_t *p;

	for (int i = 0; i < thg540_len; i++) {
		p =  thg540[i];
		if (chaddr[0] == p[0] && 
		    chaddr[1] == p[1] && 
		    chaddr[2] == p[2])
			return TRUE;
	}
	return FALSE;
}




// int8_t is_is_




