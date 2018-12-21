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
#define ETH_ALEN     			     6     /* length of Ethernet hardware addresses */

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

typedef struct mac {
         uint8_t     data[ETH_ALEN];
} mac_t;
/*
mac_t mac_list[] = { 
	{"\x00\x18\x9B\x4A\x1B\x31"},
        {"\x00\x18\x9B\x4A\x1B\x3D"},
   	{"\x00\x18\x9B\x4A\x1B\x49"},
   	{"\x00\x18\x9B\x5D\xFE\x20"},
   	{"\x00\x18\x9B\x87\x16\x09"},
   	{"\x00\x18\x9B\x89\x81\x47"},
   	{"\x00\x18\x9B\x89\xF5\xDE"},
   	{"\x00\x18\x9B\x8A\x50\x8C"},
   	{"\x00\x18\x9B\x8A\x6E\x1D"},
  	{"\x00\x18\x9B\x8A\xAF\x7E"} 	};	
*/
#include "thg540_migration.h"

size_t mac_list_len = sizeof(mac_list)/sizeof(mac_t);

//mac_t my_mac = {"\x00\x18\x9b\x4a\x1b\x59"};
mac_t my_mac = {"\x00\x18\x9b\x4a\x1b\x49"};

//#define TESTE	(123)		// test comment


char buf[1024];


// forward refs
//int8_t is_thg540(uint8_t *chaddr);
int  is_thg540(mac_t *m);
int  maccmp(mac_t*  m1, mac_t* m2);
int  mac_inlist_sequencial(mac_t* m);
char *mac_print(mac_t* m); 
int mac_inlist(mac_t* m);


int main(int argc, char** argv) {

//	printf("teste = %d\n", TESTE);


	printf("my_mac = %s\n", mac_print(&my_mac));

	if (is_thg540(&my_mac) == TRUE) {
		printf("mac is a THG540.\n");
	} else {
		printf("mac OUI unknow.\n");
	}

/*
	printf("mac_list size: %d\n", mac_list_len);
	int i;
	for (i = 0; i < mac_list_len; i++) {
		printf("mac_list[%03d]=%s, maccmp=%d\n", i, mac_print(&mac_list[i]), maccmp(&my_mac, &mac_list[i]));
	}
*/
	if (mac_inlist(&my_mac) == TRUE) {
		printf("mac is in the list.\n");
	} else {
		printf("mac unknow.\n");
	}

	// bye, bye
	return 0;
}


//
// char*  mac_print(mac_t* m) 
// NOTE: only one call at each time. return only the last lbuf...
//
char*  mac_print(mac_t* m) 
{
	static char lbuf[256];
	if (!m){
		sprintf(lbuf, "<NULL>");
		
	} else {
		sprintf(lbuf, "%p->[%02x:%02x:%02x:%02x:%02x:%02x]", m,  
				m->data[0], m->data[1], m->data[2], 
				m->data[3], m->data[4], m->data[5] );
	}
	return lbuf;

}



// int  mac_inlist(mac_t* m)
// 
int  mac_inlist_sequencial(mac_t* m)
{
	int i;
	for (i = 0; i < mac_list_len; i++)
		if (maccmp(m, &mac_list[i]) == 0)
			return TRUE;
	return FALSE;
}

/*
 * int mac_inlist(mac *m)
 * binary search of a mac in the mac_list. 
 * returns TRUE(1) if found or FALSE(0) if not found.
 * mac_list must be in ascending sort order.
 *
 */
int mac_inlist(mac_t* m)
{
	mac_t *base = mac_list;
	mac_t *pivot;
	int num = mac_list_len;
	int result;

	while (num > 0) {
		pivot = base + (num >>1);
		result = maccmp(m, pivot);

		// printf("pivot=%s,  maccmp=%d\n", mac_print(pivot), result);

		if (result == 0)
			return TRUE;

		if (result > 0) {
			base = pivot + 1; 
			num--;
		}
		num >>= 1;
	}

	return FALSE;
}

//
// int  maccmp(mac_t*  m1, mac_t* m2) 
//
int  maccmp(mac_t*  m1, mac_t* m2)
{
	if (!m1 || !m2) 
		return  -1;

	return  memcmp(m1->data, m2->data, ETH_ALEN);
}


//
// is_thg540 - check if a mac address is a Thomson THG540 eMTA cable modem
//             *chaaddr - pointer to a hardware address (ethernet MAC)
//             return TRUE , FALSE
//
int is_thg540(mac_t *m)
{
	uint8_t *chaddr;
	uint8_t *p;
	size_t  i;
	
	//THG540 OUI TABLE
	uint8_t *thg540[] =  { "\x00\x18\x9b",
		   	       "\x00\x1e\x99",
			       "\x00\x25\xab" }; 
	size_t thg540_len =  sizeof(thg540)/sizeof(thg540[0]);
	
	
	if (!m) return FALSE;	
	chaddr = m->data;

	// as all thg540 OUI have '00' in it's 1st octet.
	// discart all non '00' starting MACs	 
	if (chaddr[0] != '\x00')
		return FALSE; 

	for (i = 0; i < thg540_len; i++) {
		p =  thg540[i];
		if (	// chaddr[0] == p[0] && 
		    chaddr[1] == p[1] && 
		    chaddr[2] == p[2] )
			return TRUE;
	}
	return FALSE;
}


// EOF




