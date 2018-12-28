/* dhcp_mta_opt122.c - DHCP Opt 122 subopt 6 Packet Mangling for EMTAs */

/*
 * written rdmc Oct 2018
 * (C) 2018 - NOS AÇORES
 * Serviços IP e HeadEnds, aka "CROMOS"
 *
 * This program is free software; you can redistribut it and/or modify
 * it under the terms of the GNU General Public Licence version 2 as
 * published by the Free Software Fundadtion. 
 * 
 * "dhcp_mta_opt122" is a netfilter hock kernel module that
 * for any packet, check if it is a DHCP (udp 67), and if the yiaddr
 * is in ours MTAs netework (10.98.0.0/16). Then check if it have
 * the option 122 sub option 3 and 6, and change to TPS Kerneros Realm form "BASIC.1" to "HYBRID.2"
 * default action is to let all packets thruogh.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#undef __KERNEL__
#include <linux/netfilter_ipv4.h>
#define __KERNEL__

#include <net/ip.h>
#include <net/checksum.h>

MODULE_AUTHOR("rdmc, ricardo.cabrl@nos-acores.pt");
MODULE_DESCRIPTION("DHCP Opt 122 Subopt 6 Packet Mangling for eMTAs");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0");

#define KERN_CONT   ""

/*
 * defines
 */ 

// Conditional compilation
// 

//#define FAIAL		// TGH540 eMTAs from Faial, HRT1CMTS002 VoIP network 10.98.208.0/20
#undef FAIAL
//#define TERCEIRA	// TGH540 eMTAs from Terceira, AGR1CMTS003 VoIP network2 10.98.128.0/20, 10.98.160.0/20 and 10.98.176.0/20
#undef TERCEIRA
#define MAC_TABLE	// TGH540 eMTAs from Migration list (in static mac_t *mac_List[]).
//
#undef ALL


// boolean
#define FALSE             0
#define TRUE              1

// DHCP defs

#define IP_HDR_LEN      20
#define UDP_HDR_LEN     8
#define TOT_HDR_LEN     28
  
#define DHCP_CHADDR_LEN (16)
#define DHCP_SNAME_LEN  (64)
#define DHCP_FILE_LEN   (128)
#define DHCP_VEND_LEN   (308)
#define DHCP_OPTION_MAGIC_NUMBER (0x63825363)

#define DHCP_OPTION_FIELD   (0)
#define DHCP_FILE_FIELD     (1)
#define DHCP_SNAME_FIELD    (2)

#define ETHERNET_HARDWARE_ADDRESS            1     /* used in htype field of dhcp packet */
#define ETHERNET_HARDWARE_ADDRESS_LENGTH     6     /* length of Ethernet hardware addresses */
#define ETH_ALEN     			     6     /* ... same*/


// struct from freeradius.org - proto_dhcp/dhcp.c
typedef struct dhcp_packet {
        uint8_t     opcode;
        uint8_t     htype;
        uint8_t     hlen;
        uint8_t     hops;
        uint32_t    xid;    /* 4 */
        uint16_t    secs;   /* 8 */
        uint16_t    flags;
        uint32_t    ciaddr; /* 12 */
        uint32_t    yiaddr; /* 16 */
        uint32_t    siaddr; /* 20 */
        uint32_t    giaddr; /* 24 */
        uint8_t     chaddr[DHCP_CHADDR_LEN]; /* 28 */
        uint8_t     sname[DHCP_SNAME_LEN]; /* 44 */
        uint8_t     file[DHCP_FILE_LEN]; /* 108 */
        uint32_t    option_format; /* 236 */  // Magic Cookie
        uint8_t     options[DHCP_VEND_LEN];
} dhcp_packet_t;

typedef struct dhcp_option_t {
        uint8_t     code;
        uint8_t     length;
} dhcp_option_t;

/*
 *  MAC
 *  type and mac list
 */ 

typedef struct mac {
	uint8_t data[ETH_ALEN];
} mac_t;


#ifdef MAC_TABLE

/*
 *  mac_list
 *  list of all thg540 for migration.
 *  if it gets too big, incluide as an expernal file.
 *  ex: #include "thg540_migration.h"
 */

static mac_t mac_list[] = {
        {"\x00\x18\x9B\x4A\x1B\x32"},
        {"\x00\x18\x9B\x4A\x1B\x3E"},
        {"\x00\x18\x9B\x4A\x1B\x4A"},
        {"\x00\x18\x9B\x4A\x1B\x59"},	// my test modem!!!!
        {"\x00\x18\x9B\x5D\xFE\x21"},
        {"\x00\x18\x9B\x87\x16\x0A"},
        {"\x00\x18\x9B\x89\x81\x48"},
        {"\x00\x18\x9B\x89\xF5\xDF"},
        {"\x00\x18\x9B\x8A\x50\x8D"},
        {"\x00\x18\x9B\x8A\x6E\x1E"},
        {"\x00\x18\x9B\x8A\xAF\x7F"},
        {"\x00\x18\x9B\x8C\xED\x8D"},
        {"\x00\x18\x9B\x8D\x12\x17"},
        {"\x00\x18\x9B\x8E\x1E\x76"},
        {"\x00\x18\x9B\x8E\x60\x88"},
        {"\x00\x18\x9B\x91\x43\x03"},
        {"\x00\x18\x9B\x94\x4F\x2A"},
        {"\x00\x18\x9B\x94\xB3\x1D"},
        {"\x00\x18\x9B\x94\xBC\x47"},
        {"\x00\x18\x9B\x95\x1E\x93"},
        {"\x00\x18\x9B\x95\x32\x9A"},
        {"\x00\x1E\x69\x5B\xA5\x31"},
        {"\x00\x1E\x69\x5E\x6A\xE4"},
        {"\x00\x1E\x69\x5E\xEC\x53"},
        {"\x00\x1E\x69\x5F\x1D\xF1"},
        {"\x00\x1E\x69\x6A\xC2\x36"},
        {"\x00\x1E\x69\x6A\xD6\x04"},
        {"\x00\x1E\x69\x6A\xE1\xE9"},
        {"\x00\x1E\x69\x70\xCE\xAE"},
        {"\x00\x1E\x69\x95\x64\x8D"},
        {"\x00\x1E\x69\xDC\x05\x3A"},
        {"\x00\x1E\x69\xE1\x75\x94"},
        {"\x00\x1E\x69\xE1\xC0\xA9"},
        {"\x00\x1E\x69\xE2\xF9\x7E"},
        {"\x00\x1E\x69\xE2\xFB\x2E"},
        {"\x00\x1E\x69\xE3\xBC\xA5"},
        {"\x00\x1E\x69\xE3\xF3\xCE"},
        {"\x00\x1E\x69\xEF\xE9\xEE"},
        {"\x00\x1E\x69\xF0\x13\x46"},
        {"\x00\x1E\x69\xF0\x25\x01"},
        {"\x00\x1E\x69\xF0\x25\x3D"},
        {"\x00\x1E\x69\xF0\xE4\x47"},
        {"\x00\x1E\x69\xF1\xF4\xF9"},
        {"\x00\x24\xD1\x8E\xBE\xA4"},
        {"\x00\x24\xD1\x8F\x5D\xBF"},
        {"\x00\x24\xD1\x8F\x5D\xC5"},
        {"\x00\x24\xD1\x8F\x79\xFD"},
        {"\x00\x24\xD1\x91\x97\xDA"},
        {"\x00\x24\xD1\x91\x98\x9D"},
        {"\x00\x24\xD1\x92\x20\x1E"},
        {"\x00\x24\xD1\x92\x35\xCC"},
        {"\x00\x24\xD1\x92\xFE\x93"},
        {"\x00\x24\xD1\x96\xEC\x95"},
        {"\x00\x24\xD1\x97\x97\xE0"},
        {"\x00\x24\xD1\x97\x98\x7F"},
        {"\x00\x24\xD1\x98\xA7\x42"}
};

static size_t mac_list_len = sizeof(mac_list)/sizeof(mac_t);

#endif

/*
 * dhcp option 122
 * PACKET CABLE VoIP RFC 3495
 *
 * sub-option 3 - Provisioning Server's Address:
 * 			"mps0.cabotva.net." or  "mps.cabotva.net"
 * sub-option 6 - Kerkeros Realm Name:
 * 			"BASIC.1" or "HYBRID.2"
 */ 

#define	PACKETCABLE	(122)		// dhcp option 122. PACKET CABLE VoIP 


// tlv option and len
static uint8_t *opt122_init =   "\x7A\x20";

// original suboptions 3 and 6 
// not used, only for REFERENCE
//static uint8_t *opt122_basic =  "\x03\x13\x00\004mps0\007CABOTVA\003NET\x00"
//                                "\x06\x09\005BASIC\001\x31\x00";

// mangled suboptions 3 and 6 
static uint8_t *opt122_hybrid = "\x03\x12\x00\003mps\007CABOTVA\003NET\x00"
                                "\x06\x0a\006HYBRID\001\x32\x00";
// option 122 len 
uint8_t  opt122_len = 0x20;


/*
 * forward declarations
 */
static uint8_t *dhcp_get_option(dhcp_packet_t *packet, size_t packet_size,
                unsigned int option);               

static int is_thg540(mac_t *mac);
static int  maccmp(mac_t*  mac1, mac_t* mac2);
#ifdef MAC_TABLE
static int mac_inlist(mac_t* mac);
#endif


/*
 *  out_hookfn
 *  function to be called by hook
 */  
static unsigned int out_hookfn(unsigned int hooknum,            //"const struct nf_hook_ops *ops" for kernel > 2.6.2x
                        struct sk_buff *skb,                  //""struct sk_buf*"  for kernel > 2.6.2x
                        const struct net_device *in, 
                        const struct net_device *out, 
                        int (*okfn)(struct sk_buff *))

{
        struct iphdr    *iph;
        struct udphdr   *udph;
        struct dhcp_packet  *dhcp;      
        uint8_t *data;
        uint8_t *opt;    
	mac_t *mac;	// working mac

	//uint8_t *mac_ptr;
        size_t  udp_len, iph_len, dhcp_len;

        union ipv4 {
                uint32_t ip;
                uint8_t  data[4];
        } yiaddr;       // working yiaddr	

        if ((skb == NULL ) || (skb_linearize(skb) < 0)) 
                return NF_ACCEPT;
                                
        iph = (struct iphdr *) skb_header_pointer (skb, 0, 0, NULL);
        iph_len = iph->ihl * 4;

        if ((iph == NULL) || (iph->protocol != IPPROTO_UDP)) 
                return NF_ACCEPT;       

        iph_len = iph->ihl * 4;                    
        udph = (struct udphdr *) skb_header_pointer (skb, iph_len, 0, NULL);                        

        // dhcp/bootps ?
        //if ((udph == NULL) || (ntohs(udph->source) != 67)) 	
        if (!udph || (ntohs(udph->source) != 67)) 	
		return NF_ACCEPT;

        data = (uint8_t *) skb->data + iph_len + sizeof(struct udphdr);
        dhcp = (struct dhcp_packet *) data;
        dhcp_len = skb->len - iph_len - sizeof(struct udphdr);
                
        if (dhcp_len < 300)     // ignore dhcp packet too short
                return NF_ACCEPT;
        
        yiaddr.ip = dhcp->yiaddr;

        // for a mta ? (yiaddr in MTA/VoIP range "10.98.x.x")
        if ((yiaddr.data[0] != 10) || (yiaddr.data[1] != 98))
  		return NF_ACCEPT;                
		
      	mac = (mac_t*) dhcp->chaddr; 

	// mac is a thg520 eMTA ? 	
	if (!is_thg540(mac)) 
  		return NF_ACCEPT;                
	
	// DEBUG:
	//printk(KERN_INFO "dhcp_cm_opt122: got a THG540: %pM \n", mac->data); 
	

	// check by HE (Faial and/or Terceira)

	if  (true &&
#ifdef	FAIAL
// thg540 from Faial network 10.98.208.0/20 
		(yiaddr.data[2] & 0xf0 != 208) &&
#endif
#ifdef	TERCEIRA
// thg540 from Terceira networks 10.98.128.0/20, 10.98.160.0/20 AND 10.98.176.0/24 
		(yiaddr.data[2] & 0xf0 != 128) &&
		(yiaddr.data[2] & 0xf0 != 160) &&
		(yiaddr.data[2] & 0xf0 != 176) &&
#endif
#ifdef	MAC_TABLE
// THG540 MAC IN OUWER LIST
		!mac_inlist(mac) &&
#endif
		true )
			return NF_ACCEPT;
	
	// DEBUG:
	//printk(KERN_INFO "dhcp_cm_opt122: THG540: %pM will be mangled.\n", mac->data); 
  	//return NF_ACCEPT;                
         
               
        // get dhcp option 122, and check length
        opt = dhcp_get_option(dhcp, dhcp_len, 122);
        if (opt && (opt[1] == opt122_len)) {
                 
		// make socket buffer awritable              
                if (! skb_make_writable(skb, skb->len)) {
                       	//printk(KERN_INFO "dhcp_cm_opt122: skb_make_writable Failed.\n"); 
                        return NF_ACCEPT;
                }
	
		/*
                 *  re-fetch the skb->data pointers after skb_make_writable
                 */
                iph = (struct iphdr *) skb_header_pointer (skb, 0, 0, NULL);                        
                iph_len = iph->ihl * 4;                                
                
                udph = (struct udphdr *) skb_header_pointer (skb, iph_len, 0, NULL);
                udp_len = skb->len - iph_len;
                                
                data = (uint8_t *) skb->data + iph_len + sizeof(struct udphdr);
                dhcp = (struct dhcp_packet *) data;
                dhcp_len = skb->len - iph_len - sizeof(struct udphdr);
                                              
                //mac = dhcp->chaddr; not needed
                                
                opt = dhcp_get_option(dhcp, dhcp_len, 122);                                
                if (!opt || (opt[1] != opt122_len)) {
                       	// WTF ? 
                        return NF_ACCEPT;
                }
			
		// DO MEM COPY !!!!!
                memcpy(&opt[2], opt122_hybrid, opt122_len);                                                 
                                           
                // calculete upd checksum                                
                /*  Don't care...
                udph->check = 0;
                udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, 
                                                udp_len, IPPROTO_UDP, 
                                                csum_partial((unsigned char *)udph, udp_len, 0)); 
                */
                                        
              		          
        }                
                        

//accept:
       return NF_ACCEPT;
}


/*
 * the folowing function code is from:
 * freeradius.org - proto_dhcp/dhcp.c
 *
 *  (c) 2008 The FreeRADIUS server project
 */
static uint8_t *dhcp_get_option(dhcp_packet_t *packet, size_t packet_size,
                unsigned int option)                
{
        int overload = 0;
        int field = DHCP_OPTION_FIELD;
        size_t where, size;
        uint8_t *data = packet->options;

        where = 0;
        size = packet_size - offsetof(dhcp_packet_t, options);
        data = &packet->options[where];

        while (where < size) {
                if (data[0] == 0) { /* padding */
                        where++;
                        continue;
                }

                if (data[0] == 255) { /* end of options */
                        if ((field == DHCP_OPTION_FIELD) &&
                            (overload & DHCP_FILE_FIELD)) {
                                data = packet->file;
                                where = 0;
                                size = sizeof(packet->file);
                                field = DHCP_FILE_FIELD;
                                continue;

                        } else if ((field == DHCP_FILE_FIELD) &&
                                    (overload && DHCP_SNAME_FIELD)) {
                                data = packet->sname;
                                where = 0;
                                size = sizeof(packet->sname);
                                field = DHCP_SNAME_FIELD;
                                continue;
                        }

                        return NULL;
                }

                /*
                 *  We MUST have a real option here.
                 */
                if ((where + 2) > size) {
                        //fr_strerror_printf("Options overflow field at %u",
                        //           (unsigned int) (data - (uint8_t *) packet));
                        return NULL;
                }

                if ((where + 2 + data[1]) > size) {
                        //fr_strerror_printf("Option length overflows field at %u",
                        //           (unsigned int) (data - (uint8_t *) packet));
                        return NULL;
                }

                if (data[0] == option) return data;

                if (data[0] == 52) { /* overload sname and/or file */
                        overload = data[3];
                }

                where += data[1] + 2;
                data += data[1] + 2;
        }

        return NULL;
}


/*
 * is_thg540 - check if a mac address is a Thomson THG540 eMTA cable modem
 *             *chaaddr - pointer to a hardware address (ethernet MAC)
 *             return TRUE , FALSE
 */ 

static int is_thg540(mac_t  *mac) 
{
	uint8_t *chaddr;
	uint8_t *p;
	size_t i;

	//THG540 OUI TABLE
	//  all OUIs of the Thomson THG540 that we have:
        uint8_t *thg540[] =  { "\x00\x11\xe3",
                               "\x00\x18\x9b",
                               "\x00\x1e\x69",
                               "\x00\x24\xd1" };

        size_t thg540_len =  sizeof(thg540)/sizeof(thg540[0]);
	
	if (!mac) return FALSE;

	chaddr = mac->data;

	// as all OUI have the '00' int the1st octet.
	// discart all non '00' starting MACs
	if (chaddr[0] != '\x00')
		return FALSE;

        for (i = 0; i < thg540_len; i++) {
                p =  thg540[i];
                if (chaddr[1] == p[1] &&  chaddr[2] == p[2])
                        return TRUE;
        }
        return FALSE;
}



/*
 * int  maccmp(mac_t*  m1, mac_t* m2) 
 * Compares to mac hardware addreses
 */

static int  maccmp(mac_t*  mac1, mac_t* mac2)
{
	if (!mac1 || !mac2) 
		return  -1;

	return  memcmp(mac1->data, mac2->data, ETH_ALEN);
}


#ifdef MAC_TABLE

/*
 * int mac_inlist(mac *m)
 * binary search of a mac in the mac_list. 
 * returns TRUE(1) if found or FALSE(0) if not found.
 * mac_list must be in ascending sort order.
 *
 */

static int mac_inlist(mac_t* mac)
{
	mac_t *base = mac_list;
	mac_t *pivot;
	int num = mac_list_len;
	int result;

	while (num > 0) {
		pivot = base + (num >>1);
		result = maccmp(mac, pivot);

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

#endif

/*
 *  netfilter hock & kernel module stuff
 */


static struct nf_hook_ops nfho_out __read_mostly = {
        //.pf       = NFPROTO_IPV4,
        .pf         = AF_INET,
        .priority = 1,
        .hooknum  = NF_IP_LOCAL_OUT,
        .hook     = out_hookfn,
};


static void mangle_cleanup(void)
{
        nf_unregister_hook(&nfho_out);
}


static void __exit mangle_fini(void)
{
        printk(KERN_INFO "module dhcp_opt122, cleanup...\n");
        mangle_cleanup();
}


static int __init mangle_init(void)
{
        int ret = 0;
        printk(KERN_INFO "module dhcp_cm_opt123, init...\n");

        ret = nf_register_hook(&nfho_out);
        if (ret) {
            printk(KERN_ERR "dhcp_cm_opt122: failed to register");
            mangle_cleanup();
        }

        return ret;
}


module_init(mangle_init);
module_exit(mangle_fini);

//EOF
