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
 

//TODO
// como o tamanho ad subopcão 122.6 'e diferente "BASIC.1" (9) e "HYBRID.2" (10) sugiro:
// na option 122 (31 bytes) 122.3 "mps.CABOTVA.NET" (18 bytes), alterar para 
// "mps0.CABOTVA.NET" (18 bytes)e shiftar à esquerda 1 byte a partir do "0", no "HYBRID.2"  ficando "mps.CABOTVA.NET" (17 bytes) 
// evitando ter de alterar a alocação de  memoria, que é sempre um assunto "melindroso". 
// Cariar e testar no DNS o A RECORD "mps0" no dominio "CABOTVA.NET#
// TLV:	122,32,3,18,"mps0.CABOTVA.NET",6,9,"BASIC.1" para:
//  	122,32,3,17,"mps.CABOTVA.NET",6,10,"HYBRID.2" ficando tudo o resto igual
//  	XXXXXXXXXXXXXXXXX esto so seria alerado casso recebermos na opcao 43.9 "THG540" (NOTA 2)
//  	infelizmente a 43.9 so é mandada nos pedidos docsis.* e não nos de pckt*
//  	sendo assim, so mesmo criando uma tabela de todos os OUIs dos THG540 ex: "00189b"
//  ROSA: arranjamos uma lista is OUIs de todos os thomson ???
//      garantimos que não existem hitrons v3 e v4 (ZONHUBS) com estes OUIs ?????


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


// OPTION 122
static uint8_t *opt122_init =   "\x7A\x20";


static uint8_t *opt122_basic =  "\x03\x13\x00\004mps0\007CABOTVA\003NET\x00"
                                "\x06\x09\005BASIC\001\x31\x00";


static uint8_t *opt122_hybrid = "\x03\x12\x00\003mps\007CABOTVA\003NET\x00"
                                "\x06\x0a\006HYBRID\001\x32\x00";
uint8_t  opt122_len = 0x20;


// forward declarations
static uint8_t *dhcp_get_option(dhcp_packet_t *packet, size_t packet_size,
                unsigned int option);               

static int8_t is_thg540(uint8_t *chaddr);

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
	uint8_t *mac;
        size_t  udp_len, iph_len, dhcp_len;

        union ipv4 {
                uint32_t ip;
                uint8_t  data[4];
        } yiaddr;       

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

		
        mac = dhcp->chaddr; 
	
	if (is_thg540(mac) == FALSE) 
  		return NF_ACCEPT;                

	// adicional check .......
	// check by HE (Faial and/or Terceira)
	
	printk(KERN_INFO "dhcp_cm_opt122: got a THG540: %pM \n", mac); 
	
	// early return for testing
  	return NF_ACCEPT;                

	// is the a thg520 !!!!
	//

                        
        //  with dhcp option 122, and have the expected len ?
        opt = dhcp_get_option(dhcp, dhcp_len, 122);
        if (opt && (opt[1] = opt122_len)) {
                               

		/// 

		//printk(KERN_INFO "dhcp_cm_opt122: got dhcp packt with opt 122.\n"); 

                if (! skb_make_writable(skb, skb->len)) {
                       	//printk(KERN_INFO "dhcp_cm_opt122: skb_make_writable Failed.\n"); 
                        return NF_ACCEPT;
                }

                // re-fetch the skb->data pointers after skb_make_writable
                iph = (struct iphdr *) skb_header_pointer (skb, 0, 0, NULL);                        
                iph_len = iph->ihl * 4;                                
                
                udph = (struct udphdr *) skb_header_pointer (skb, iph_len, 0, NULL);
                udp_len = skb->len - iph_len;
                                
                data = (uint8_t *) skb->data + iph_len + sizeof(struct udphdr);
                dhcp = (struct dhcp_packet *) data;
                dhcp_len = skb->len - iph_len - sizeof(struct udphdr);
                                              
                mac = dhcp->chaddr; 
                                
                opt = dhcp_get_option(dhcp, dhcp_len, 122);                                
                if ((opt == NULL) || (opt[1] != opt122_len)) {
                       	// WTF ? 
                        return NF_ACCEPT;
                }
				
		// DO MEM COPY !!!!!

                                                                 
                                           
                // calculete upd checksum
                                
                /*  Don't care...
                udph->check = 0;
                udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, 
                                                udp_len, IPPROTO_UDP, 
                                                csum_partial((unsigned char *)udph, udp_len, 0)); 
                */
                                        
              		          
        } // has opt 122 l                              
                        

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

static int8_t is_thg540(uint8_t *chaddr) {

	//THG540 OUI TABLE
	//  all OUIs of the Thomson THG540 that we have:
	//  0011e3, 00189b, 001e69 and 0024d1
        uint8_t *thg540[] =  { "\x00\x11\xe3",
                               "\x00\x18\x9b",
                               "\x00\x1e\x69",
                               "\x00\x24\xd1" };

        size_t thg540_len =  sizeof(thg540)/sizeof(thg540[0]);
        uint8_t *p;
	size_t i;
	
	// as all OUI have the '00' int the1st octet.
	// discart all non '00' starting MACs
	if (chaddr[0] == '\x00')
		return FALSE;

        for (i = 0; i < thg540_len; i++) {
                p =  thg540[i];
                if ( // chaddr[0] == p[0] &&
                    chaddr[1] == p[1] &&
                    chaddr[2] == p[2])
                        return TRUE;
        }
        return FALSE;
}



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
