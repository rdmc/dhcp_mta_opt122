# dhcp_mta_opt122

DHCP Opt 122 subopt 3 and 6  Packet Mangling for Cable Modems eMTAs


 "dhcp_mta_opt122" is a netfilter hock kernel module that
 for any packet, check if it is a DHCP (udp 67), and if the yiaddr
 is in our MTAs netework (10.98.0.0/16). Then check if it have
 the option 122 sub option 3 and 6, and change to TPS Kerneros Realm form "BASIC.1" to "HYBRID.2"
 default action is to let all 

 The porpuse is to teste/help migrating MTAs from MGCP to IMS.
 

