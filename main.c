#include<pcap/pcap.h>
#include<stdio.h>

#include"trace.h"
#include"regroup.h"
#include"libndpi-1.8.0/libndpi/ndpi_main.h"
#include"libndpi-1.8.0/libndpi/ndpi_api.h"
#define IP_MF 0x2000     //0010 0000 0000 0000
#define IP_OFFSET 0x1fff    //offset part
#define SNAP 0xaa


int exa(struct ndpi_iphdr *iph)
{
	int len=ntohs(iph->tot_len)-28;
	Trace("len=%d\n",len);
	int i=0;
	char *data=(char *)iph;
	for(;i<len;i++)
	{
		printf("%c",data[i+28]);
		if(i%10+65!=data[i+28])
			return 0;
	}
	printf("\n");
	return 1;
}


void func(u_char *user,const struct pcap_pkthdr *hdr,const u_char *packet)
{
	//only deal with DLT_EN10MB
	const struct ndpi_ethhdr *ethernet;
	//llc header
	const struct ndpi_llc_header *llc;
	//ip header
	struct ndpi_iphdr *iph;

	u_int16_t eth_offset = 0;
	u_int16_t ip_offset = 0;
	u_int16_t type = 0;
	int pyld_eth_len = 0;
	int check = 0;
	int flag = 0;
	struct ndpi_iphdr **defrag;
	ethernet = (struct ndpi_ethhdr*)&packet[eth_offset];
	ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
	iph = (struct ndpi_iphdr*)&(packet[ip_offset]);
	flag = ntohs(iph->frag_off);

	if(((flag & IP_MF) == 0) && ((flag & IP_OFFSET) == 0))
	{
		return;
		//get_protocol(iph,ip_offset,hdr->len-ip_offset);
	}
	else
	{
		if(iph)
		{
			Trace("");
			if(ip_defrag_stub(iph,defrag)==1)
			{
				Trace("tot_len=%d\n",ntohs((*defrag)->tot_len));
				if((flag=exa(*defrag)))
				{
					Trace("yes\n");
				}
				else
				{
					Trace("NO\n");
				}
				return ;
			}
			else
			{
				Trace("not over\n");
				return ;
			}
		}
		else
		{
			return ;
		}
	}
	return;

}


int main()
{
	char errBuf[PCAP_ERRBUF_SIZE],*devStr;
	devStr="eth2";
	struct pcap_t* device;
	device=pcap_open_live(devStr,65535,1,0,errBuf);
	ip_frag_init();
	pcap_loop(device,-1,func,NULL);
}
