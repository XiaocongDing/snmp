#pragma once
#include "basic.h"


//#pragma pack(1)
typedef struct SNMPHDR {
	u_int hdr;
	u_char version;
	u_char us1;
	u_char us2;
	u_char us3;
	u_char * community;
	u_char us4;
	u_char us5;
	u_char us6;
	u_char us7;
	u_char us8;
	//u_int num1;
	u_char requestId[4];
	u_char err_stat[3];
	u_char err_index[3];
	u_char num[13];

}SNMP_HDR,*pSNMP_HDR;


class SendRaw {
private:
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_t* fp;
	char buff[200];
	struct bpf_program fcode;
	char* MacAddr;
	char* MacLocal;

	string lhIP;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[200];

public:
	SendRaw()
	{
		if (pcap_findalldevs(&alldevs, errbuf) == -1)
		{
			exit(1);
		}
	}
	pcap_if_t* IpfindIf(string ipv4);
	char* iptos(u_long in);
	void ifprint(pcap_if_t* d);
	int snmpScan(string ipaddr);
	int tcpScanpre(string ipaddr);
	int tcpScan(string ipaddr, uint16_t dport, uint8_t flags, uint16_t win);
	char* getMac(u_long ip);
	bool getlocalmac(char* src);
	bool getlocalmacbyip(ULONG IP,char *src);
	int snmpReceive(string ipaddr);
	int tcpReceive(string ipaddr);
	int setFilter(string ipaddr, char packet_filter[]);
	//void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
};


static void snmp_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	u_char buff[2000];
	u_char* p;
	IP_HDR* ih;
	UDP_HDR* uh;
	u_int ip_len;
	u_short sport, dport;
	in_addr mAddr_des,mAddr_src;

	ih = (IP_HDR*)(pkt_data + 14);

	ip_len = (ih->h_lenver & 0xf) * 4;
	uh = (UDP_HDR*)((u_char*)ih + ip_len);

	p = (u_char*)((u_char*)uh + 53);
	memcpy(buff, p, header->len - (67 + ip_len));

	sport = ntohs(uh->src_port);
	dport = ntohs(uh->des_port);

	mAddr_src.S_un.S_addr = ih->srcIP;
	mAddr_des.S_un.S_addr = ih->desIP;

	cout << inet_ntoa(mAddr_src) << "  " << sport << "     ";
	cout << inet_ntoa(mAddr_des) << "  " << dport << "     ";
	asciiFilter(buff, header->len - (67 + ip_len));
	cout << buff << endl;
}
static void tcp_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	u_char buff[2000];
	u_char* p;
	IP_HDR* ih;
	TCP_HDR* th;
	u_int ip_len;
	u_short sport, dport;
	in_addr mAddr_des, mAddr_src;

	ih = (IP_HDR*)(pkt_data + 14);

	ip_len = (ih->h_lenver & 0xf) * 4;
	th = (TCP_HDR*)((u_char*)ih + ip_len);

	p = (u_char*)((u_char*)th + 53);
	//memcpy(buff, p, header->len - (67 + ip_len));

	sport = ntohs(th->th_sport);
	dport = ntohs(th->th_dport);

	mAddr_src.S_un.S_addr = ih->srcIP;
	mAddr_des.S_un.S_addr = ih->desIP;

	cout << inet_ntoa(mAddr_src) << "  " << sport << "     ";
	cout << inet_ntoa(mAddr_des) << "  " << dport << "     ";
	//asciiFilter(buff, header->len - (67 + ip_len));
	cout << pkt_data << endl;
}

class ReceiveRaw {
private:
	pcap_if_t* alldevs;
	string lhIP;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[200];
public:
	ReceiveRaw()
	{
		if (pcap_findalldevs(&alldevs, errbuf) == -1)
		{
			exit(1);
		}
	}
};