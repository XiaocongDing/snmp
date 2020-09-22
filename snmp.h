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
	char* getMac(u_long ip);
	bool getlocalmac(char* src);
	bool getlocalmacbyip(ULONG IP,char *src);
	int snmpReceive(string ipaddr);
	//void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
};

static void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[16];
	u_char buff[1000];
	u_char* p;
	IP_HDR* ih;
	UDP_HDR* uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;
	in_addr mAddr_des,mAddr_src;

	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);


	//printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);


	ih = (IP_HDR*)(pkt_data +
		14);


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