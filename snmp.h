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
	void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
};

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