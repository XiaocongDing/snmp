#pragma once
#ifndef SNMP
#define SNMP
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

	vector<uint16_t> tcp_open_ps;
	vector<uint16_t> udp_open_ps;
	vector<string> fingerprints;

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
	
	int Scanpre(string ipaddr);
	int tcpScan(string ipaddr, uint16_t dport, uint16_t sport,uint8_t flags, uint16_t win,uint16_t ipflag);
	int tcpScanPortList(string ipaddr, vector<uint16_t>& ports);
	char* getMac(u_long ip);
	bool getlocalmac(char* src);
	bool getlocalmacbyip(ULONG IP,char *src);
	int snmpReceive(string ipaddr);
	int tcpReceive(string ipaddr, int timeout);
	int setFilter(string ipaddr, char packet_filter[]);
	void getTcpOpenPorts(vector<uint16_t> &tcp_open_p);
	int tcpScan2(string ipaddr, vector<uint16_t> &ports);
	void get_fp(pcap_t* p);
	void OS_fp_get(string ipaddr);
	void free_alldevs();
	int snmp_Segment_Scan(vector<unsigned long> ipaddr,vector<string>&ScanResults);
	int snmpGet(string ipaddr, int timeout,vector<string> &ScanResults);
	void tcpScan_socket(unsigned long ipaddr, vector<uint16_t>portlist, vector<string>& ScanResults);
	void tcp_Segment_Scan(vector<unsigned long> inputIP, vector<uint16_t>portlist, vector<string>& ScanResults); 
	//void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

	void udpScanPortList(string ipaddr, vector<uint16_t>& ports);
	void udp_Segment_Scan(vector<unsigned long> inputIP, vector<uint16_t>&portlist, vector<string>& ScanResults);
	void udpReceive(string ipaddr, int timeout);
	void udpScan(string ipaddr, uint16_t port);
	void udpScan_socket(unsigned long ipaddr, vector<uint16_t>portlist, vector<string>& ScanResults);
	void getUdpOpenPorts(vector<uint16_t>& udp_open_p);
};


static vector<uint16_t> tcp_open_ports;
static vector<uint16_t> udp_open_ports;

static vector<uint16_t> udp_to_scan_ports;
static string udp_temp_results;

static u_char packetdata[2000];

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

	int len;
	len = asciiFilter(buff, header->len - (67 + ip_len));
	memcpy(packetdata, buff, len);
	cout << packetdata << endl;
	packetdata[len] = '\0';
}

static void udp_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	IP_HDR* ih;
	UDP_HDR* uh;
	u_int ip_len;
	uint16_t dport;
	in_addr mAddr_des, mAddr_src;
	char buff[200];
	ih = (IP_HDR*)(pkt_data + 14);
	ip_len = (ih->h_lenver & 0xf) * 4;
	dport = (u_short)(pkt_data + 64);
	mAddr_src.S_un.S_addr = ih->srcIP;
	cout << inet_ntoa(mAddr_src) << "\t" << dport << endl;
	if (ih->proto == 0x01)
	{
		
		snprintf(buff, 200, "%d\tclosed\n", dport);
		udp_temp_results = udp_temp_results + buff;
		vector<uint16_t>::iterator it;
		for (it = udp_to_scan_ports.begin(); it != udp_to_scan_ports.end(); it++)
		{
			if (*it == dport)
				it = udp_to_scan_ports.erase(it);
		}
	}
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
	p = (u_char*)((u_char*)th + 24);
	//memcpy(buff, p, header->len - (67 + ip_len));

	sport = ntohs(th->th_sport);
	dport = ntohs(th->th_dport);

	tcp_open_ports.push_back((uint16_t)sport);

	mAddr_src.S_un.S_addr = ih->srcIP;
	mAddr_des.S_un.S_addr = ih->desIP;

	cout << inet_ntoa(mAddr_src) << "  " << sport << "     ";
	cout << inet_ntoa(mAddr_des) << "  " << dport << "     ";
	cout << endl;

	memcpy(packetdata, pkt_data, header->len);
	packetdata[header->len] = '\0';
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

static char sessionrequest[] =
"/x81/x00/x00/x44/x20/x43/x4b/x46/x44/x45/x4e/x45/x43/x46/x44/x45"
"/x46/x46/x43/x46/x47/x45/x46/x46/x43/x43/x41/x43/x41/x43/x41/x43"
"/x41/x43/x41/x43/x41/x00/x20/x45/x4b/x45/x44/x46/x45/x45/x49/x45"
"/x44/x43/x41/x43/x41/x43/x41/x43/x41/x43/x41/x43/x41/x43/x41/x43"
"/x41/x43/x41/x43/x41/x41/x41/x00";

static char negotiate[] =
"/x00/x00/x00/x2f/xff/x53/x4d/x42/x72/x00/x00/x00/x00/x00/x00/x00"
"/x00/x00/x00/x00/x00/x00/x00/x00/x00/x00/x00/x00/x00/x00/x5c/x02"
"/x00/x00/x00/x00/x00/x0c/x00/x02/x4e/x54/x20/x4c/x4d/x20/x30/x2e"
"/x31/x32/x00";

static char setupaccount[] =
"/x00/x00/x00/x48/xff/x53/x4d/x42/x73/x00/x00/x00/x00/x00/x00/x00"
"/x00/x00/x00/x00/x00/x00/x00/x00/x00/x00/x00/x00/x00/x00/x5c/x02"
"/x00/x00/x00/x00/x0d/xff/x00/x00/x00/xff/xff/x02/x00/x5c/x02/x00"
"/x00/x00/x00/x00/x00/x00/x00/x00/x00/x00/x00/x01/x00/x00/x00/x0b"
"/x00/x00/x00/x6e/x74/00/x70/x79/x73/x6d/x62/x00";

static int SmpScan1(unsigned int ipaddr)
{
	WSADATA wsaData;
	unsigned int sock, addr, i;
	unsigned short smbport = 139;
	unsigned char* infobuf;
	int rc;
	struct sockaddr_in smbtcp;
	unsigned int zeroc = 0;
	if (WSAStartup(MAKEWORD(2, 1), &wsaData) != 0)
	{
		printf("WSAStartup failed !\n");
		exit(-1);
	}
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (!sock)
	{
		printf("socket() error...\n");
		exit(-1);
	}
	addr = ipaddr;
	smbtcp.sin_addr.s_addr = addr;
	smbtcp.sin_family = AF_INET;
	smbtcp.sin_port = htons(smbport);

	infobuf = new unsigned char[256];
	memset(infobuf, 0, 256);

	rc = connect(sock, (struct sockaddr*)&smbtcp, sizeof(struct sockaddr_in));
	if (rc == 0)
	{
		printf("sending session request ....\n");
		send(sock, sessionrequest, sizeof(sessionrequest) - 1, 0);
		//Sleep(500);
		rc = recv(sock, (char*)infobuf, 256, 0);
		if (rc < 0)
		{
			printf("recv error=%d\n", WSAGetLastError());
			exit(-1);
		}
		memset(infobuf, 0, 256);
		printf("[*] Sending negotiation request....\n");
		send(sock, negotiate, sizeof(negotiate) - 1, 0);
		//Sleep(500);

		rc = recv(sock, (char*)infobuf, 256, 0);
		if (rc < 0)
		{
			printf("error = %d (rc=%u)\n\n", WSAGetLastError(), rc);
			return NULL;
		}
		memset(infobuf, 0, 256);
		printf("[*] Sending setup account request....\n");
		send(sock, setupaccount, sizeof(setupaccount) - 1, 0);
		//Sleep(500);
		rc = recv(sock, (char*)infobuf, 256, 0);
		if (rc < 0)
		{
			printf("error = %d (rc=%u)\n\n", WSAGetLastError(), rc);
			return NULL;
		}
		else if (rc == 0)
		{
			printf("[*] Successful....\n");
			printf("\nRemote OS:\n");
			printf("----------");
			printf("\nI got back a null buffer ! WINXP sometimes does it\n");
		}
		else
		{
			printf("[*] Successful....\n");
			printf("\nRemote OS:\n");
			printf("----------");
			i = rc;
			while ((--i > 0) && (zeroc < 4))
			{
				if (infobuf[i] == 0x00)
				{
					printf("%s\n", (char*)&(infobuf[i + 1]));
					zeroc++;
				}
			}
		}
	}
	else {
		printf("can not connect to smb port 139\n");
	}
	closesocket(sock);
	free(infobuf);
}


static byte d1[] = {
	0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F,
	0x52, 0x4B, 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02,
	0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6E, 0x64, 0x6F,
	0x77, 0x73, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x57, 0x6F, 0x72, 0x6B, 0x67, 0x72, 0x6F, 0x75, 0x70,
	0x73, 0x20, 0x33, 0x2E, 0x31, 0x61, 0x00, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30,
	0x32, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E, 0x31, 0x00, 0x02, 0x4E, 0x54,
	0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00
};

static byte d2[] = {
	0x00, 0x00, 0x01, 0x0A, 0xFF, 0x53, 0x4D, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
	0x00, 0x00, 0x40, 0x00, 0x0C, 0xFF, 0x00, 0x0A, 0x01, 0x04, 0x41, 0x32, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x00, 0x00, 0xA0, 0xCF, 0x00, 0x60,
	0x48, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x3E, 0x30, 0x3C, 0xA0, 0x0E, 0x30,
	0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA2, 0x2A, 0x04,
	0x28, 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x82, 0x08,
	0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x05, 0x02, 0xCE, 0x0E, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00,
	0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00,
	0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00, 0x33, 0x00,
	0x20, 0x00, 0x33, 0x00, 0x37, 0x00, 0x39, 0x00, 0x30, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
	0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x20, 0x00, 0x50, 0x00, 0x61, 0x00,
	0x63, 0x00, 0x6B, 0x00, 0x20, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x00, 0x69, 0x00,
	0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
	0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00,
	0x33, 0x00, 0x20, 0x00, 0x35, 0x00, 0x2E, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00
};

static byte d3[] = {
0x81,0x00,0x00,0x44,0x20,0x43,0x4b,0x46,0x44,0x45,0x4e,0x45,0x43,0x46,0x44,0x45
,0x46,0x46,0x43,0x46,0x47,0x45,0x46,0x46,0x43,0x43,0x41,0x43,0x41,0x43,0x41,0x43
,0x41,0x43,0x41,0x43,0x41,0x00,0x20,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43
,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43
,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00
};

static void SplitString(char *s, int len, std::vector<std::string>& v)
{
	char* p = s;
	int i,j;
	i = j = 0;
	char buff[200];
	while (i < len)
	{
		if (*(p + i) == '\0')
		{
			if (*(p + i + 1) == '\0')
			{
				buff[j + 1] = '\0';
				v.push_back(buff);
				i++;
				j = 0;
			}
			
		}
		else
		{
			if (*(p + i) == 32 || (*(p + i) >= 48 && *(p + i) <= 122))
			{
				buff[j] = *(p + i);
				j++;
			}
		}
		i++;
	}
}


static int SmbScan2(unsigned long ipaddr,int flag139,vector<string> &ScanResults)
{
	WSADATA wsaData;
	unsigned int sock, addr, i;
	unsigned short smbport = 445;
	if (flag139 == 1)
		smbport = 139;
	unsigned char* infobuf;
	int rc;
	struct sockaddr_in smbtcp;
	unsigned int zeroc = 0;
	timeval tv = { 1000 ,0 };
	if (WSAStartup(MAKEWORD(2, 1), &wsaData) != 0)
	{
		printf("WSAStartup failed !\n");
		exit(-1);
	}
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (!sock)
	{
		printf("socket() error...\n");
		exit(-1);
	}
	if ((setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(timeval))) < -1)
		return -1;
	smbtcp.sin_addr.s_addr = ipaddr;
	smbtcp.sin_family = AF_INET;
	smbtcp.sin_port = htons(smbport);

	infobuf = new unsigned char[1024];
	memset(infobuf, 0, 1024);

	rc = connect(sock, (struct sockaddr*)&smbtcp, sizeof(struct sockaddr_in));

	if (rc == 0)
	{
		if (flag139 == 1)
		{
			send(sock, (char*)d3, sizeof(d3) - 1, 0);
			rc = recv(sock, (char*)infobuf, 1024, 0);
		}
		send(sock, (char*)d1, sizeof(d1), 0);
		rc = recv(sock, (char*)infobuf, 1024, 0);
		send(sock, (char*)d2, sizeof(d2), 0);
		rc = recv(sock, (char*)infobuf, 1024, 0);
		
		if (rc > 0)
		{
			vector<string> results;
			uint32_t len;
			len = (int)infobuf[3] + (int)infobuf[2] * 256;
			char buff[1024];
			memcpy(buff, infobuf + len - 128, 128);
			SplitString(buff, 128, results);
			cout << results.back() << endl;
			snprintf(buff, 1024, "%s\n", results.back().c_str());
			ScanResults.push_back(buff);
			ScanResults.push_back("\n");
		}
		else {
			cout << "Version Unkown\n";
			ScanResults.push_back("Version Unknown\n");
		}
	}
	closesocket(sock);
	free(infobuf);
	return 0;
}
#endif