#pragma once
#include "icmp.h"
#include "TcpScan.h"
typedef bool flag;

static int SmbScan2(unsigned long ipaddr, int flag139, vector<string>& ScanResults);
static void SplitString(char* s, int len, std::vector<std::string>& v);

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

class Scan {
private:
	flag ip_range_flag; // ip range 1, single ip 0
	flag tcp_scan_ports_flag; // 
	flag udp_scan_ports_flag;
	flag icmp_flag;
	flag arp_flag;
	flag tcp_flag;
	flag udp_flag;
	flag traceroute_flag;
	flag host_os_flag; // os_finger_print
	flag route_os_flag; // snmp 
	
	bool aliveHostScaned;

	int time_interval;
	string input_ip_ranges;

	vector<pair<unsigned long, unsigned long>>ipranges;
	
	vector<uint16_t> tcp_scan_ports;
	vector<uint16_t> udp_scan_ports;

	vector<unsigned long> aliveIP_icmp;
	vector<unsigned long> aliveIP_arp;
	vector<unsigned long> aliveIP;
	
	

	vector<string> ScanResults;

	
public:
	Scan()
	{
		ip_range_flag = 0;
		tcp_scan_ports_flag = 0; //0 common ports 
		udp_scan_ports_flag = 0;
		icmp_flag = 0;
		arp_flag = 0;
		tcp_flag = 0;
		udp_flag = 0;
		traceroute_flag = 0;
		host_os_flag = 0;
		route_os_flag = 0;
		
	}
	Scan(bool icmp_f, bool arp_f, bool tcp_f, 
		bool udp_f, bool traceroute_f, bool host_os_f, bool route_os_f, int time_v, 
		string ip_range_r,string scanPorts)
	{
		icmp_flag = icmp_f;
		arp_flag = arp_f;
		tcp_flag = tcp_f;
		udp_flag = udp_f;
		traceroute_flag = traceroute_f;
		host_os_flag = host_os_f;
		route_os_flag = route_os_f;
		time_interval = time_v;
		input_ip_ranges = ip_range_r;

		int loc_a = 0;
		int loc_b;
		int loc;

		if (input_ip_ranges.find("-",0)==input_ip_ranges.npos)
		{
			int loc = 0;
			if (input_ip_ranges.find("/",0)!=input_ip_ranges.npos)
			{
				loc = input_ip_ranges.find("/", 0);
				string ipaddr;
				ipaddr = input_ip_ranges.substr(0, loc);
				int mask;
				unsigned long ip_a, ip_s, ip_e;

				mask = (int)stoi(input_ip_ranges.substr(loc + 1, input_ip_ranges.size()-loc-1));
				ip_a = (unsigned long)pow(2, (32 - mask));
				ip_s = (swap_endian(inet_addr(ipaddr.c_str())) / ip_a) * ip_a;
				ip_e = ip_s + ip_a - 1;
				ipranges.push_back(make_pair(swap_endian(ip_s), swap_endian(ip_e)));
			}
			else {
				unsigned long ip_s;
				ip_s = inet_addr(input_ip_ranges.c_str());
				ipranges.push_back(make_pair(ip_s, ip_s));
			}
		}
		else
		{
			char buff[200];
			memcpy(buff, input_ip_ranges.c_str(), input_ip_ranges.size());
			char* p = buff;
		
			string subtemp;
			string ipaddr1, ipaddr2;
			unsigned long ip_s, ip_e;
			while (input_ip_ranges.find(",",loc_a)!=input_ip_ranges.npos)
			{
				loc_b = input_ip_ranges.find(",", loc_a);
				subtemp = input_ip_ranges.substr(loc_a, loc_b - loc_a);
				loc = subtemp.find("-", 0);
				ipaddr1 = subtemp.substr(0, loc);
				ipaddr2 = subtemp.substr(loc + 1, subtemp.size() - loc - 1);
				ip_s = inet_addr(ipaddr1.c_str());
				ip_e = inet_addr(ipaddr2.c_str());
				ipranges.push_back(make_pair(ip_s, ip_e));
				loc_a = loc_b + 1;
			}
			loc_b = input_ip_ranges.size();
			subtemp = input_ip_ranges.substr(loc_a, loc_b - loc_a);
			loc = subtemp.find("-", 0);
			ipaddr1 = subtemp.substr(0, loc);
			ipaddr2 = subtemp.substr(loc + 1, subtemp.size() - loc - 1);
			ip_s = inet_addr(ipaddr1.c_str());
			ip_e = inet_addr(ipaddr2.c_str());
			ipranges.push_back(make_pair(ip_s, ip_e));
		}
		/////ports
		string port;
		loc_a = loc = 0;
		loc_b = scanPorts.find("/", 0);
		do
		{
			loc = scanPorts.find(",", loc_a);
			if (loc >= loc_b)
				break;
			port = scanPorts.substr(loc_a, loc - loc_a);
			tcp_scan_ports.push_back((uint16_t)stoi(port));
			loc_a = loc + 1;
			//cout << loc << endl;
		} while (loc < loc_b && scanPorts.find(",", loc_a) != scanPorts.npos);
		port = scanPorts.substr(loc_a, loc_b - loc_a);
		tcp_scan_ports.push_back((uint16_t)stoi(port));


		loc_a = loc_b + 1;
		loc_b = scanPorts.size();
		loc = loc_a;
		while (loc < loc_b && scanPorts.find(",", loc_a) != scanPorts.npos)
		{
			loc = scanPorts.find(",", loc_a);
			if (loc >= loc_b)
				break;
			port = scanPorts.substr(loc_a, loc-loc_a);
			udp_scan_ports.push_back((uint16_t)stoi(port));
			loc_a = loc + 1;
		}
		port = scanPorts.substr(loc_a, loc_b - loc_a);
		udp_scan_ports.push_back((uint16_t)stoi(port));
	}
	void mergeAliveip()
	{
		aliveHostScaned = true;
		if (icmp_flag && arp_flag)
		{
			if (aliveIP_icmp.size() == 0 && aliveIP_arp.size() == 0)
				return;
			merge(aliveIP_icmp.begin(), aliveIP_icmp.end(), aliveIP_arp.begin(), aliveIP_arp.end(), back_inserter(aliveIP));
			aliveIP.erase(unique(aliveIP.begin(), aliveIP.end()), aliveIP.end());
		}
		else if (icmp_flag)
		{
			if (aliveIP_icmp.size() == 0)
				return;
			aliveIP = aliveIP_icmp;
		}
		else if (arp_flag)
		{
			if (aliveIP_arp.size() == 0)
				return;
			aliveIP = aliveIP_arp;
		}
		else
		{
			aliveHostScaned = false;
			return;
		}
		
	}
	void printIpPorts()
	{
		int i;
		for ( i = 0; i < ipranges.size(); i++)
		{
			in_addr mAddr1,mAddr2;
			mAddr1.S_un.S_addr = ipranges[i].first;
			mAddr2.S_un.S_addr = ipranges[i].second;
			cout << inet_ntoa(mAddr1) << "      ";
			cout << inet_ntoa(mAddr2) << endl;
		}
		cout << "udp Scan port:" << endl;
		for ( i = 0; i < udp_scan_ports.size(); i++)
		{
			cout << udp_scan_ports[i] << endl;
		}
		cout << "tcp Scan port:" << endl;
		for ( i = 0; i < tcp_scan_ports.size(); i++)
		{
			cout << tcp_scan_ports[i] << endl;
		}
	}
	void printAliveip() {
		int i = 0;
		in_addr mAddr;
		cout << "ICMP alive ip:" << endl;
		for ( i = 0; i < aliveIP_icmp.size(); i++)
		{
			mAddr.S_un.S_addr = aliveIP_icmp[i];
			cout << inet_ntoa(mAddr) << endl;
		}
		cout << "ARP alive ip:" << endl;
		for ( i = 0; i < aliveIP_arp.size(); i++)
		{
			mAddr.S_un.S_addr = aliveIP_arp[i];
			cout << inet_ntoa(mAddr) << endl;
		}
		cout << "merged alive ip:" << endl;
		for ( i = 0; i < aliveIP.size(); i++)
		{
			mAddr.S_un.S_addr = aliveIP[i];
			cout << inet_ntoa(mAddr) << endl;
		}
	}
	void Scan_Start();
	void os_info_scan(vector <unsigned long> aliveIp, vector<string>& ScanResults);
	vector<string> getResult()
	{
		return ScanResults;
	}
};

static void SplitString(char* s, int len, std::vector<std::string>& v)
{
	char* p = s;
	int i, j;
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

static int SmbScan2(unsigned long ipaddr, int flag139, vector<string>& ScanResults)
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
	timeval tv = { 100 ,0 };
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
			ScanResults.push_back("\n");
		}
	}
	closesocket(sock);
	free(infobuf);
	return 0;
}
