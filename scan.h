#pragma once
#include "icmp.h"


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
		//////add on 1105
		int loc_a, loc_b, loc;
		string subtemp, ipaddr1, ipaddr2, ipaddr;
		unsigned long ip_s, ip_e, ip_a;
		int mask = 0;
		loc_a = 0;
		while ((loc_b = input_ip_ranges.find(";", loc_a)) != input_ip_ranges.npos)
		{
			subtemp = input_ip_ranges.substr(loc_a, loc_b - loc_a);
			if ((loc = subtemp.find("-", 0)) != subtemp.npos)
			{
				ipaddr1 = subtemp.substr(0, loc);
				ipaddr2 = subtemp.substr(loc + 1, subtemp.size() - loc - 1);
				ip_s = inet_addr(ipaddr1.c_str());
				ip_e = inet_addr(ipaddr2.c_str());
				ipranges.push_back(make_pair(ip_s, ip_e));
			}
			else if ((loc = subtemp.find("/", 0)) != subtemp.npos)
			{
				ipaddr = subtemp.substr(0, loc);
				mask = (int)stoi(subtemp.substr(loc + 1, subtemp.size() - loc - 1));
				ip_a = (unsigned long)pow(2, (32 - mask));
				ip_s = (swap_endian(inet_addr(ipaddr.c_str())) / ip_a) * ip_a;
				ip_e = ip_s + ip_a - 1;
				ipranges.push_back(make_pair(swap_endian(ip_s), swap_endian(ip_e)));
			}
			else
			{

				ip_s = inet_addr(subtemp.c_str());
				ipranges.push_back(make_pair(ip_s, ip_s));
			}
			loc_a = loc_b + 1;

		}
		loc_b = input_ip_ranges.size();
		subtemp = input_ip_ranges.substr(loc_a, loc_b - loc_a);
		if ((loc = subtemp.find("-", 0)) != subtemp.npos)
		{
			ipaddr1 = subtemp.substr(0, loc);
			ipaddr2 = subtemp.substr(loc + 1, subtemp.size() - loc - 1);
			ip_s = inet_addr(ipaddr1.c_str());
			ip_e = inet_addr(ipaddr2.c_str());
			ipranges.push_back(make_pair(ip_s, ip_e));
		}
		else if ((loc = subtemp.find("/", 0)) != subtemp.npos)
		{
			ipaddr = subtemp.substr(0, loc);
			mask = (int)stoi(subtemp.substr(loc + 1, subtemp.size() - loc - 1));
			ip_a = (unsigned long)pow(2, (32 - mask));
			ip_s = (swap_endian(inet_addr(ipaddr.c_str())) / ip_a) * ip_a;
			ip_e = ip_s + ip_a - 1;
			ipranges.push_back(make_pair(swap_endian(ip_s), swap_endian(ip_e)));
		}
		else
		{

			ip_s = inet_addr(subtemp.c_str());
			ipranges.push_back(make_pair(ip_s, ip_s));
		}
		///////////
		/////ports
		string port;
		loc_a = loc = 0;
		loc_b = scanPorts.find("/", 0);
		///////add on 1106
		if (loc_b == -1)
		{
			loc_b = scanPorts.size() + 20;
		}
		//////
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


		///////add on 1106
		if (loc_b != scanPorts.size() + 20)
		{
			loc_a = loc_b + 1;
			loc_b = scanPorts.size();
			loc = loc_a;
			while (loc < loc_b && scanPorts.find(",", loc_a) != scanPorts.npos)
			{
				loc = scanPorts.find(",", loc_a);
				if (loc >= loc_b)
					break;
				port = scanPorts.substr(loc_a, loc - loc_a);
				udp_scan_ports.push_back((uint16_t)stoi(port));
				loc_a = loc + 1;
			}
			port = scanPorts.substr(loc_a, loc_b - loc_a);
			udp_scan_ports.push_back((uint16_t)stoi(port));
		}
		///////
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

void Scan::Scan_Start()
{
	int i;
	//getTime(ScanResults);
	cout << "icmp start" << endl;
	if (icmp_flag)
	{
		for (i = 0; i < ipranges.size(); i++)
		{
			icmp_Segment_Scan(ipranges[i].first, ipranges[i].second, ScanResults, aliveIP_icmp);
		}
	}
	cout << "arp start" << endl;
	if (arp_flag)
	{
		cout << "arp scan start" << endl;
		for (i = 0; i < ipranges.size(); i++)
		{
			arp_Segment_Scan(ipranges[i].first, ipranges[i].second, ScanResults, aliveIP_arp);
		}
	}
	mergeAliveip();
	cout << "traceroute scan start" << endl;
	if (traceroute_flag)
	{
		if (icmp_flag)
		{
			traceroute(aliveIP_icmp, ScanResults);
		}
		else
		{
			for (i = 0; i < ipranges.size(); i++)
			{
				traceroute(ipranges[i].first, ipranges[i].second, ScanResults);
			}
		}
	}
	cout << "tcp scan start..." << endl;
	if (tcp_flag)
	{
		if (aliveHostScaned)
		{
			tcp_Segment_Scan(aliveIP, tcp_scan_ports, ScanResults);
		}
		else
		{
			vector<unsigned long> ip_tcp_to_scan;
			for (i = 0; i < ipranges.size(); i++)
			{
				for (int j = swap_endian(ipranges[i].first); j <= swap_endian(ipranges[i].second); j++)
				{
					ip_tcp_to_scan.push_back(swap_endian(j));
				}
			}
			tcp_Segment_Scan(ip_tcp_to_scan, tcp_scan_ports, ScanResults);
		}
	}
	cout << "udp scan start..." << endl;
	if (udp_flag)
	{
		if (aliveHostScaned)
		{
			udp_Segment_Scan(aliveIP, udp_scan_ports, ScanResults);
		}
		else
		{
			vector<unsigned long> ip_udp_to_scan;
			for (i = 0; i < ipranges.size(); i++)
			{
				for (int j = swap_endian(ipranges[i].first); j <= swap_endian(ipranges[i].second); j++)
				{
					ip_udp_to_scan.push_back(swap_endian(j));
				}
			}
			udp_Segment_Scan(ip_udp_to_scan, udp_scan_ports, ScanResults);
		}
	}
	cout << "route os scan start" << endl;
	if (route_os_flag)
	{
		if (traceroute_flag == 0)
		{
			cout << "hasn't traceroute start tr" << endl;
			if (icmp_flag)
			{
				traceroute(aliveIP_icmp, ScanResults);
			}
			else
			{
				for (i = 0; i < ipranges.size(); i++)
				{
					traceroute(ipranges[i].first, ipranges[i].second, ScanResults);
				}
			}
		}
		if (tracertIP.size() == 0)
		{
			ScanResults.push_back("###\nfunction48=SNMPScan\n$$$\n");
			ScanResults.push_back("No routers found\n");
		}
		else
		{
			tracertIP.erase(unique(tracertIP.begin(), tracertIP.end()), tracertIP.end());
			snmp_Segment_Scan(tracertIP, ScanResults);
		}
	}
	cout << "os scan start..." << endl;
	if (host_os_flag)
	{
		if (aliveHostScaned)
		{
			os_info_scan(aliveIP, ScanResults);
		}
		else
		{
			vector<unsigned long> ip_os_to_scan;
			for (i = 0; i < ipranges.size(); i++)
			{
				for (int j = swap_endian(ipranges[i].first); j <= swap_endian(ipranges[i].second); j++)
				{
					ip_os_to_scan.push_back(swap_endian(j));
				}
			}
			os_info_scan(ip_os_to_scan, ScanResults);
		}
	}
	//add on 1110
	ScanResults.push_back("$$AAABBB$$");
	////
}

void Scan::os_info_scan(vector<unsigned long> aliveIp, vector<string>& ScanResults)
{
	in_addr mAddr;
	vector<uint16_t>wports = { 135,139,445,3389 };
	vector<uint16_t>lports = { 22,111 };

	SOCKET mysocket = INVALID_SOCKET;
	sockaddr_in my_addr;
	timeval tv = { 1000 ,0 };
	int opt = 5;
	int status, ret;
	WSADATA wsa;
	if (status = WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		exit(EXIT_FAILURE);
	}

	ScanResults.push_back("###\nfunction49=OSScan\n$$$\nOperation system information scan...\n");
	for (int i = 0; i < aliveIp.size(); i++)
	{
		mAddr.S_un.S_addr = aliveIp[i];
		char buff[100];
		bool ifwin = false;
		bool if445 = false;
		int cnt = 0;
		snprintf(buff, 100, "OS Scanning IP: %s\t", inet_ntoa(mAddr));
		ScanResults.push_back(buff);

		while (cnt < wports.size())
		{
			if ((mysocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
			{
				perror("socket:");
				continue;
			}
			setsockopt(mysocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(timeval));
			setsockopt(mysocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
			if ((setsockopt(mysocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(timeval))) < -1)
				return;
			my_addr.sin_family = AF_INET;
			my_addr.sin_addr.s_addr = aliveIp[i];
			my_addr.sin_port = htons(wports[cnt]);
			ret = connect(mysocket, (sockaddr*)&my_addr, sizeof(sockaddr));
			if (ret != -1)
			{
				ifwin = true;
				if (cnt == 2)
					if445 = true;
			}
			cnt++;

		}
		if (ifwin)
		{
			ScanResults.push_back("Windows\t\n");
#ifndef KASPERKEY
			if (if445)
				SmbScan2(aliveIp[i], false, ScanResults);
			else
				ScanResults.push_back("\n");
#else
			ScanResults.push_back("\n");
#endif
		}
		else
		{
			my_addr.sin_port = htons(22);
			ret = connect(mysocket, (sockaddr*)&my_addr, sizeof(sockaddr));
			my_addr.sin_port = htons(111);
			int ret2 = connect(mysocket, (sockaddr*)&my_addr, sizeof(sockaddr));
			if (ret != -1 || ret2 != -1)
			{
				ScanResults.push_back("Linux\n");
			}
			else
			{
				ScanResults.push_back("Windows/Linux\n");
			}
		}
		closesocket(mysocket);
	}
}