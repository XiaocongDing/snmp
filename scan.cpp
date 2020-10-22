#include"scan.h"
void Scan::Scan_Start()
{
	int i;
	getTime(ScanResults);
	if (!ip_range_flag||!tcp_scan_ports_flag)
		return;
	icmp_flag = false;
	if (icmp_flag)
	{
		for ( i = 0; i < ipranges.size(); i++)
		{
			icmp_Segment_Scan(ipranges[i].first, ipranges[i].second, ScanResults, aliveIP_icmp);
		}
	}
	arp_flag = false;
	if (arp_flag)
	{
		for ( i = 0; i < ipranges.size(); i++)
		{
			arp_Segment_Scan(ipranges[i].first, ipranges[i].second, ScanResults, aliveIP_arp);
		}
	}
	mergeAliveip();
	traceroute_flag = false;
	if (traceroute_flag)
	{
		if (icmp_flag)
		{
			traceroute(aliveIP_icmp, ScanResults);
		}
		else
		{
			for ( i = 0; i < ipranges.size(); i++)
			{
				traceroute(ipranges[i].first, ipranges[i].second, ScanResults);
			}
		}
	}
	route_os_flag = false;
	if (route_os_flag)
	{
		if (traceroute_flag == 0)
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
		if (tracertIP.size() == 0)
		{
			ScanResults.push_back("###\nfunction46=SNMPScan\n$$$\n");
			ScanResults.push_back("No routers found\n");
		}
		else
		{
			tracertIP.erase(unique(tracertIP.begin(), tracertIP.end()), tracertIP.end());
			raw.snmp_Segment_Scan(tracertIP, ScanResults);
		}
	}
	tcp_flag = false;
	if (tcp_flag)
	{
		if (aliveHostScaned)
		{
			raw.tcp_Segment_Scan(aliveIP, tcp_scan_ports, ScanResults);
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
			raw.tcp_Segment_Scan(ip_tcp_to_scan, tcp_scan_ports, ScanResults);
		}
	}
	udp_flag = false;
	if (udp_flag)
	{
		if (aliveHostScaned)
		{
			raw.udp_Segment_Scan(aliveIP, udp_scan_ports, ScanResults);
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
			raw.udp_Segment_Scan(ip_udp_to_scan, udp_scan_ports, ScanResults);
		}
	}
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
	
}

void Scan::os_info_scan(vector<unsigned long> aliveIp, vector<string>& ScanResults)
{
	in_addr mAddr;
	vector<uint16_t>wports = { 135,139,445,3389 };

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
			closesocket(mysocket);
		}
		if (ifwin)
		{
			ScanResults.push_back("Windows\t");
			if (if445)
				SmbScan2(aliveIp[i], false, ScanResults);
		}
		else
		{
			ScanResults.push_back("Unknown\n");
		}
		
	}
}