#include"scan.h"
void Scan::Scan_Start()
{
	int i;
	getTime(ScanResults);
	if (!ip_range_flag||!tcp_scan_ports_flag)
		return;
	if (icmp_flag)
	{
		for ( i = 0; i < ipranges.size(); i++)
		{
			icmp_Segment_Scan(ipranges[i].first, ipranges[i].second, ScanResults, aliveIP_icmp);
		}
	}
	/*if (arp_flag)
	{
		for ( i = 0; i < ipranges.size(); i++)
		{
			arp_Segment_Scan(ipranges[i].first, ipranges[i].second, ScanResults, aliveIP_arp);
		}
	}*/
	mergeAliveip();
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
				for (int j = swap_endian(ipranges[i].first); j < swap_endian(ipranges[i].second); j++)
				{
					ip_tcp_to_scan.push_back(swap_endian(j));
				}
			}
			raw.tcp_Segment_Scan(ip_tcp_to_scan, tcp_scan_ports, ScanResults);
		}
	}
	
	
	
	
}