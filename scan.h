#pragma once
#include "icmp.h"
#include "snmp.h"
typedef bool flag;

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
	
	

	SendRaw raw;
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
	Scan(int ip_range_f, int ports_tf, int ports_uf, int icmp_f, int arp_f, int tcp_f, 
		int udp_f, int traceroute_f, int host_os_f, int route_os_f, int time_v, 
		string ip_range_r,string scanPorts)
	{
		ip_range_flag = ip_range_f;
		tcp_scan_ports_flag = ports_tf;
		udp_scan_ports_flag = ports_uf;
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
		loc_b = scanPorts.find("#", 0);
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
	vector<string> getResult()
	{
		return ScanResults;
	}
};
