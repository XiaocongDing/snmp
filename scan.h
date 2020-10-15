#pragma once
#include "snmp.h"
#include "tcp.h"
typedef int flag;

class Scan {
private:
	flag ip_range_flag;
	flag tcp_scan_ports_flag;
	flag udp_scan_ports_flag;
	flag icmp_flag;
	flag arp_flag;
	flag tcp_flag;
	flag udp_flag;
	flag traceroute_flag;
	flag host_os_flag; // os_finger_print
	flag route_os_flag; // snmp 
	
	int time_interval;
	string input_ip_range;
	vector<uint16_t> tcp_scan_ports;
	vector<uint16_t> udp_scan_ports;
	
	SendRaw raw;
	vector<string> result;
public:
	Scan()
	{
		ip_range_flag = 0;
		tcp_scan_ports_flag = 0;
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
		string ip_range_r,vector<uint16_t> &scan_ports_tr, vector<uint16_t>& scan_ports_ur)
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
		input_ip_range = ip_range_r;
		tcp_scan_ports = scan_ports_tr;
		udp_scan_ports = scan_ports_ur;
	}

	void Scan_Start();
};