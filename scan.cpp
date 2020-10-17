#include"scan.h"
void Scan::Scan_Start()
{
	if (!ip_range_flag||!tcp_scan_ports_flag)
		return;
	if (icmp_flag)
		return;
}