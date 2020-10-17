#include "scan.h"
//#include "osscan.h"
int main(int argc, char** argv)
{
	SendRaw a;
	string ipaddr;
	//cin >> ipaddr;
	//a.ifprint(a.IpfindIf(ipaddr));
	//a.snmpScan(ipaddr);
	//a.tcpScanPortList(ipaddr, ports);
	//a.snmpGet(ipaddr,2000);
	Scan b(1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 100,
		"192.168.1.1", "23,24,27#12,27,18,23");
	b.printIpPorts();
	a.free_alldevs();
	//a.tcpReceive(ipaddr);
	//a.snmpReceive(ipaddr);
	

	return 0;
}