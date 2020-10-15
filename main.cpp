#include "snmp.h"
//#include "osscan.h"
int main(int argc, char** argv)
{
	SendRaw a;
	string ipaddr;
	cin >> ipaddr;
	a.ifprint(a.IpfindIf(ipaddr));
	//a.snmpScan(ipaddr);
	//a.tcpScanPortList(ipaddr, ports);
	a.snmpGet(ipaddr,2000);
	a.free_alldevs();
	//a.tcpReceive(ipaddr);
	//a.snmpReceive(ipaddr);
	

	return 0;
}