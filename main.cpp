#include "snmp.h"
//#include "osscan.h"
int main(int argc, char** argv)
{
	SendRaw a;
	string ipaddr;
	cin >> ipaddr;
	a.ifprint(a.IpfindIf(ipaddr));
	//a.snmpScan(ipaddr);
	a.tcpScanpre(ipaddr);
	a.tcpScan(ipaddr,53,2,1024);
	a.tcpReceive(ipaddr);
	//a.snmpReceive(ipaddr);
	

	return 0;
}