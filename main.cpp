#include "snmp.h"
int main(int argc, char** argv)
{
	SendRaw a;
	string ipaddr;
	cin >> ipaddr;
	a.ifprint(a.IpfindIf(ipaddr));
	a.snmpScan(ipaddr);
	return 0;
}