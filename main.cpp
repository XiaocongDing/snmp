#include "snmp.h"
//#include "osscan.h"
int main(int argc, char** argv)
{
	SendRaw a;
	string ipaddr;
	cin >> ipaddr;
	a.ifprint(a.IpfindIf(ipaddr));
	//a.snmpScan(ipaddr);
	vector<uint16_t> ports = { 21,22,37,57,80,135,137,138,139,143,
161,443,445,464,488,496,500,538,546,547,563,611,873,902,
912,992,993,994,995,1080,2869,3306,3389,5357,8080,10243 };
	a.tcpScanPortList(ipaddr, ports);
	
	//a.tcpReceive(ipaddr);
	//a.snmpReceive(ipaddr);
	

	return 0;
}