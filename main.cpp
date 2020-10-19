#include "scan.h"
//#include "osscan.h"
int main(int argc, char** argv)
{
	SendRaw a;
	string ipaddr;
	cin >> ipaddr;
	vector<string> results;
	ofstream file("Result", ios::app);
	
	//Scan b(1, 1, 1, 1, 1, 1,
	//	1, 1, 1, 1, 100,
	//	"192.168.0.19/28", "23,24,27#12,27,18,23");
	////b.printIpPorts();
	//b.Scan_Start();
	//results=b.getResult();
	//for (int i = 0; i < results.size(); i++)
	//{
	//	file << results[i];
	//}
	//b.printAliveip();
	

	a.snmpScan(ipaddr);
	a.snmpReceive(ipaddr);
	a.free_alldevs();
	

	return 0;
}