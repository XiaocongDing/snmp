#include "scan.h"
//#include "osscan.h"
int main(int argc, char** argv)
{
	SendRaw a;
	string ipaddr;
	vector<string> results;
	ofstream file("Result", ios::app);
	
	Scan b(1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 100,
		"192.168.0.19/28", "23,24,27#12,27,18,23");
	//b.printIpPorts();
	b.Scan_Start();
	results=b.getResult();
	for (int i = 0; i < results.size(); i++)
	{
		file << results[i];
	}
	b.printAliveip();
	a.free_alldevs();

	//a.tcpReceive(ipaddr);
	//a.snmpReceive(ipaddr);
	

	return 0;
}