#include "scan.h"
//#include "osscan.h"
int main(int argc, char** argv)
{
	/*string ipaddr;
	cin >> ipaddr;
	SmpScan1(inet_addr(ipaddr.c_str()));*/
	vector<string> results;
	ofstream file("Result", ios::app);
	
	Scan b(1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 100,
		"192.168.0.19/28", "21,22,37,57,80,135,137,138,139,143,161,443,445,464,488,496,500,538, 546, 547, 563, 611, 873, 902,912, 992, 993, 994, 995, 1080, 2869, 3306, 3389, 5357, 8080, 10243 #31,41,53,67,68,135,137,138,139,146,161,162,445,500,666,4000,1900,4500,5050,5353,5355,8099");

	b.Scan_Start();
	results=b.getResult();
	for (int i = 0; i < results.size(); i++)
	{
		file << results[i];
	}
	return 0;
}