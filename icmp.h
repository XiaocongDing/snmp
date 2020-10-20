#pragma once
#define ICMP_ECHO_REQUEST_TYPE 8
#define ICMP_ECHO_RREQUEST_CODE 0
#define ICMP_ECHO_REPLY_TYPE 0
#define ICMP_ECHO_REPLY_CODE 0
#define ICMP_MINIMUM_HEADER 8
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "basic.h"

typedef struct icmp_hdr {
	unsigned char icmp_type;
	unsigned char icmp_code;
	unsigned short icmp_checksum;
	unsigned icmp_id;
	unsigned short icmp_sequence;
	unsigned long icmp_timestamp;
}ICMP_HDR, * PICMP_HDR;

static void InitializeWinsock() {
	int status;
	WSADATA wsa;
	if (status = WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		exit(EXIT_FAILURE);
	}
}

static vector<unsigned long> tracertIP;

static void InitIcmpHeader(ICMP_HDR* icmp_hdr) {
	char buff[sizeof(ICMP_HDR) + 32];
	icmp_hdr->icmp_type = ICMP_ECHO_REQUEST_TYPE;
	icmp_hdr->icmp_code = ICMP_ECHO_REPLY_CODE;
	icmp_hdr->icmp_id = (USHORT)GetCurrentProcessId();
	icmp_hdr->icmp_checksum = 0;
	icmp_hdr->icmp_sequence = 0;
	icmp_hdr->icmp_timestamp = GetTickCount();
	memset(&buff[sizeof(ICMP_HDR)], 'E', 32);
}
static void traceroute(vector<unsigned long>& aliveIP, vector<string>& ScanResults);
static void traceroute(unsigned long starthost, unsigned long endhost, vector<string>& ScanResults);

static void icmp_Segment_Scan(unsigned long starthost, unsigned long endhost, vector<string> &ScanResults,vector<unsigned long>&aliveIp)
{
	SOCKET sock = INVALID_SOCKET;
	sockaddr_in dest,from;
	unsigned long start, end, i;
	ICMP_HDR* icmp_hdr, * recv_icmp;
	int status, tick;
	int nLen = sizeof(from);
	string temp;

	InitializeWinsock();
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET)
		return;
	dest.sin_family = AF_INET;
	timeval tv = { 1000,0 };
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(timeval));
	ScanResults.push_back("###\nfunction43=ICMPScan\n$$$\nIpAddress\tstate\tDelay\tOS\tTTL\n");

	start = swap_endian(starthost);
	end = swap_endian(endhost);

	for ( i = start; i <= end; i++)
	{
		char recvBuf[1024 * 5];
		char buff[sizeof(ICMP_HDR) + 32];
		icmp_hdr = (ICMP_HDR*)buff;
		dest.sin_addr.s_addr = swap_endian(i);
		InitIcmpHeader(icmp_hdr);
		icmp_hdr->icmp_sequence = i;
		icmp_hdr->icmp_checksum = checksum((unsigned short*)buff, sizeof(ICMP_HDR) + 32);

		status = sendto(sock, buff, sizeof(ICMP_HDR) + 32, 0, (SOCKADDR*)&dest, sizeof(dest));
		if (status == SOCKET_ERROR)
			return;
		status = recvfrom(sock, recvBuf, 1024 * 5, 0, (SOCKADDR*)&from, &nLen);
		recv_icmp = (ICMP_HDR*)(recvBuf + 20);
		IPHDR* recv_ip = (IPHDR*)(recvBuf);
		tick = GetTickCount();
		if (status == SOCKET_ERROR || status < sizeof(IP_HDR) + sizeof(ICMP_HDR) || recv_icmp->icmp_type != 0)
		{
			temp = temp + inet_ntoa(dest.sin_addr);
			temp = temp + "\tunknow\n";
			ScanResults.push_back(temp);
			temp = "";
			continue;
		}
		else 
		{
			temp = temp + inet_ntoa(from.sin_addr);
			temp = temp + "\talive\t";
			char numstr[32];
			_itoa(tick - recv_icmp->icmp_timestamp,numstr,10);
			temp = temp + numstr;
			temp = temp + "ms\t";
			aliveIp.push_back(from.sin_addr.s_addr);
			if (recv_ip->ttl == 32) {
				temp = temp + "windows 95\t";
			}
			else if (recv_ip->ttl == 64) {
				temp = temp + "widnows/linux/macos\t";
			}
			else if ((int)recv_ip->ttl == 128) {
				temp = temp + "Windows\t";
			}
			else if ((int)recv_ip->ttl == 255) {
				temp = temp + "UNIX\t";
			}
			else {
				temp = temp + "unknow\t";
			}
			_itoa((int)recv_ip->ttl, numstr, 10);
			//temp = temp + ((char*)recv_ip->ttl) + "\t\n";
			temp = temp + numstr + "\t\n";
			cout << temp;
			ScanResults.push_back(temp);
			temp = "";
		}
	}
}


static int ifSamenet(unsigned long ip)
{
	struct hostent* phost;
	WSADATA wsadata;
	char Name[255];
	vector<string> localIP;
	int count;
	if (0 != WSAStartup(MAKEWORD(2, 2), &wsadata))   //³õÊ¼»¯
	{
		return -1;
	}

	if (gethostname(Name, sizeof(Name)) == 0)
	{
		phost = gethostbyname(Name);
		if (phost != NULL)
		{
			for (count = 0; (in_addr*)phost->h_addr_list[count]; count++)
			{
				localIP.push_back(inet_ntoa(*(in_addr*)phost->h_addr_list[count]));
			}
		}
	}
	WSACleanup();
	
	vector<unsigned long>localIPhex;
	unsigned long tmp;
	for (int i = 0; i < localIP.size(); i++)
	{
		tmp = swap_endian(inet_addr(localIP[i].c_str()));
		tmp = tmp - (tmp % 256);
		localIPhex.push_back(tmp);
	}
	
	ip = swap_endian(ip);
	int flag = 0;
	for (int i = 0; i < localIPhex.size(); i++)
	{
		if (ip - localIPhex[i] >= 0 && ip - localIPhex[i] < 256)
		{
			flag = 1;
			break;
		}
	}
	return flag;
}

static bool WINAPI arpScan(unsigned long ipStart,vector<string>&ScanResults, vector<unsigned long>&aliveIP)
{
	in_addr mAddr;
	mAddr.S_un.S_addr = ipStart;
	if (!ifSamenet(ipStart))
	{
		return false;
	}
	ULONG MacArr[2];
	DWORD AddrLen = 6;
	char buff[50];
	string temp;
	if (SendARP(mAddr.S_un.S_addr, NULL, MacArr, &AddrLen) == NO_ERROR)
	{
		snprintf(buff,50, "%s\t\t", inet_ntoa(mAddr));
		temp = temp + buff;
		memset(buff, 0, 50);
		
		BYTE* bPhysAddr = (BYTE*)MacArr;
		for (int i = 0; i < (int)AddrLen; i++) {
			if (i == (AddrLen - 1))
			{
				snprintf(buff, 50, "%X\n", (int)bPhysAddr[i]);
				temp = temp + buff;
				memset(buff, 0, 50);
			}
			else
			{
				snprintf(buff, 50, "%X-", (int)bPhysAddr[i]);
				temp = temp + buff;
				memset(buff, 0, 50);
			}
		}
		cout << temp;
		ScanResults.push_back(temp);
		temp = "";
		aliveIP.push_back(mAddr.S_un.S_addr);
		return true;
	}
	else
	{
		snprintf(buff, 50, "%s\t\tnot alive\n", inet_ntoa(mAddr));
		ScanResults.push_back(buff);
		memset(buff, 0, 50);
	}
	return false;
}

static void arp_Segment_Scan(unsigned long starthost, unsigned long endhost, vector<string>& ScanResults, vector<unsigned long>&aliveIP)
{
	unsigned long start, end, i;
	start = swap_endian(starthost);
	end = swap_endian(endhost);
	ScanResults.push_back("###\nfunction44=ARPScan\n$$$\nIP Address \t\tMAC Address\n");
	for ( i = start; i <=end; i++)
	{
		arpScan(swap_endian(i), ScanResults, aliveIP);
	}
}

static string getLocalipbyremote(const char* remote)
{
	int status, tick, i;
	WSADATA wsa;
	SOCKET sock = INVALID_SOCKET;
	sockaddr_in from,dest;

	ICMP_HDR* icmp_hdr, * recv_icmp;
	unsigned short nSeq = 0;
	int nLen = sizeof(from);


	InitializeWinsock();

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (sock == INVALID_SOCKET) {
		if (WSAGetLastError() == 10013) {
			printf("Socket Failed: Permission denied.\n");
			exit(EXIT_FAILURE);
		}
	}
	dest.sin_family = AF_INET;

	timeval tv = { 1000, 0 };
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(timeval));

	char recvBuf[1024 * 5];
	char buff[sizeof(ICMP_HDR) + 32];
	icmp_hdr = (ICMP_HDR*)buff;

	dest.sin_addr.s_addr = inet_addr(remote);
	InitIcmpHeader(icmp_hdr);
	icmp_hdr->icmp_sequence = 1;
	icmp_hdr->icmp_checksum = checksum((unsigned short*)buff, sizeof(ICMP_HDR) + 32);

	status = sendto(sock, buff, sizeof(ICMP_HDR) + 32, 0, (SOCKADDR*)&dest, sizeof(dest));

	if (status == SOCKET_ERROR) {
		printf("sent() error:%d\n", WSAGetLastError());
		exit(EXIT_FAILURE);
	}

	status = recvfrom(sock, recvBuf, 1024 * 5, 0, (SOCKADDR*)&from, &nLen);
	recv_icmp = (ICMP_HDR*)(recvBuf + 20);
	IPHDR* recv_ip = (IPHDR*)(recvBuf);

	if (status == SOCKET_ERROR) {
		//cout << "failed to get localhost ip" << endl;
		return "localhost";
	}
	else
	{
		from.sin_addr.s_addr = recv_ip->desIP;
		return inet_ntoa(from.sin_addr);
	}
}

static void traceroute(unsigned long starthost, unsigned long endhost, vector<string>& ScanResults)
{
	vector<unsigned long>aliveIP;
	for (unsigned long i = swap_endian(starthost); i < swap_endian(endhost); i++)
	{
		aliveIP.push_back(swap_endian(aliveIP[i]));
	}
	traceroute(aliveIP, ScanResults);
}

static void traceroute(vector<unsigned long>& aliveIP, vector<string>& ScanResults)
{
	ScanResults.push_back("###\nfunction45=traceRoute\n$$$\n");
	char temp[100];
	in_addr mAddr;
	string IP;
	string cmd = "cmd /c tracert ";
	FILE* p;
	vector<string> stackIP,traRoute;
	cmatch m;
	
	for (int i = 0; i < aliveIP.size(); i++)
	{
		mAddr.S_un.S_addr = aliveIP[i];
		IP = inet_ntoa(mAddr);
		
		cmd = cmd + IP + " > log";
		
		CString strPara;
		strPara = cmd.c_str();
		STARTUPINFO si = { sizeof(si) };
		PROCESS_INFORMATION pi;

		bool fRet = CreateProcess(NULL, strPara.GetBuffer(), NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
		if (fRet)
		{
			WaitForSingleObject(pi.hThread, INFINITE);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
		}

		p = fopen("log", "rt");

		ScanResults.push_back("@#@\nTraceroute IP:" + IP + "\n");
		
		while (!feof(p))
		{
			fgets(temp, 100, p);
			regex_search(temp, m, ipv4_regex);
			if (m.size() == 4)
				stackIP.push_back(m[0]);
		}
		memset(temp, 0, 100);
		fclose(p);
		WinExec("cmd /c del log", SW_HIDE);
		if (stackIP.size() > 2)
		{
			for (int k = 1; k < stackIP.size()-1; k++)
			{
				tracertIP.push_back(inet_addr(stackIP[i].c_str()));
			}
		}
		
		while (stackIP.size())
		{
			cout << stackIP.back() << endl;
			traRoute.push_back(stackIP.back());
			stackIP.pop_back();
		}
		
		string tmp;
		string des;
		vector<pair<string, string>> result;
		tmp = getLocalipbyremote(traRoute.back().c_str());
		if (!tmp.compare("localhost"))
		{
			return;
		}
		des = traRoute.back();
		traRoute.pop_back();

		while (des.compare(traRoute.back()))
		{
			result.push_back(pair<string, string>(tmp, traRoute.back()));
			ScanResults.push_back(tmp + "\t" + traRoute.back() + "\n");
			tmp = traRoute.back();
			traRoute.pop_back();
		}
		ScanResults.push_back(tmp + "\t" + traRoute.back() + "\n");
		traRoute.clear();
		stackIP.clear();
		cmd = "cmd /c tracert ";
	}
	
}