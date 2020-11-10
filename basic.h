#pragma once
#ifndef BASIC_H
#define BASIC_H
#define WIN32
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <atlstr.h>
#include <cstdlib>
#include <cstring>

#include <iostream>
#include <iphlpapi.h>
#include <String>
#include <assert.h>
#include <signal.h>
#include <winsock2.h>
#include <Windows.h>
#include <vector>
#include <fstream>
#include <algorithm>
#include <stdlib.h>


#include <regex>

#include <time.h>
using namespace std;

#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")

typedef struct IPHDR
{
	u_char h_lenver;
	u_char tos;
	u_short total_len;
	u_short ident;
	u_short frag_and_flags;
	u_char ttl;
	u_char proto;
	u_short checksum;
	u_int srcIP;
	u_int desIP;
}IP_HDR,*pIP_HDR;

typedef struct TCPHDR
{
	uint16_t	th_sport;	/* source port */
	uint16_t	th_dport;	/* destination port */
	uint32_t	th_seq;		/* sequence number */
	uint32_t	th_ack;		/* acknowledgment number */
	uint8_t		th_hdlen;	/*tcp header length*/
	uint8_t		th_flags;	/* control flags */
	uint16_t	th_win;		/* window */
	uint16_t	th_sum;		/* checksum */
	uint16_t	th_urp;
	uint8_t		th_kind;
	uint8_t		th_len;
	uint16_t	th_mss;
}TCP_HDR,*pTCP_HDR;

typedef struct UDPHDR
{
	u_short src_port;
	u_short des_port;
	u_short length;
	u_short cksum;
}UDP_HDR,*pUDP_HDR;

static regex ipv4_regex("(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}");

static void getTime(vector<string>& ScanResults)
{
	time_t nowTime = time(NULL);
	struct tm* sysTime;
	sysTime = (struct tm*)malloc(sizeof(tm));
	localtime_s(sysTime, &nowTime);
	char buff[50];
	ScanResults.push_back("###\nStartTime\n$$$\n");
	snprintf(buff, 50, "Year:%d Month:%d Day:%d Hours:%d Min:%d \n", sysTime->tm_year + 1900, sysTime->tm_mon+1, sysTime->tm_mday, sysTime->tm_hour, sysTime->tm_min);
	ScanResults.push_back(buff);
}

static unsigned short checksum(unsigned short* addr, unsigned int count) {
	register unsigned long sum = 0;
	while (count > 1) {
		sum += *addr++;
		count -= 2;
	}
	//if any bytes left, pad the bytes and add
	if (count > 0) {
		sum += ((*addr) & htons(0xFF00));
	}
	//Fold sum to 16 bits: add carrier to result
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	//one's complement
	sum = ~sum;
	return ((unsigned short)sum);
}


static uint32_t swap_endian(uint32_t val)
{
	val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
	return (val << 16) | (val >> 16);
}

static char * byteReverse(char* s,int size)
{
	char* p = s;
	char* q = s;
	while (--size)
		++q;
	while (q > p)
	{
		char t = *p;
		*p++ = *q;
		*q-- = t;
	}
	return s;
}

static uint16_t ip_checksum(uint16_t initcksum, uint8_t* ptr, int len)
{
	unsigned int cksum;
	int idx;
	int odd;

	cksum = (unsigned int)initcksum;
	odd = len & 1;
	len -= odd;
	for ( idx = 0; idx < len; idx += 2)
	{
		cksum += ((unsigned long)ptr[idx] << 8) + ((unsigned long)ptr[idx + 1]);
	}
	if (odd)
	{
		cksum += ((unsigned long)ptr[idx] << 8);
	}
	while (cksum >> 16)
	{
		cksum = (cksum && 0xffff) + (cksum >> 16);
	}
	return cksum;
}

static int asciiFilter(u_char* buff,int size)
{
	u_char* temp = buff;
	
	int j = 0;
	for (int i = 0; i < size; i++)
	{
		if (buff[i]==32||(buff[i] >= 48 && buff[i] <= 122))
		{
			temp[j++] = buff[i];
		}
	}
	temp[j] = '\0';
	return j;
}

static bool find_char(char* str, char t)
{
	char* p = str;
	while (*p != '\0')
	{
		if (*p == t)
			return true;
		p++;
	}
	return false;
}

typedef bool flag;

static int SmbScan2(unsigned long ipaddr, int flag139, vector<string>& ScanResults);
static void SplitString(char* s, int len, std::vector<std::string>& v);

static byte d1[] = {
	0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F,
	0x52, 0x4B, 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02,
	0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6E, 0x64, 0x6F,
	0x77, 0x73, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x57, 0x6F, 0x72, 0x6B, 0x67, 0x72, 0x6F, 0x75, 0x70,
	0x73, 0x20, 0x33, 0x2E, 0x31, 0x61, 0x00, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30,
	0x32, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E, 0x31, 0x00, 0x02, 0x4E, 0x54,
	0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00
};

static byte d2[] = {
	0x00, 0x00, 0x01, 0x0A, 0xFF, 0x53, 0x4D, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
	0x00, 0x00, 0x40, 0x00, 0x0C, 0xFF, 0x00, 0x0A, 0x01, 0x04, 0x41, 0x32, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x00, 0x00, 0xA0, 0xCF, 0x00, 0x60,
	0x48, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x3E, 0x30, 0x3C, 0xA0, 0x0E, 0x30,
	0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA2, 0x2A, 0x04,
	0x28, 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x82, 0x08,
	0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x05, 0x02, 0xCE, 0x0E, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00,
	0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00,
	0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00, 0x33, 0x00,
	0x20, 0x00, 0x33, 0x00, 0x37, 0x00, 0x39, 0x00, 0x30, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
	0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x20, 0x00, 0x50, 0x00, 0x61, 0x00,
	0x63, 0x00, 0x6B, 0x00, 0x20, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x00, 0x69, 0x00,
	0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
	0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00,
	0x33, 0x00, 0x20, 0x00, 0x35, 0x00, 0x2E, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00
};

static byte d3[] = {
0x81,0x00,0x00,0x44,0x20,0x43,0x4b,0x46,0x44,0x45,0x4e,0x45,0x43,0x46,0x44,0x45
,0x46,0x46,0x43,0x46,0x47,0x45,0x46,0x46,0x43,0x43,0x41,0x43,0x41,0x43,0x41,0x43
,0x41,0x43,0x41,0x43,0x41,0x00,0x20,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43
,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43
,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00
};

static void SplitString(char* s, int len, std::vector<std::string>& v)
{
	char* p = s;
	int i, j;
	i = j = 0;
	char buff[200];
	while (i < len)
	{
		if (*(p + i) == '\0')
		{
			if (*(p + i + 1) == '\0')
			{
				buff[j + 1] = '\0';
				v.push_back(buff);
				i++;
				j = 0;
			}

		}
		else
		{
			if (*(p + i) == 32 || (*(p + i) >= 48 && *(p + i) <= 122))
			{
				buff[j] = *(p + i);
				j++;
			}
		}
		i++;
	}
}
#ifndef KASPERKEY

static int SmbScan2(unsigned long ipaddr, int flag139, vector<string>& ScanResults)
{
	WSADATA wsaData;
	unsigned int sock, addr, i;
	unsigned short smbport = 445;
	if (flag139 == 1)
		smbport = 139;
	unsigned char* infobuf;
	int rc;
	struct sockaddr_in smbtcp;
	unsigned int zeroc = 0;
	timeval tv = { 100 ,0 };
	if (WSAStartup(MAKEWORD(2, 1), &wsaData) != 0)
	{
		printf("WSAStartup failed !\n");
		exit(-1);
	}
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (!sock)
	{
		printf("socket() error...\n");
		exit(-1);
	}
	if ((setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(timeval))) < -1)
		return -1;
	smbtcp.sin_addr.s_addr = ipaddr;
	smbtcp.sin_family = AF_INET;
	smbtcp.sin_port = htons(smbport);

	infobuf = new unsigned char[1024];
	memset(infobuf, 0, 1024);

	rc = connect(sock, (struct sockaddr*)&smbtcp, sizeof(struct sockaddr_in));

	if (rc == 0)
	{
		if (flag139 == 1)
		{
			send(sock, (char*)d3, sizeof(d3) - 1, 0);
			rc = recv(sock, (char*)infobuf, 1024, 0);
		}
		send(sock, (char*)d1, sizeof(d1), 0);
		rc = recv(sock, (char*)infobuf, 1024, 0);
		send(sock, (char*)d2, sizeof(d2), 0);
		rc = recv(sock, (char*)infobuf, 1024, 0);

		if (rc > 0)
		{
			vector<string> results;
			uint32_t len;
			len = (int)infobuf[3] + (int)infobuf[2] * 256;
			char buff[1024];
			memcpy(buff, infobuf + len - 134, 134);
			SplitString(buff, 134, results);
			cout << results.back() << endl;
			snprintf(buff, 1024, "%s\n", results.back().c_str());
			ScanResults.push_back(buff);
			ScanResults.push_back("\n");
		}
		else {
			ScanResults.push_back("\n");
		}
	}
	closesocket(sock);
	free(infobuf);
	return 0;
}
#endif
static vector<string> temp_result;

static DWORD WINAPI ThreadProcTCP(LPVOID pPara);

static int TcpScan(unsigned long ipaddr, vector<uint16_t> portlist, vector<string>& ScanResults)

{
	WSADATA wsad;
	SOCKADDR_IN target;
	USHORT PortEnd, PortStart, i;

	clock_t TimeStart, TimeEnd;

	HANDLE    hThread;

	DWORD    dwThreadId;

	TimeStart = clock();
	WSAStartup(MAKEWORD(2, 2), &wsad);
	target.sin_family = AF_INET;
	target.sin_addr.s_addr = ipaddr;
	char buf[100];
	for (i = 0; i < temp_result.size(); i++)
	{
		ScanResults.push_back(temp_result[i]);
	}
	temp_result.clear();
	snprintf(buf, 100, "TCP Scanning IP: %s\n", inet_ntoa(target.sin_addr));
	ScanResults.push_back(buf);
	for (i = 0; i < portlist.size(); ++i) {
		target.sin_port = htons(portlist[i]);

		hThread = CreateThread(NULL, 0, ThreadProcTCP, (LPVOID)&target, 0, &dwThreadId);
///////add on 1105
		Sleep(1000);
////
		if (hThread == NULL) {
			printf("CreateThread() failed: %d\n", GetLastError());

			break;

		}
		CloseHandle(hThread);
	}
	Sleep(50);

	for (i = 0; i < temp_result.size(); i++)
	{
		ScanResults.push_back(temp_result[i]);
	}
	temp_result.clear();
	TimeEnd = clock();
	printf("Time cost:%.3fs\n", (float)(TimeEnd - TimeStart) / CLOCKS_PER_SEC);
	WSACleanup();
	return 0;
}

static byte Snmp_payload[] = {
	0x30,0x26,0x02,0x01,0x01,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xa1,
	0x19,0x02,0x04,0x04,0xc9,0x46,0xbc,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0b,0x30,
	0x09,0x06,0x05,0x2b,0x06,0x01,0x02,0x01,0x05,0x00
};


static DWORD WINAPI ThreadProcTCP(LPVOID pParam)
{
	SOCKADDR_IN target = *(SOCKADDR_IN*)pParam;
	SOCKET sConn;
	char buffer[256];
	char out_result[300];
	string temp_str;
	timeval t = { 50,0 };
	//printf("%s %d\n", inet_ntoa(target.sin_addr), ntohs(target.sin_port));
	sConn = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (setsockopt(sConn, SOL_SOCKET, SO_RCVTIMEO, (char*)&t, sizeof(timeval)) != 0)
	{
		cout << "Receive time set error\n";
	}
	if (connect(sConn, (const SOCKADDR*)&target, sizeof(target)) == SOCKET_ERROR)
	{
		return 0;
	}
	else {
		printf("%d\topen\n", ntohs(target.sin_port));
		snprintf(out_result, 300, "%d\topen\t", ntohs(target.sin_port));
		temp_str = temp_str + out_result;
		memset(out_result, 0, 300);
		int packet_len = recv(sConn, buffer, 256, 0);
		if (packet_len == SOCKET_ERROR)
		{
			temp_str = temp_str + "banner unknown\n";
		}
		else {
			asciiFilter((u_char*)buffer, packet_len);
			snprintf(out_result, 300, "%s\n", buffer);
			temp_str = temp_str + out_result;
		}
	}
	printf("%d\topen\n", ntohs(target.sin_port));
	temp_result.push_back(temp_str);
	closesocket(sConn);

	return 0;
}
static DWORD WINAPI ThreadProcUDP(LPVOID pParam)
{
	SOCKADDR_IN target = *(SOCKADDR_IN*)pParam;
	SOCKET sConn;
	int addr_len = sizeof(struct sockaddr_in);
	char buffer[256];
	char buf[100];
	memset(buffer, 0, sizeof(buffer));
	timeval t = { 50,0 };
	//printf("%s %d\n", inet_ntoa(target.sin_addr), ntohs(target.sin_port));
	sConn = socket(AF_INET, SOCK_DGRAM, 0);

	if (setsockopt(sConn, SOL_SOCKET, SO_SNDTIMEO, (char*)&t, sizeof(timeval)) != 0)
	{
		cout << "Send time set error\n";
	}
	if (setsockopt(sConn, SOL_SOCKET, SO_RCVTIMEO, (char*)&t, sizeof(timeval)) != 0)
	{
		cout << "Receive time set error\n";
	}
	if (sendto(sConn, buffer, sizeof(buffer), 0, (const SOCKADDR*)&target, sizeof(target)) == SOCKET_ERROR) return 0;
	if (recvfrom(sConn, buffer, sizeof(buffer), 0, (struct sockaddr*)&target, &addr_len) > 0)
	{
		snprintf(buf, 100, "%d\topen\n", ntohs(target.sin_port));
	}
	else
	{
		snprintf(buf, 100, "%d\tunknown\n", ntohs(target.sin_port));
	}
	temp_result.push_back(buf);
	closesocket(sConn);
	return 0;
}

static int SnmpScan(unsigned long ipaddr, vector<string>& ScanResults)
{
	WSADATA wsad;
	WSAStartup(MAKEWORD(2, 2), &wsad);
	SOCKADDR_IN sock;
	sock.sin_family = AF_INET;
	sock.sin_addr.s_addr = ipaddr;
	sock.sin_port = htons(161);
	int addr_len = sizeof(struct sockaddr_in);
	char buffer[256];

	snprintf(buffer, 256, "IP: %s\t", inet_ntoa(sock.sin_addr));
	ScanResults.push_back(buffer);
	memset(buffer, 0, sizeof(buffer));
	SOCKET sConn;
	sConn = socket(AF_INET, SOCK_DGRAM, 0);
	timeval t = { 100,0 };


	if (setsockopt(sConn, SOL_SOCKET, SO_SNDTIMEO, (char*)&t, sizeof(timeval)) != 0)
	{
		cout << "Send time set error\n";
	}
	if (setsockopt(sConn, SOL_SOCKET, SO_RCVTIMEO, (char*)&t, sizeof(timeval)) != 0)
	{
		cout << "Receive time set error\n";
	}
	if (sendto(sConn, (char*)Snmp_payload, sizeof(Snmp_payload), 0, (const SOCKADDR*)&sock, sizeof(sock)) == SOCKET_ERROR) return 0;

	int len;
	len = recvfrom(sConn, buffer, sizeof(buffer), 0, (struct sockaddr*)&sock, &addr_len);
	if (len > 0)
	{
		printf("Port %d is open\n", ntohs(sock.sin_port));
		asciiFilter((u_char*)buffer, len);
		char buf[200];
		snprintf(buf, 200, "%s\n", buffer);
		ScanResults.push_back(buf);
	}
	else {
		ScanResults.push_back("snmp no response\n");
	}
	/////add on 1105
	char out_result[300];
	sock.sin_port = htons(23);
	if (connect(sConn, (const SOCKADDR*)&sock, sizeof(sock)) == SOCKET_ERROR)
	{
		ScanResults.push_back("port 23 closed\n");
		return 0;
	}
	else {
		string temp_str;
		snprintf(out_result, 300, "%d\topen\t", ntohs(sock.sin_port));
		temp_str = temp_str + out_result;
		memset(out_result, 0, 300);
		int packet_len = recv(sConn, buffer, 256, 0);
		if (packet_len == SOCKET_ERROR)
		{
			temp_str = temp_str + "banner unknown\n";
		}
		else {
			asciiFilter((u_char*)buffer, packet_len);
			snprintf(out_result, 300, "%s\n", buffer);
			temp_str = temp_str + out_result;
		}
		ScanResults.push_back(temp_str);
	}
	//////

	closesocket(sConn);
}

static int UdpScan(unsigned long ipaddr, vector<uint16_t>& portlist, vector<string>& ScanResults)
{
	WSADATA wsad;
	SOCKADDR_IN target;
	USHORT i;
	clock_t TimeStart, TimeEnd;
	HANDLE    hThread;
	DWORD    dwThreadId;

	TimeStart = clock();
	WSAStartup(MAKEWORD(2, 2), &wsad);
	target.sin_family = AF_INET;
	target.sin_addr.s_addr = ipaddr;
	char buf[100];

	for (i = 0; i < temp_result.size(); i++)
	{
		ScanResults.push_back(temp_result[i]);
	}
	temp_result.clear();

	snprintf(buf, 100, "UDP Scanning IP: %s\n", inet_ntoa(target.sin_addr));
	ScanResults.push_back(buf);
	for (i = 0; i < portlist.size(); ++i) {
		target.sin_port = htons(portlist[i]);
		hThread = CreateThread(NULL, 0, ThreadProcUDP, (LPVOID)&target, 0, &dwThreadId);
		Sleep(70);
		if (hThread == NULL) {
			printf("CreateThread() failed: %d\n", GetLastError());
			break;
		}
		CloseHandle(hThread);
	}
	for (i = 0; i < temp_result.size(); i++)
	{
		ScanResults.push_back(temp_result[i]);
	}
	temp_result.clear();
	Sleep(50);
	TimeEnd = clock();
	printf("Time cost:%.3fs\n", (float)(TimeEnd - TimeStart) / CLOCKS_PER_SEC);
	WSACleanup();
	return 0;
}

static int snmp_Segment_Scan(vector<unsigned long>ipaddr, vector<string>& ScanResults)
{
	cout << "start Snmp Scan" << endl;
	ScanResults.push_back("###\nfunction48=SNMPScan\n$$$\n");
	for (int i = 0; i < ipaddr.size(); i++)
	{
		SnmpScan(ipaddr[i], ScanResults);
	}
	return 0;
}

static void tcp_Segment_Scan(vector<unsigned long>ipaddr, vector<uint16_t>& portlist, vector<string>& ScanResults)
{
	in_addr mAddr;
	ScanResults.push_back("###\nfunction46=TCPScan\n$$$\nTcp ports status and banner scan...\n");
	for (int i = 0; i < ipaddr.size(); i++)
	{
		TcpScan(ipaddr[i], portlist, ScanResults);
	}
}
static void udp_Segment_Scan(vector<unsigned long>ipaddr, vector<uint16_t>& portlist, vector<string>& ScanResults)
{
	in_addr mAddr;
	ScanResults.push_back("###\nfunction47=UDPScan\n$$$\nUDP ports status scan...\n");
	for (int i = 0; i < ipaddr.size(); i++)
	{
		UdpScan(ipaddr[i], portlist, ScanResults);
	}
}
#endif