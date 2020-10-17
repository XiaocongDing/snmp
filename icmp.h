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

static void icmp_Segment_Scan(unsigned long starthost, unsigned long endhost, vector<string> &ScanResults,vector<unsigned int>&aliveIp)
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
			continue;
		}
		else 
		{
			temp = temp + inet_ntoa(from.sin_addr);
			temp = temp + "\talive\t";
			temp = temp + (char*)(tick - recv_icmp->icmp_timestamp);
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
			temp = temp + (char *)recv_ip->ttl + "\t";
			ScanResults.push_back(temp);
		}
	}
}