#pragma once
#define WIN32
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <pcap.h>
#include <iphlpapi.h>
#include <String>
#include <assert.h>
#include <signal.h>
#include <Windows.h>
#include <vector>
#include <fstream>
#include <algorithm>
#include <stdlib.h>
#include <winsock2.h>
#include <cstdlib>
#include <cstring>
#include <WinSock2.h>
#include <regex>
#include <atlstr.h>
using namespace std;

#pragma comment(lib,"../lib/Packet.lib")
#pragma comment(lib,"../lib/wpcap.lib")
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

static void asciiFilter(u_char* buff,int size)
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
