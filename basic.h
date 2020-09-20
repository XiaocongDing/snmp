#pragma once
#define WIN32
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <pcap.h>
#include <iphlpapi.h>
#include <String>
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

typedef struct UDPHDR
{
	u_short src_port;
	u_short des_port;
	u_short length;
	u_short cksum;
}UDP_HDR,*pUDP_HDR;

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

static void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[16];
	IP_HDR* ih;
	UDP_HDR* uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);


	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);


	ih = (IP_HDR*)(pkt_data +
		14);


	ip_len = (ih->h_lenver & 0xf) * 4;
	uh = (UDP_HDR*)((u_char*)ih + ip_len);


	sport = ntohs(uh->src_port);
	dport = ntohs(uh->des_port);

	cout << ih->srcIP << "  " << uh->src_port << endl;
	cout << ih->desIP << "  " << uh->des_port << endl;
}