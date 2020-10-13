#include "snmp.h"

void SendRaw ::ifprint(pcap_if_t *d)
{
	if (d == NULL)
		return;
	pcap_addr_t *a;
	char ip6str[128];

	/* Name */
	printf("%s\n", d->name);

	/* Description */
	if (d->description)
		printf("\tDescription: %s\n", d->description);

	/* Loopback Address*/
	printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

	/* IP addresses */
	for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);

		
		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
				printf("\tAddress: %s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
			if (a->netmask)
				printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)
				printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)
				printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
			break;

		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	printf("\n");
}
pcap_if_t * SendRaw:: IpfindIf(string ipv4)
{
	pcap_addr_t *a;
	pcap_if_t *p;
	string t;
	int end = ipv4.find_last_of('.');
	ipv4 = ipv4.substr(0, end);
	
	for( p =alldevs ; p ; p = p->next)
	{
		for(a = p->addresses; a ; a=a->next)
		{
			if (a->addr->sa_family == AF_INET)
			{
				t = iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr);
				lhIP = t;
				t = t.substr(0, end);
				if (!ipv4.compare(t))
				{
					d = p;
					return p;
				}
			}
		}
	}
	return NULL;
}
/* From tcptraceroute, convert a numeric IP address to a string */

#define IPTOSBUFFERS	12
char * SendRaw::iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

int SendRaw::tcpScan(string ipaddr)
{
	
	return 0;
}

int SendRaw::setFilter(string ipaddr,char packet_filter[])
{
	u_int netmask;
	fp = pcap_open_live(d->name, 65536, 1, 100, errbuf);
	if (fp == NULL)
	{
		exit(1);
	}
	if (pcap_datalink(fp) != DLT_EN10MB)
	{
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (d->addresses != NULL)

		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else

		netmask = 0xffffff;
	if (pcap_compile(fp, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_setfilter(fp, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("\nlistening on %s...\n", d->description);

	pcap_freealldevs(alldevs);
}

typedef struct __THREAD_DATA
{
	pcap_t* fp;
	DWORD timeout;
}THREAD_DATA;	

DWORD WINAPI ThreadProc1(LPVOID lp)
{
	THREAD_DATA* pThreadData = (THREAD_DATA*)lp;
	pcap_loop(pThreadData->fp, 2000, tcp_packet_handler, NULL);
	return 0L;
}
DWORD WINAPI ThreadProc2(LPVOID lp)
{
	THREAD_DATA* pThreadData = (THREAD_DATA*)lp;
	Sleep(pThreadData->timeout);
	pcap_breakloop(pThreadData->fp);
	pcap_close(pThreadData->fp);
	return 0L;
}

int SendRaw::tcpReceive(string ipaddr)
{
	string packet_filter = "tcp and host ";
	packet_filter = packet_filter + ipaddr;
	setFilter(ipaddr, (char*)packet_filter.c_str());
	THREAD_DATA threadData;
	threadData.fp = fp;
	threadData.timeout = 130000;
	HANDLE thread1 = CreateThread(NULL, 0, ThreadProc1, &threadData, 0, NULL);
	HANDLE thread2 = CreateThread(NULL, 0, ThreadProc2, &threadData, 0, NULL);
	Sleep(12000); // must be smaller than time in ThreadProc2, thread1 can not be null 
	CloseHandle(thread1); // if thread1 = null, an error occurs.
	CloseHandle(thread2);
	return 0;
}
int SendRaw::snmpScan(string ipaddr)
{	
	d = IpfindIf(ipaddr);
	fp = pcap_open_live(d->name, 65536, 1, 100, errbuf);
	if (fp == NULL)
	{
		exit(1);
	}
	//Ethernet
	char* MacAddr;
	char* MacLocal;
	MacAddr = getMac(inet_addr(ipaddr.c_str()));
	memcpy(packet, MacAddr, 6);
	MacLocal=(char *)malloc(sizeof(MacLocal));
	getlocalmacbyip(inet_addr(ipaddr.c_str()),MacLocal);
	memcpy(packet + 6, MacLocal, 6);
	packet[12] = 0x08;
	packet[13] = 0x00;
	//IPPROTO
	IPHDR iphdr;
	iphdr.h_lenver = 0x45;
	iphdr.tos = 0x00;
	iphdr.total_len = 0;
	iphdr.ident = 0xcdbb;
	iphdr.frag_and_flags = 0x00;
	iphdr.ttl = 0x38;
	iphdr.proto = 0x11;
	iphdr.checksum = 0x00;
	iphdr.srcIP = inet_addr(lhIP.c_str());
	iphdr.desIP = inet_addr(ipaddr.c_str());
	//UDP
	UDPHDR udphdr;
	udphdr.src_port = htons(60340);
	udphdr.des_port = htons(161);
	udphdr.length = 0x00;
	udphdr.cksum = 0x00;
	//SNMP

	SNMPHDR snmphdr;
	snmphdr.hdr = 0x01022630;
	snmphdr.version = 0x01;
	snmphdr.us1 = 0x04;
	snmphdr.us2 = 0x06;
	snmphdr.us3 = 'p';
	u_char buf[10] = "ublic";
	snmphdr.community = (u_char*)malloc(6);
	memcpy(&snmphdr.community, buf, 6);
	snmphdr.us4 = 'c';
	snmphdr.us5 = 0xa1;
	snmphdr.us6 = 0x19;
	snmphdr.us7 = 0x02;
	snmphdr.us8 = 0x04;
	//snmphdr.num1 = 0xa1190204;
	snmphdr.requestId[0] = 0x25;
	snmphdr.requestId[1] = 0x93;
	snmphdr.requestId[2] = 0x37;
	snmphdr.requestId[3] = 0x4f;
	snmphdr.err_stat[0] = 0x02;
	snmphdr.err_stat[1] = 0x01;
	snmphdr.err_stat[2] = 0x00;
	snmphdr.err_index[0] = 0x02;
	snmphdr.err_index[1] = 0x01;
	snmphdr.err_index[2] = 0x00;
	snmphdr.num[0] = 0x30;
	snmphdr.num[1] = 0x0b;
	snmphdr.num[2] = 0x30;
	snmphdr.num[3] = 0x09;
	snmphdr.num[4] = 0x06;
	snmphdr.num[5] = 0x05;
	snmphdr.num[6] = 0x2b;
	snmphdr.num[7] = 0x06;
	snmphdr.num[8] = 0x01;
	snmphdr.num[9] = 0x02;
	snmphdr.num[10] = 0x01;
	snmphdr.num[11] = 0x05;
	snmphdr.num[12] = 0x00;


	//length && checksum
	udphdr.length = htons( sizeof(udphdr) + sizeof(snmphdr));

	memcpy(buff, &iphdr.srcIP, sizeof(int));
	memcpy(buff + 4, &iphdr.desIP, sizeof(int));
	memcpy(buff + 8, &udphdr, sizeof(udphdr));
	u_short t = 0x1100;
	memcpy(buff + 8 + sizeof(udphdr),&t, sizeof(u_short));
	memcpy(buff + 10 + sizeof(udphdr), &udphdr.length, sizeof(u_short));
	memcpy(buff + 12 + sizeof(udphdr), &snmphdr, sizeof(snmphdr));
	udphdr.cksum = checksum((USHORT*)buff, sizeof(udphdr) + 12 + sizeof(snmphdr));

	iphdr.total_len = htons(sizeof(iphdr) + sizeof(udphdr) + sizeof(snmphdr));
	memcpy(buff, &iphdr, sizeof(iphdr));
	iphdr.checksum = checksum((USHORT*)buff, sizeof(iphdr));
	memcpy(buff, &iphdr, sizeof(iphdr));
	memcpy(buff + sizeof(iphdr), &udphdr, sizeof(udphdr));
	memcpy(buff + sizeof(iphdr) + sizeof(udphdr), &snmphdr, sizeof(snmphdr));
	
	memcpy(packet + 14, buff, sizeof(iphdr) + sizeof(udphdr) + sizeof(snmphdr));

	int i = 10;
	while (i--)
	{
		if (pcap_sendpacket(fp,
			packet,
			14 + sizeof(iphdr) + sizeof(udphdr) + sizeof(snmphdr)
		) != 0)
		{
			fprintf(stderr, "\nError sending the packet : %s\n", pcap_geterr(fp));
			return 3;
		}
	}
	
	pcap_close(fp);
	return 0;
}

char* SendRaw::getMac(u_long ip)
{
	in_addr mAddr;
	mAddr.S_un.S_addr = ip;
	ULONG MacArr[2];
	DWORD AddrLen = 6;
	if (SendARP(mAddr.S_un.S_addr, NULL, MacArr, &AddrLen) == NO_ERROR)
	{
		char* bPhysAddr = (char*)MacArr;
		return bPhysAddr;
	}
	return 0;
}

bool SendRaw::getlocalmac(char* sMac)
{
	bool bRtn = false;
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) != ERROR_SUCCESS)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
	}
	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
	{
		pAdapter = pAdapterInfo;
		char szMac[20] = { 0 };
		char szAddress[4] = { 0 };
		while (pAdapter)
		{

			if (strcmp(pAdapter->IpAddressList.IpAddress.String, "0.0.0.0") != 0)
			{
				for (UINT i = 0; i < pAdapter->AddressLength; i++)
				{
					sprintf_s(szAddress, "%02X", pAdapter->Address[i]);
					strcat_s(szMac, szAddress);
					if (i != pAdapter->AddressLength - 1)
					{
						strcat_s(szMac, ":");
					}
				}
				break;
			}
			cout << "SzAddress: "<<szAddress << endl;
			pAdapter = pAdapter->Next;
		}
		memcpy(sMac, szMac, strlen(szMac));
		bRtn = true;
	}

	return bRtn;
}

bool SendRaw::getlocalmacbyip(ULONG IP,char *src)
{
	ULONG ulAdapterInfoSize = sizeof(IP_ADAPTER_INFO);
	IP_ADAPTER_INFO* pAdapterInfo = (IP_ADAPTER_INFO*)new char[ulAdapterInfoSize];
	IP_ADAPTER_INFO* pAdapterInfoEnum = NULL;

	if (GetAdaptersInfo(pAdapterInfo, &ulAdapterInfoSize) == ERROR_BUFFER_OVERFLOW)
	{
		delete[] pAdapterInfo;
		pAdapterInfo = (IP_ADAPTER_INFO*)new char[ulAdapterInfoSize];
	}
	pAdapterInfoEnum = pAdapterInfo;
	if (GetAdaptersInfo(pAdapterInfoEnum, &ulAdapterInfoSize) == ERROR_SUCCESS)
	{
		do {
			if (pAdapterInfoEnum->Type == MIB_IF_TYPE_ETHERNET)
			{
				if(swap_endian(inet_addr(pAdapterInfoEnum->IpAddressList.IpAddress.String))/256 == swap_endian(IP)/256)
				{
					printf("%s IP: %s GATEIP: %s\n ", pAdapterInfoEnum->AdapterName,
						pAdapterInfoEnum->IpAddressList.IpAddress.String, pAdapterInfoEnum->GatewayList.IpAddress.String);
					printf("MAC: %02X%02X%02X%02X%02X%02X\n", pAdapterInfoEnum->Address[0], pAdapterInfoEnum->Address[1],
						pAdapterInfoEnum->Address[2], pAdapterInfoEnum->Address[3], pAdapterInfoEnum->Address[4], pAdapterInfoEnum->Address[5]);
					memcpy(src, pAdapterInfoEnum->Address, 6);
					return true;
				}
			}
			pAdapterInfoEnum = pAdapterInfoEnum->Next;
		} while (pAdapterInfoEnum);
	}
	delete[]pAdapterInfo;
	return false;
}

int SendRaw::snmpReceive(string ipaddr)
{
	char packet_filter[] = "udp dst port 60340";
	setFilter(ipaddr, packet_filter);
	pcap_loop(fp, 1, snmp_packet_handler, NULL);
	pcap_breakloop(fp);
	pcap_close(fp);
	return 0;
}



