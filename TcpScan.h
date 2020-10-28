#pragma once
#include <time.h>
#include "basic.h"


static vector<string> temp_result;

static DWORD WINAPI ThreadProcTCP(LPVOID pPara);

static int TcpScan(unsigned long ipaddr, vector<uint16_t> portlist, vector<string> &ScanResults)

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

        Sleep(100);

        if (hThread == NULL) {
            printf("CreateThread() failed: %d\n", GetLastError());

            break;

        }
        CloseHandle(hThread);
    }
    Sleep(50);

    for ( i = 0; i < temp_result.size(); i++)
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
    
    if (setsockopt(sConn,SOL_SOCKET,SO_SNDTIMEO,(char*)&t,sizeof(timeval)) != 0)
    {
        cout << "Send time set error\n";
    }
    if (setsockopt(sConn, SOL_SOCKET, SO_RCVTIMEO, (char*)&t, sizeof(timeval)) != 0)
    {
        cout << "Receive time set error\n";
    }
    if (sendto(sConn, buffer,sizeof(buffer),0,(const SOCKADDR*)&target, sizeof(target)) == SOCKET_ERROR) return 0;
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

static int SnmpScan(unsigned long ipaddr,vector<string> &ScanResults)
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
    if ( len > 0)
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
    closesocket(sConn);
}

static int UdpScan(unsigned long ipaddr, vector<uint16_t> &portlist,vector<string> &ScanResults)
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
    for ( i = 0; i < temp_result.size(); i++)
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

static void tcp_Segment_Scan(vector<unsigned long>ipaddr, vector<uint16_t>&portlist ,vector<string>& ScanResults)
{
    in_addr mAddr;
    ScanResults.push_back("###\nfunction46=TCPScan\n$$$\nTcp ports status and banner scan...\n");
    for (int i = 0; i < ipaddr.size(); i++)
    {
        TcpScan(ipaddr[i], portlist, ScanResults);
    }
}
static void udp_Segment_Scan(vector<unsigned long>ipaddr, vector<uint16_t>&portlist ,vector<string>& ScanResults)
{
    in_addr mAddr;
    ScanResults.push_back("###\nfunction47=UDPScan\n$$$\nUDP ports status scan...\n");
    for (int i = 0; i < ipaddr.size(); i++)
    {
        UdpScan(ipaddr[i], portlist, ScanResults);
    }
}
