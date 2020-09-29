#include "tcpip.h"

static u8* build_tcp(u16 sport, u16 dport, u32 seq, u32 ack, u8 reserved,
    u8 flags, u16 window, u16 urp,
    const u8* tcpopt, int tcpoptlen,
    const char* data, u16 datalen, u32* packetlen) {
    struct tcp_hdr* tcp;
    u8* packet;

    if (tcpoptlen % 4 != 0)
        std::cout << "tcpoptlen error" << endl;

    *packetlen = sizeof(*tcp) + tcpoptlen + datalen;
    packet = (u8*)safe_malloc(*packetlen);
    tcp = (struct tcp_hdr*)packet;

    memset(tcp, 0, sizeof(*tcp));
    tcp->th_sport = htons(sport);
    tcp->th_dport = htons(dport);

    if (seq)
        tcp->th_seq = htonl(seq);
    else if (flags & TH_SYN)
        get_random_bytes(&(tcp->th_seq), 4);

    if (ack)
        tcp->th_ack = htonl(ack);

    if (reserved)
        tcp->th_x2 = reserved & 0x0F;
    tcp->th_off = 5 + (tcpoptlen / 4); /* words */
    tcp->th_flags = flags;

    if (window)
        tcp->th_win = htons(window);
    else
        tcp->th_win = htons(1024); /* Who cares */

    if (urp)
        tcp->th_urp = htons(urp);

    /* And the options */
    if (tcpoptlen)
        memcpy(packet + sizeof(*tcp), tcpopt, tcpoptlen);

    /* We should probably copy the data over too */
    if (data && datalen)
        memcpy(packet + sizeof(*tcp) + tcpoptlen, data, datalen);

    tcp->th_sum = 0;

    return packet;
}

int send_tcp_raw(int sd, const struct eth_nfo* eth,
    const struct in_addr* source,
    const struct in_addr* victim, int ttl, bool df,
    u8* ipops, int ipoptlen, u16 sport, u16 dport, u32 seq,s
    u32 ack, u8 reserved, u8 flags, u16 window, u16 urp,
    u8* options, int optlen, const char* data, u16 datalen) {
    struct sockaddr_storage dst;
    struct sockaddr_in* dst_in;
    unsigned int packetlen;
    int res = -1;

    u8* packet = build_tcp_raw(source, victim,
        ttl, get_random_u16(), IP_TOS_DEFAULT, df,
        ipops, ipoptlen,
        sport, dport,
        seq, ack, reserved, flags, window, urp,
        options, optlen,
        data, datalen, &packetlen);
    if (!packet)
        return -1;
    memset(&dst, 0, sizeof(dst));
    dst_in = (struct sockaddr_in*)&dst;
    dst_in->sin_family = AF_INET;
    dst_in->sin_addr = *victim;
    res = send_ip_packet(sd, eth, &dst, packet, packetlen);

    free(packet);
    return res;
}

int send_tcp_raw_decoys(int sd, const struct eth_nfo* eth,
    const struct in_addr* victim,
    int ttl, bool df,
    u8* ipopt, int ipoptlen,
    u16 sport, u16 dport,
    u32 seq, u32 ack, u8 reserved, u8 flags,
    u16 window, u16 urp, u8* options, int optlen,
    const char* data, u16 datalen) {
    int decoy;

    for (decoy = 0; decoy < o.numdecoys; decoy++)
        if (send_tcp_raw(sd, eth,
            &((struct sockaddr_in*)&o.decoys[decoy])->sin_addr, victim,
            ttl, df,
            ipopt, ipoptlen,
            sport, dport,
            seq, ack, reserved, flags, window, urp,
            options, optlen, data, datalen) == -1)
            return -1;

    return 0;
}

u8* build_tcp_raw(const struct in_addr* source,
    const struct in_addr* victim, int ttl, u16 ipid, u8 tos,
    bool df, const u8* ipopt, int ipoptlen, u16 sport, u16 dport,
    u32 seq, u32 ack, u8 reserved, u8 flags, u16 window,
    u16 urp, const u8* tcpopt, int tcpoptlen, const char* data,
    u16 datalen, u32* packetlen) {
    struct tcp_hdr* tcp;
    u32 tcplen;
    u8* ip;

    tcp = (struct tcp_hdr*)build_tcp(sport, dport, seq, ack, reserved, flags,
        window, urp, tcpopt, tcpoptlen, data, datalen, &tcplen);
    tcp->th_sum = ipv4_cksum(source, victim, IPPROTO_TCP, tcp, tcplen);
    ip = build_ip_raw(source, victim, IPPROTO_TCP, ttl, ipid, tos, df,
        ipopt, ipoptlen, (char*)tcp, tcplen, packetlen);
    free(tcp);

    return ip;
}