#include "tcpip.h"
#define o.numdecoys 10


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
    u8* ipops, int ipoptlen, u16 sport, u16 dport, u32 seq,
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

static int send_ipv4_packet(int sd, const struct eth_nfo* eth,
    const struct sockaddr_in* dst,
    const u8* packet, unsigned int packetlen) {
    struct ip* ip = (struct ip*)packet;
    int res;

    assert(packet);
    assert((int)packetlen > 0);

    /* Fragmentation requested && packet is bigger than MTU */
    if (o.fragscan && !(ntohs(ip->ip_off) & IP_DF) &&
        (packetlen - ip->ip_hl * 4 > (unsigned int)o.fragscan)) {
        res = send_frag_ip_packet(sd, eth, dst, packet, packetlen, o.fragscan);
    }
    else {
        res = send_ip_packet_eth_or_sd(sd, eth, dst, packet, packetlen);
    }
    if (res != -1)
        PacketTrace::trace(PacketTrace::SENT, packet, packetlen);

    return res;
}

int send_ip_packet(int sd, const struct eth_nfo* eth,
    const struct sockaddr_storage* dst,
    const u8* packet, unsigned int packetlen) {
    struct ip* ip = (struct ip*)packet;

    /* Ensure there's enough to read ip->ip_v at least. */
    if (packetlen < 1)
        return -1;

    if (ip->ip_v == 4) {
        if (dst->ss_family != AF_INET)
            return -1;
        return send_ipv4_packet(sd, eth, (struct sockaddr_in*)dst, packet, packetlen);
    }
    else if (ip->ip_v == 6) {
        return -1;
    }

    return -1;
}

u8* build_ip_raw(const struct in_addr* source,
    const struct in_addr* victim, u8 proto, int ttl,
    u16 ipid, u8 tos, bool df, const u8* ipopt, int ipoptlen,
    const char* data, u16 datalen, u32* outpacketlen) {
    int packetlen = sizeof(struct ip) + ipoptlen + datalen;
    u8* packet = (u8*)safe_malloc(packetlen);
    struct ip* ip = (struct ip*)packet;
    static int myttl = 0;

    /* check that required fields are there and not too silly */
    assert(source);
    assert(victim);
    assert(ipoptlen % 4 == 0);

    /* Time to live */
    if (ttl == -1) {
        myttl = (get_random_uint() % 23) + 37;
    }
    else {
        myttl = ttl;
    }

    fill_ip_raw(ip, packetlen, ipopt, ipoptlen,
        tos, ipid, df ? IP_DF : 0, myttl, proto, source, victim);

    /* We should probably copy the data over too */
    if (data && datalen)
        memcpy((u8*)ip + sizeof(struct ip) + ipoptlen, data, datalen);

    *outpacketlen = packetlen;
    return packet;
}

static inline int fill_ip_raw(struct ip* ip, int packetlen, const u8* ipopt,
    int ipoptlen, int tos, int id,
    int off, int ttl, int p,
    const struct in_addr* ip_src,
    const struct in_addr* ip_dst) {
    ip->ip_v = 4;
    ip->ip_hl = 5 + (ipoptlen / 4);
    ip->ip_tos = tos;
    ip->ip_len = htons(packetlen);
    ip->ip_id = htons(id);
    ip->ip_off = htons(off);
    ip->ip_ttl = ttl;
    ip->ip_p = p;
    ip->ip_src.s_addr = ip_src->s_addr;
    ip->ip_dst.s_addr = ip_dst->s_addr;

    if (ipoptlen)
        memcpy((u8*)ip + sizeof(struct ip), ipopt, ipoptlen);

    // ip options source routing hack:
    if (ipoptlen && o.ipopt_firsthop && o.ipopt_lasthop) {
        u8* ipo = (u8*)ip + sizeof(struct ip);
        struct in_addr* newdst = (struct in_addr*)&ipo[o.ipopt_firsthop];
        struct in_addr* olddst = (struct in_addr*)&ipo[o.ipopt_lasthop];
        // our destination is somewhere else :)
        ip->ip_dst.s_addr = newdst->s_addr;

        // and last hop should be destination
        olddst->s_addr = ip_dst->s_addr;
    }

#if HAVE_IP_IP_SUM
    ip->ip_sum = 0;
    ip->ip_sum = in_cksum((unsigned short*)ip, sizeof(struct ip) + ipoptlen);
#endif
    return (sizeof(struct ip) + ipoptlen);
}

static u16 ipv4_cksum(const struct in_addr* src, const struct in_addr* dst,
    u8 proto, const void* data, u16 len) {
    u16 sum;

#if STUPID_SOLARIS_CHECKSUM_BUG
    sum = len;
#else
    sum = ipv4_pseudoheader_cksum(src, dst, proto, len, data);
#endif

    if (o.badsum) {
        --sum;
        if (proto == IPPROTO_UDP && sum == 0)
            sum = 0xffff; // UDP checksum=0 means no checksum
    }

    return sum;
}

int send_ip_packet_eth_or_sd(int sd, const struct eth_nfo* eth,
    const struct sockaddr_in* dst,
    const u8* packet, unsigned int packetlen) {
    if (eth)
        return send_ip_packet_eth(eth, packet, packetlen);
    else
        return send_ip_packet_sd(sd, dst, packet, packetlen);
}

int send_frag_ip_packet(int sd, const struct eth_nfo* eth,
    const struct sockaddr_in* dst,
    const u8* packet, unsigned int packetlen, u32 mtu) {
    struct ip* ip = (struct ip*)packet;
    int headerlen = ip->ip_hl * 4; // better than sizeof(struct ip)
    u32 datalen = packetlen - headerlen;
    int fdatalen = 0, res = 0;
    int fragment = 0;

    assert(headerlen <= (int)packetlen);
    assert(headerlen >= 20 && headerlen <= 60); // sanity check (RFC791)
    assert(mtu > 0 && mtu % 8 == 0); // otherwise, we couldn't set Fragment offset (ip->ip_off) correctly

    if (datalen <= mtu) {
        //netutil_error("Warning: fragmentation (mtu=%lu) requested but the payload is too small already (%lu)", (unsigned long)mtu, (unsigned long)datalen);
        return send_ip_packet_eth_or_sd(sd, eth, dst, packet, packetlen);
    }

    u8* fpacket = (u8*)safe_malloc(headerlen + mtu);
    memcpy(fpacket, packet, headerlen + mtu);
    ip = (struct ip*)fpacket;

    // create fragments and send them
    for (fragment = 1; fragment * mtu < datalen + mtu; fragment++) {
        fdatalen = (fragment * mtu <= datalen ? mtu : datalen % mtu);
        ip->ip_len = htons(headerlen + fdatalen);
        ip->ip_off = htons((fragment - 1) * mtu / 8);
        if ((fragment - 1) * mtu + fdatalen < datalen)
            ip->ip_off |= htons(IP_MF);
#if HAVE_IP_IP_SUM
        ip->ip_sum = 0;
        ip->ip_sum = in_cksum((unsigned short*)ip, headerlen);
#endif
        if (fragment > 1) // copy data payload
            memcpy(fpacket + headerlen,
                packet + headerlen + (fragment - 1) * mtu, fdatalen);
        res = send_ip_packet_eth_or_sd(sd, eth, dst, fpacket, ntohs(ip->ip_len));
        if (res == -1)
            break;
    }
    free(fpacket);
    return res;
}


int send_ip_packet_eth(const struct eth_nfo* eth, const u8* packet, unsigned int packetlen) {
    eth_t* ethsd;
    u8* eth_frame;
    int res;

    eth_frame = (u8*)safe_malloc(14 + packetlen);
    memcpy(eth_frame + 14, packet, packetlen);
    //eth_pack_hdr(eth_frame, eth->dstmac, eth->srcmac, ETH_TYPE_IP);
    if (!eth->ethsd) {
     //   ethsd = eth_open_cached(eth->devname);
       // if (!ethsd)
       //     netutil_fatal("%s: Failed to open ethernet device (%s)", __func__, eth->devname);
    }
    else {
        ethsd = eth->ethsd;
    }
    res = eth_send(ethsd, eth_frame, 14 + packetlen);
    /* No need to close ethsd due to caching */
    free(eth_frame);

    return res;
}