#pragma once
#ifndef TCPIP_H
#define TCPIP_H

#define IP_TOS_DEFAULT 0x00
#define TH_SYN 0x02

#include "nbase.h"
#include "basic.h"

struct tcp_hdr {
    uint16_t	th_sport;	/* source port */
    uint16_t	th_dport;	/* destination port */
    uint32_t	th_seq;		/* sequence number */
    uint32_t	th_ack;		/* acknowledgment number */
#if DNET_BYTESEX == DNET_BIG_ENDIAN
    uint8_t		th_off : 4,	/* data offset */
        th_x2 : 4;	/* (unused) */
#elif DNET_BYTESEX == DNET_LIL_ENDIAN
    uint8_t		th_x2 : 4,
        th_off : 4;
#else
# error "need to include <dnet.h>"
#endif
    uint8_t		th_flags;	/* control flags */
    uint16_t	th_win;		/* window */
    uint16_t	th_sum;		/* checksum */
    uint16_t	th_urp;		/* urgent pointer */
};


struct ip
{
#if WORDS_BIGENDIAN
    u_int8_t ip_v : 4;                    /* version */
    u_int8_t ip_hl : 4;                   /* header length */
#else
    u_int8_t ip_hl : 4;                   /* header length */
    u_int8_t ip_v : 4;                    /* version */
#endif
    u_int8_t ip_tos;                    /* type of service */
    u_short ip_len;                     /* total length */
    u_short ip_id;                      /* identification */
    u_short ip_off;                     /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* don't fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
    u_int8_t ip_ttl;                    /* time to live */
    u_int8_t ip_p;                      /* protocol */
    u_short ip_sum;                     /* checksum */
    struct in_addr ip_src, ip_dst;      /* source and dest address */
};

struct sockaddr_storage {
    u16 ss_family;
    u16 __align_to_64[3];
    u64 __padding[16];
};

class PacketTrace {
public:
    static const int SENT = 1;
    static const int RCVD = 2;
    typedef int pdirection;

    static void trace(pdirection pdir, const u8* packet, u32 len, struct timeval* now = NULL);

    static void traceConnect(u8 proto, const struct sockaddr* sock,
        int socklen, int connectrc, int connect_errno,
        const struct timeval* now);
    static void traceArp(pdirection pdir, const u8* frame, u32 len,
        struct timeval* now);
    static void traceND(pdirection pdir, const u8* frame, u32 len,
        struct timeval* now);
};


int send_tcp_raw(int sd, const struct eth_nfo* eth,
    const struct in_addr* source, const struct in_addr* victim,
    int ttl, bool df,
    u8* ipopt, int ipoptlen,
    u16 sport, u16 dport,
    u32 seq, u32 ack, u8 reserved, u8 flags, u16 window, u16 urp,
    u8* options, int optlen,
    const char* data, u16 datalen);

int send_tcp_raw_decoys(int sd, const struct eth_nfo* eth,
    const struct in_addr* victim,
    int ttl, bool df,
    u8* ipopt, int ipoptlen,
    u16 sport, u16 dport,
    u32 seq, u32 ack, u8 reserved, u8 flags, u16 window, u16 urp,
    u8* options, int optlen,
    const char* data, u16 datalen);

u8* build_tcp_raw(const struct in_addr* source,
    const struct in_addr* victim, int ttl, u16 ipid, u8 tos,
    bool df, const u8* ipopt, int ipoptlen, u16 sport, u16 dport,
    u32 seq, u32 ack, u8 reserved, u8 flags, u16 window,
    u16 urp, const u8* tcpopt, int tcpoptlen, const char* data,
    u16 datalen, u32* packetlen);

u8* build_ip_raw(const struct in_addr* source, const struct in_addr* victim,
    u8 proto,
    int ttl, u16 ipid, u8 tos, bool df,
    const u8* ipopt, int ipoptlen,
    const char* data, u16 datalen,
    u32* packetlen);

int send_ip_packet(int sd, const struct eth_nfo* eth,
    const struct sockaddr_storage* dst,
    const u8* packet, unsigned int packetlen);

static u16 ipv4_cksum(const struct in_addr* src, const struct in_addr* dst,
    u8 proto, const void* data, u16 len);

static inline int fill_ip_raw(struct ip* ip, int packetlen, const u8* ipopt,
    int ipoptlen, int tos, int id,
    int off, int ttl, int p,
    const struct in_addr* ip_src,
    const struct in_addr* ip_dst);

int send_ip_packet_eth_or_sd(int sd, const struct eth_nfo* eth,
    const struct sockaddr_in* dst,
    const u8* packet, unsigned int packetlen);

int send_frag_ip_packet(int sd, const struct eth_nfo* eth,
    const struct sockaddr_in* dst,
    const u8* packet, unsigned int packetlen, u32 mtu);


long
eth_send(eth_t* e, const void* buf, size_t len)
{
    return (write(e->fd, buf, len));
}

#endif