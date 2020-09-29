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
#endif