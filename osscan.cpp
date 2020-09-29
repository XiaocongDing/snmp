#include "osscan.h"

int HostOsScan::send_tcp_probe(HostOsScanStats* hss,
	int ttl, bool df, u8* ipopt, int ipoptlen,
	u16 sport, u16 dport, u32 seq, u32 ack,
	u8 reserved, u8 flags, u16 window, u16 urp,
	u8* option, int oplen,
	char* data, u16 datalen)
{

}