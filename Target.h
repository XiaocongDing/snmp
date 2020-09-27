#pragma once

#ifndef TARGET_H
#define TARGET_H

#include "nbase.h"
#include "osscan.h"
#include <time.h>
#include <string>

#define NUM_SEQ_SAMPLES 6
#define INET6_ADDRSTRLEN 46

struct host_timeout_nfo {
	unsigned long msecs_used;
	bool toclock_running;
	struct timeval toclock_start;
	time_t host_start, host_end;
};

struct seq_info {
	int responses;
	int ts_seqclass; /* TS_SEQ_* defines in nmap.h */
	int ipid_seqclass; /* IPID_SEQ_* defines in nmap.h */
	u32 seqs[NUM_SEQ_SAMPLES];
	u32 timestamps[NUM_SEQ_SAMPLES];
	int index;
	u16 ipids[NUM_SEQ_SAMPLES];
	time_t lastboot; /* 0 means unknown */
};

class Target {
public:
	Target();
	~Target();
	char* hostname;
	char* targetname;
	struct seq_info seq;
	int distance;
	int osscan_flag;
	int weird_responses;
	unsigned int flag;

	const u8* MACAddress() const;
	const u8* SrcMACAddress() const;
	const u8* NextHopMACAddress() const;

	int directly_connected;
	char targetipstring[INET6_ADDRSTRLEN];
	char sourceipstring[INET6_ADDRSTRLEN];

	u8 MACaddress[6], SrcMACaddress[6], NextHopMACaddress[6];



private:
	void Initialize();
	
};

#endif // !TARGET_H