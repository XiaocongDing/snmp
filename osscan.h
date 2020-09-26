#pragma once
#ifndef OSSCAN_H
#define OSSCAN_H

#include<vector>

#define OSSCAN_SUCCESS 0
#define OSSCAN_NOMATCHES -1
#define OSSCAN_TOOMANYMATCHES -2
#define OSSCAN_GUESS_THRESHOLD 0.85

enum dist_calc_method {
	DIST_METHOD_NONE,
	DIST_METHOD_LOCALHOST,
	DIST_METHOD_DIRECT,
	DIST_METHOD_ICMP,
	DIST_METHOD_TRACEROUTE
};

struct AVal {
	const char* attribute;
	const char* value;
	bool operator<(const AVal& other) const {
		return strcmp(attribute, other.attribute) < 0;
	}
};

struct OS_Classification {
	const char* OS_Vendor;
	const char* OS_Family;
	const char* OS_Generation;
	const char* Device_Type;
	std::vector<const char*> cpe;
};

struct FingerMatch {
	int line; //reference
	unsigned short numprints;
	char* OS_name;
	std::vector<OS_Classification> OS_class;
	FingerMatch()
	{
		line = -1;
		OS_name = NULL;
	}
};

struct FingerTest {
	const char* name;
	std::vector<struct AVal> results;
	bool operator<(const FingerTest& other)const {
		return strcmp(name, other.name) < 0;
	}
};

struct FingerPrint {
	FingerMatch match;
	std::vector<FingerTest> test;
	FingerPrint();
	void sort();
};

class HostOsScanStats {
	FingerPrint* FP;
};

#endif