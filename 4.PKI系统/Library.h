#pragma once
//Ö¤Êé¿â

#include<NTL/ZZ.h>
#include<vector>
#include"RSA.h"
using namespace NTL;
using namespace std;

const int NO_CERT = 0;
const int NO_USERID = 1;
const int NO_TAID = 2;


class CERTLIB {
private:
	vector<vector<ZZ>>lib;
	const int KEYLEN;
public:
	CERTLIB(int keylen = KEYLEN1) : KEYLEN(keylen) {};
	vector<ZZ> findroute(const ZZ&User_ID);
	void addtolib(const ZZ& Cert);
};