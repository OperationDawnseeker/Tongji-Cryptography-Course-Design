#pragma once
#include<NTL/ZZ.h>
using namespace NTL;
using namespace std;

const int KEYLEN1 = 512;//单位：bit
const int KEYLEN2 = 1024;

const int USERID_LEN = 64;//单位：bit
const int TAID_LEN = 64;

class RSA {
private:
	const int KEYLEN;//pq长度
	ZZ a, p, q;
	ZZ Euler_n;//φ(n)
	void GenerateKey();
public:
	ZZ n, b;
	ZZ ID;

	RSA(int keylen = KEYLEN1) : KEYLEN(keylen) {
		this->GenerateKey();
	}

	void Encrypt(const ZZ& x, ZZ& y);
	void Decrypt(const ZZ& y, ZZ& x);

	void display() {
		cout << "pri:p,q,a" << endl;
		cout << p << endl << q << endl << a << endl;
		cout << "pub:n,b" << endl;
		cout << n << endl << b << endl;
	}

	void Sign(const ZZ& x, ZZ& sig);
	void Sign(const string& x, ZZ& sig);
	bool Verify(const ZZ& x, const ZZ& y);
	bool Verify(const string& x, const ZZ& y);

	void printPerKey(ZZ& _p, ZZ& _q, ZZ& _a);//打印私钥

	ZZ Certificate(const ZZ& User_ID, const ZZ& n, const ZZ& b);
	bool Cert_Verify(const ZZ& User_ID, const ZZ& n, const ZZ& b, const ZZ& Cert);
	bool Cert_Verify(const ZZ& User_ID, const ZZ& Cert, ZZ& n_ret, ZZ& b_ret);

};

bool Verify(const string& x, const ZZ& n, const ZZ& b, const ZZ& y);
