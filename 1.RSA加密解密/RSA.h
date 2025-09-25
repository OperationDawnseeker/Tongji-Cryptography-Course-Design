#pragma once

#include<NTL/ZZ.h>
using namespace NTL;
using namespace std;

const int KEYLEN1 = 512;
const int KEYLEN2 = 1024;

class RSA {
private:
	const int KEYLEN;//pq³¤¶È
	ZZ a, p, q;
	ZZ Euler_n;//¦Õ(n)
	void GenerateKey();
public:
	ZZ n, b;

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
};