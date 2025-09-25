#include<string>
#include<iostream>
#include"RSA.h"
#include"SHA.h"

using namespace NTL;
using namespace std;

void RSA::GenerateKey()
{
	const int keylen = KEYLEN;

	RandomPrime(p, keylen, 10);//����20��
	RandomPrime(q, keylen, 10);
	n = p * q;

	Euler_n = (p - 1) * (q - 1);

	do {
		b = RandomBnd(Euler_n - 3) + 2;//����0-n֮���Ϊ�������0<=x<=n ;  2<=b<=��(n)-1
	} while (GCD(b, Euler_n) != 1);

	InvMod(a, b, Euler_n);//a=b^-1 mod ��(n)

	if (a < 0)
		a += Euler_n;
}

void RSA::Encrypt(const ZZ& x, ZZ& y) {
	//y=x^b mod n
	y = PowerMod(x%n, b, n);

}

void RSA::Decrypt(const ZZ& y, ZZ& x)
{	//x=y^a mod n;
	x = PowerMod(y%n, a, n);
}


void RSA::Sign(const ZZ& x, ZZ& sig)
{	//sigSK (x) = x^a mod n
	sig = PowerMod(x, a, n);
}

void RSA::Sign(const string& x, ZZ& sig) 
{
	/* sha���� �������Ϊ160bit */
	SHA_1 sha;
	vector<DWORD> sha_x;
	ZZ hx = ZZ(0);

	sha_x = sha.SHA_Encrypt(x);

	hx = sha_x[0];

	for (int i = 1; i < sha_x.size(); i++) {
		hx = (hx << (sizeOfDWORD)) + sha_x[i];
	}

	sig = PowerMod(hx % n, a, n);
}

bool RSA::Verify(const ZZ& x, const ZZ& y)
{	//verPK(x,y)=(x == y^b mod n)?
	ZZ ver= PowerMod(y, b, n);
	return (ver == x);
}

bool RSA::Verify(const string& x, const ZZ& y)
{	//verPK(x,y)=(x == y^b mod n)?

	SHA_1 sha;
	vector<DWORD> sha_x;
	ZZ hx = ZZ(0);

	sha_x = sha.SHA_Encrypt(x);

	hx = sha_x[0];

	for (int i = 1; i < sha_x.size(); i++) {
		hx = (hx << (sizeOfDWORD)) + sha_x[i];
	}

	ZZ ver = PowerMod(y % n, b, n);

	return (ver == hx % n);
}