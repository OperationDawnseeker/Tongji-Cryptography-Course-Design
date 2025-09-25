#include<string>
#include<iostream>
#include"RSA.h"
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
	y = PowerMod(x % n, b, n);
	
}

void RSA::Decrypt(const ZZ& y, ZZ& x)
{	//x=y^a mod n;
	x = PowerMod(y % n, a, n);
}