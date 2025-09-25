#include<string>
#include<iostream>
#include<sstream>
#include"RSA.h"
#include"SHA.h"
using namespace NTL;
using namespace std;

void RSA::GenerateKey()
{
	const int keylen = KEYLEN;

	RandomPrime(p, keylen, 10);//测试20次
	RandomPrime(q, keylen, 10);
	n = p * q;

	Euler_n = (p - 1) * (q - 1);

	do {
		b = RandomBnd(Euler_n - 3) + 2;//生成0-n之间的为随机数。0<=x<=n ;  2<=b<=φ(n)-1
	} while (GCD(b, Euler_n) != 1);

	InvMod(a, b, Euler_n);//a=b^-1 mod φ(n)
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

void RSA::Sign(const ZZ& x, ZZ& sig)
{	//sigSK (x) = x^a mod n
	sig = PowerMod(x, a, n);
}

void RSA::Sign(const string& x, ZZ& sig)
{
	/* sha加密 输出长度为160bit */
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
	ZZ ver = PowerMod(y, b, n);
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

bool Verify(const string& x, const ZZ&n,const ZZ&b,const ZZ& y)
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

void RSA::printPerKey(ZZ& _p, ZZ& _q, ZZ& _a)
{
	_p = p; _q = q; _a = a;
}


ZZ RSA::Certificate(const ZZ& User_ID, const ZZ& n, const ZZ& b) {
	ZZ Cert = User_ID;
	ZZ sig;
	Cert = (Cert << (KEYLEN * 2)) + n;//ver=n||b
	Cert = (Cert << (KEYLEN * 2)) + b;//Cert=ID||ver

	ostringstream out;
	out << Cert;
	string ID_ver = out.str();

	Sign(ID_ver, sig);
	//cout << sig << endl;

	Cert = (Cert << KEYLEN * 2) + sig;

	Cert = (Cert << TAID_LEN) + ID;
	Cert = (Cert << 1) + ((KEYLEN == KEYLEN1) ? 0 : 1);//flag=0 -->512 1-->1024

	return Cert;
}


bool RSA::Cert_Verify(const ZZ& User_ID, const ZZ& n, const ZZ& b, const ZZ& Cert) {
	ZZ temp = power(ZZ(2), (KEYLEN * 2));
	ZZ sig;
	sig = Cert >> 1 + TAID_LEN;
	sig %= temp;
	//cout << sig << endl;
	temp = User_ID;
	temp = (temp << (KEYLEN * 2)) + n;//ver=n||b
	temp = (temp << (KEYLEN * 2)) + b;//Cert=ID||ver

	ostringstream out;
	out << temp;
	string ID_ver = out.str();

	bool ver = Verify(ID_ver, sig);

	return ver;

}

bool RSA::Cert_Verify(const ZZ& User_ID, const ZZ& Cert,ZZ&n_ret,ZZ&b_ret) {
	//如果验证成功会返回公钥
	ZZ temp = power(ZZ(2), (KEYLEN * 2));
	ZZ sig;
	ZZ _n;
	ZZ _b;
	sig = Cert >> 1 + TAID_LEN;
	sig %= temp;

	_n = _b = Cert >> 1 + TAID_LEN + KEYLEN * 2;
	_n = _n >> KEYLEN * 2;
	_b %= temp;
	_n %= temp;

	temp = power(ZZ(2), (KEYLEN * 2 + 1 + TAID_LEN));
	temp = Cert / temp;

	ostringstream out;
	out << temp;
	string ID_ver = out.str();

	bool ver = Verify(ID_ver, sig);
	n_ret = _n; b_ret = _b;
	return ver;
}