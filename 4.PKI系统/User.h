#pragma once
#include<iostream>
#include<NTL/ZZ.h>
#include"RSA.h"
#include"Library.h"
using namespace NTL;
using namespace std;

const ZZ CAROOT_ID = ZZ(100000);
const ZZ CA1_ID = ZZ(100001);
const ZZ CA2_ID = ZZ(100002);

const ZZ Alice_ID = ZZ(5000000029);
const ZZ Bob_ID = ZZ(45685210017);
const ZZ Eve_ID = ZZ(999999999902);


int ReadFile(const string& filename, string& message)
{
	ifstream in;
	char ch;
	in.open(filename, ios::in);
	if (!in.is_open()) {
		cout << filename << "打开失败" << endl;
		return -1;
	}
	in >> message;
	in.close();
	cout << "已成功读取" << filename << endl;
	return 0;
}

int ReadFile(const string& filename, ZZ& message)
{
	ifstream in;
	in.open(filename, ios::in);
	if (!in.is_open()) {
		cout << filename << "打开失败" << endl;
		return -1;
	}
	in >> message;
	in.close();
	cout << "已成功读取" << filename << endl;
	return 0;
}

class _Alice {
private:
	RSA Alice;

public:
	ZZ ApplyCertficate( RSA& CA, CERTLIB& lib) {
		
		Alice.ID = Alice_ID;

		ZZ Alice_Cert = CA.Certificate(Alice.ID, Alice.n, Alice.b);
		lib.addtolib(Alice_Cert);
		return Alice_Cert;
	}

	ZZ SignMessage(const string&filename) {
		ZZ sig;
		string message;
		ReadFile(filename, message);
		Alice.Sign(message, sig);
		return sig;
	}


};

class _Bob {
private:
	RSA Bob;
public:
	ZZ ApplyCertficate( RSA& CA, CERTLIB& lib) {

		Bob.ID = Bob_ID;

		ZZ Bob_Cert = CA.Certificate(Bob.ID, Bob.n, Bob.b);
		lib.addtolib(Bob_Cert);
		return Bob_Cert;
	}

	vector<ZZ> CheckCertficate(const ZZ& User_ID, CERTLIB& lib)
	{
		return lib.findroute(User_ID);
	}

	bool VerifyCertRoute(RSA& CAROOT, RSA& CA1, RSA& CA2, vector<ZZ>& route,ZZ&_n,ZZ&_b) {
		ZZ n, b;
		bool ver1 = CAROOT.Cert_Verify(CAROOT_ID, route[0], n, b);
		bool ver2 = CAROOT.Cert_Verify(CA1_ID, route[1], n, b);
		bool ver3 = CA1.Cert_Verify(Alice_ID, route[2], n, b);
		_n = n, _b = b;
		if (ver1 && ver2 && ver3) {
			cout << "证书路径正确" << endl;
			return 1;
		}
		else {
			cout << "证书路径验证失败" << endl;
			return 0;
		}
	}

	bool VerifySig(string &m_filename,string &sig_filename,ZZ&n,ZZ&b) {
		string message;
		ReadFile(m_filename, message);
		ZZ sig;
		ReadFile(sig_filename, sig);
		bool ver = Verify(message, n, b, sig);
		cout << "签名验证：" << ( ver? "true" : "false") << endl;
		return ver;
	}
};

class _Eve {
private:
	RSA Eve;
public:
	ZZ ApplyCertficate(RSA& CA, CERTLIB& lib) {

		Eve.ID = Bob_ID;

		ZZ Eve_Cert = CA.Certificate(Eve.ID, Eve.n, Eve.b);
		lib.addtolib(Eve_Cert);
		return Eve_Cert;
	}

};