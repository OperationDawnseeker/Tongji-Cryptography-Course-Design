#include<iostream>
#include<NTL/ZZ.h>
#include<fstream>
#include"RSA.h"
#include"SHA.h"
#include<bitset>

using namespace std;
using namespace NTL;

/* 实现一个简单的证书方案 */
//包含证书颁发（协议9.5）和证书验证。


int main()
{
	int len, sel;
	cout << "请选择p，q的比特长：1-512bit  2-1024bit" << endl;
	cin >> sel;
	if (sel == 1 || sel == 512)
		len = KEYLEN1;
	else if (sel == 2 || sel == 1024)
		len = KEYLEN2;
	else
		len = KEYLEN1;
	/*************************************************************************/

	RSA rsa_Alice(len), rsa_TA(len);

	ifstream in; 
	in.open("Alice_id.txt", ios::in);
	if (!in.is_open()) {
		cout << "Alice_id.txt打开失败" << endl;
		return -1;
	}
	in >> rsa_Alice.ID;//直接由大整数输入id
	in.close();

	in.open("TA_id.txt", ios::in);
	if (!in.is_open()) {
		cout << "TA_id.txt打开失败" << endl;
		return -1;
	}
	in >> rsa_TA.ID;//直接由大整数输入id
	in.close();

	/*************************************************************************/
	/*                             证书颁发                                  */
	/*************************************************************************/
	ZZ Cert_Alice = rsa_TA.Certificate(rsa_Alice.ID, rsa_Alice.n, rsa_Alice.b);

	ZZ p, q, a; 
	rsa_Alice.printPerKey(p, q, a);

	ofstream out;
	cout <<endl<< "测试：证书颁发" << endl;

	out.open("Alice_Cert.txt", ios::out);
	if (!out.is_open()) {
		cout << "Alice_Cert.txt打开失败" << endl;
		return -1;
	}
	out << Cert_Alice << endl;
	cout << "证书已生成至Alice_Cert.txt" << endl;
	out.close();

	out.open("Alice_PerKey.txt", ios::out);
	if (!out.is_open()) {
		cout << "Alice_PerKey.txt打开失败" << endl;
		return -1;
	}
	out << "p:" << p << endl;
	out << "q:" << q << endl;
	out << "a:" << a << endl;
	cout << "私钥已生成至Alice_PerKey.txt" << endl;
	out.close();

	/*************************************************************************/
	/*                             证书验证                                  */
	/*************************************************************************/

	cout << endl << "测试：证书验证" << endl;


	bool ver=rsa_TA.Cert_Verify(rsa_Alice.ID, rsa_Alice.n, rsa_Alice.b,Cert_Alice);
	cout << "证书验证结果为：" << (ver ? "true" : "false") << endl;

	in.open("Alice_Cert.txt", ios::in);
	if (!in.is_open()) {
		cout << "Alice_Cert.txt打开失败" << endl;
		return -1;
	}
	in >> Cert_Alice;//直接由大整数输入id
	in.close();

	ver = rsa_TA.Cert_Verify(rsa_Alice.ID, rsa_Alice.n, rsa_Alice.b, Cert_Alice);
	cout << "从Alice_Cert.txt读取的证书验证结果为：" << (ver ? "true" : "false") << endl;
	ver = rsa_TA.Cert_Verify(rsa_Alice.ID, rsa_Alice.n, rsa_Alice.b, Cert_Alice>>1);
	cout << "错误检测-证书验证结果为：" << (ver ? "true" : "false") << endl;


	return 0;
}