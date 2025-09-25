#include<iostream>
#include<NTL/ZZ.h>
#include<fstream>
#include"RSA.h"
#include"SHA.h"
#include<bitset>

using namespace std;
using namespace NTL;

/* ʵ��һ���򵥵�֤�鷽�� */
//����֤��䷢��Э��9.5����֤����֤��


int main()
{
	int len, sel;
	cout << "��ѡ��p��q�ı��س���1-512bit  2-1024bit" << endl;
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
		cout << "Alice_id.txt��ʧ��" << endl;
		return -1;
	}
	in >> rsa_Alice.ID;//ֱ���ɴ���������id
	in.close();

	in.open("TA_id.txt", ios::in);
	if (!in.is_open()) {
		cout << "TA_id.txt��ʧ��" << endl;
		return -1;
	}
	in >> rsa_TA.ID;//ֱ���ɴ���������id
	in.close();

	/*************************************************************************/
	/*                             ֤��䷢                                  */
	/*************************************************************************/
	ZZ Cert_Alice = rsa_TA.Certificate(rsa_Alice.ID, rsa_Alice.n, rsa_Alice.b);

	ZZ p, q, a; 
	rsa_Alice.printPerKey(p, q, a);

	ofstream out;
	cout <<endl<< "���ԣ�֤��䷢" << endl;

	out.open("Alice_Cert.txt", ios::out);
	if (!out.is_open()) {
		cout << "Alice_Cert.txt��ʧ��" << endl;
		return -1;
	}
	out << Cert_Alice << endl;
	cout << "֤����������Alice_Cert.txt" << endl;
	out.close();

	out.open("Alice_PerKey.txt", ios::out);
	if (!out.is_open()) {
		cout << "Alice_PerKey.txt��ʧ��" << endl;
		return -1;
	}
	out << "p:" << p << endl;
	out << "q:" << q << endl;
	out << "a:" << a << endl;
	cout << "˽Կ��������Alice_PerKey.txt" << endl;
	out.close();

	/*************************************************************************/
	/*                             ֤����֤                                  */
	/*************************************************************************/

	cout << endl << "���ԣ�֤����֤" << endl;


	bool ver=rsa_TA.Cert_Verify(rsa_Alice.ID, rsa_Alice.n, rsa_Alice.b,Cert_Alice);
	cout << "֤����֤���Ϊ��" << (ver ? "true" : "false") << endl;

	in.open("Alice_Cert.txt", ios::in);
	if (!in.is_open()) {
		cout << "Alice_Cert.txt��ʧ��" << endl;
		return -1;
	}
	in >> Cert_Alice;//ֱ���ɴ���������id
	in.close();

	ver = rsa_TA.Cert_Verify(rsa_Alice.ID, rsa_Alice.n, rsa_Alice.b, Cert_Alice);
	cout << "��Alice_Cert.txt��ȡ��֤����֤���Ϊ��" << (ver ? "true" : "false") << endl;
	ver = rsa_TA.Cert_Verify(rsa_Alice.ID, rsa_Alice.n, rsa_Alice.b, Cert_Alice>>1);
	cout << "������-֤����֤���Ϊ��" << (ver ? "true" : "false") << endl;


	return 0;
}