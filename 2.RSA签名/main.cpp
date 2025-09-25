#include<iostream>
#include<NTL/ZZ.h>
#include<fstream>
#include"RSA.h"
#include<bitset>

using namespace std;
using namespace NTL;
/* ʵ��RSAǩ���㷨 */


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

	/*��������������������������������������������������������������������������������������������*/

	RSA rsa(len);

	ifstream in;
	ofstream out;

	string x="";
	ZZ sig;

	char ch;
	int i = 0;
	in.open("message.txt", ios::in | ios::binary);
	if (!in.is_open()) {
		cout << "message.txt��ʧ��" << endl;
		return -1;
	}
	
	while ((ch = in.get()) != EOF)	{
		x.push_back(ch);
	}

	/*��������������������������������������������������������������������������������������������*/

	/* RSAǩ�� */
	rsa.Sign(x, sig);

	/* RSAǩ����֤ */
	bool ver= rsa.Verify(x,sig);
	bool ver2 = rsa.Verify(x, sig + 5);//��֤ʧ��

	/*��������������������������������������������������������������������������������������������*/
	out.open("sign.txt", ios::out | ios::binary);
	if (!out.is_open()) {
		cout << "sign.txt��ʧ��" << endl;
		in.close();
		return -1;
	}

	string output = "";
	out << sig;
	/* ���ܵ��ı�Ϊ��������ʽ��ת��Ϊ�ַ���������룬���������һ������ */
	cout << "rsaǩ����д��sign.txt" << endl;
	cout << "rsaǩ����֤���Ϊ��" << (ver ? "true" : "false") << endl;
	cout << "����ǩ����֤���Ϊ��" << (ver2 ? "true" : "false") << endl;//����ǩ��Ϊ��Чǩ������ֵ��+5������
	in.close();
	out.close();

	/*��������������������������������������������������������������������������������������������*/
	/* ��ǩ���ı����Խ��� */
	in.open("sig.txt", ios::in);
	in >> sig;
	ver=rsa.Verify(x, sig);
	ver2 = rsa.Verify(x, sig + 5);
	cout << "��֤����sign.txt��message.txt����֤���Ϊ��" << (ver ? "true" : "false") << endl;

	in.close();

	return 0;
}