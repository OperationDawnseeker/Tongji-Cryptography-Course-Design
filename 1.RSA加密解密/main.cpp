#include<iostream>
#include<NTL/ZZ.h>
#include<fstream>
#include"RSA.h"
#include<bitset>

using namespace std;
using namespace NTL;
/* ʵ��RSA���ܺͽ����㷨 */

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
	ofstream en, de;

	ZZ x = ZZ(0);
	ZZ y, z;

	char ch;

	in.open("message.txt", ios::in | ios::binary);
	if (!in.is_open()) {
		cout << "message.txt��ʧ��" << endl;
		return -1;
	}
	while ((ch = in.get()) != EOF)
	{
		int a = unsigned char(ch);
		x = x * 1000 + a;
	}
	
	x = x % rsa.n;//��֤x��Zn

	rsa.Encrypt(x, y);
	rsa.Decrypt(y, z);

	/*��������������������������������������������������������������������������������������������*/
	en.open("encrypt.txt", ios::out | ios::binary);
	if (!en.is_open()) {
		cout << "encrypt.txt��ʧ��" << endl;
		in.close();
		return -1;
	}
	de.open("decrypt.txt", ios::out | ios::binary);
	if (!de.is_open()) {
		cout << "decrypt.txt��ʧ��" << endl;
		in.close();
		en.close();
		return -1;
	}

	string output = "";
	en << y;
	/* ���ܵ��ı�Ϊ��������ʽ��ת��Ϊ�ַ���������룬���������һ������ */
	cout << "���ܽ����д��encrypt.txt" << endl;

	output = "";
	while (z % 1000 != 0) {
		ch = (char)(z % 1000);
		output.insert(output.begin(), ch);
		z /= 1000;
	}
	de << output;
	cout << "���ܽ����д��decrypt.txt" << endl;

	output = "";

	in.close();
	en.close();
	de.close();

	/*��������������������������������������������������������������������������������������������*/
	/* �ü����ı����Խ��� */
	in.open("encrypt.txt", ios::in );
	de.open("decrypt_2.txt", ios::out );//| ios::binary
	ZZ e,d;
	in >> e;
	rsa.Decrypt(e, d);
	while (d % 1000 != 0) {
		ch = (char)(d % 1000);
		output.insert(output.begin(), ch);
		d /= 1000;
	}
	de << output;
	cout << "��֤��encrypt.txt�Ľ��ܽ����д��decrypt_2.txt" << endl;

	in.close();
	de.close();
	return 0;
}