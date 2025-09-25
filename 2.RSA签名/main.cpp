#include<iostream>
#include<NTL/ZZ.h>
#include<fstream>
#include"RSA.h"
#include<bitset>

using namespace std;
using namespace NTL;
/* 实现RSA签名算法 */


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

	/*——————————————————————————————————————————————*/

	RSA rsa(len);

	ifstream in;
	ofstream out;

	string x="";
	ZZ sig;

	char ch;
	int i = 0;
	in.open("message.txt", ios::in | ios::binary);
	if (!in.is_open()) {
		cout << "message.txt打开失败" << endl;
		return -1;
	}
	
	while ((ch = in.get()) != EOF)	{
		x.push_back(ch);
	}

	/*——————————————————————————————————————————————*/

	/* RSA签名 */
	rsa.Sign(x, sig);

	/* RSA签名验证 */
	bool ver= rsa.Verify(x,sig);
	bool ver2 = rsa.Verify(x, sig + 5);//验证失败

	/*——————————————————————————————————————————————*/
	out.open("sign.txt", ios::out | ios::binary);
	if (!out.is_open()) {
		cout << "sign.txt打开失败" << endl;
		in.close();
		return -1;
	}

	string output = "";
	out << sig;
	/* 加密的文本为大整数形式，转化为字符会出现乱码，不方便最后一个测试 */
	cout << "rsa签名已写入sign.txt" << endl;
	cout << "rsa签名验证结果为：" << (ver ? "true" : "false") << endl;
	cout << "错误签名验证结果为：" << (ver2 ? "true" : "false") << endl;//错误签名为有效签名在数值上+5得来。
	in.close();
	out.close();

	/*——————————————————————————————————————————————*/
	/* 用签名文本测试解密 */
	in.open("sig.txt", ios::in);
	in >> sig;
	ver=rsa.Verify(x, sig);
	ver2 = rsa.Verify(x, sig + 5);
	cout << "验证：对sign.txt与message.txt的验证结果为：" << (ver ? "true" : "false") << endl;

	in.close();

	return 0;
}