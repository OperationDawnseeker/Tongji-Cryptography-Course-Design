#include<iostream>
#include<fstream>
#include"Library.h"
#include"User.h"
using namespace std;
using namespace NTL;
//实现一个可公开查询的证书库。该证书库存储了该PKI系统的所有证书。

const int keylen = 512;//都采用默认512bit

CERTLIB certlib(keylen);//证书库

int WriteFile(const ZZ&Cert,const string &filename,const string &info) {
	ofstream out;
	out.open(filename, ios::out);
	if (!out.is_open()) {
		cout << filename<<"打开失败" << endl;
		return -1;
	}
	out << Cert << endl;
	cout << info<<"已生成至"<<filename << endl;
	out.close();
	return 0;
}

class CA {
public:
	RSA CAROOT;
	RSA CA1;
	RSA CA2;
	void Init()
	{
		CAROOT.ID = CAROOT_ID;
		CA1.ID = CA1_ID;
		CA2.ID = CA2_ID;
		//CA CA1 CA2的证书加入证书库
		ZZ tmp;
		tmp = CAROOT.Certificate(CAROOT.ID, CAROOT.n, CAROOT.b);//根CA的证书由自己签名，自己给自己颁发。
		certlib.addtolib(tmp);

		tmp = CAROOT.Certificate(CA1.ID, CA1.n, CA1.b);//根CA下有2个下级CA（CA1,CA2），它们的证书由根CA签名和颁发。
		certlib.addtolib(tmp);

		tmp = CAROOT.Certificate(CA2.ID, CA2.n, CA2.b);//根CA下有2个下级CA（CA1,CA2），它们的证书由根CA签名和颁发。
		certlib.addtolib(tmp);

		cout << "CA初始化完毕" << endl;
	}
};



int main()
{
	/********************************************
		证书库初始化
	*********************************************/

	CA _CA;
	_CA.Init();
	cout << endl;
	/********************************************
					实例检测
	*********************************************/
	cout << "实现该证书系统的一个使用例子:" << endl;
	cout<< endl;

	/*************************
					1
	**************************/

	cout << "Alice向CA1或CA2申请证书（此处假定为CA1）" << endl;
	_Alice A;
	ZZ Alice_Cert=A.ApplyCertficate(_CA.CA1,certlib);
	WriteFile(Alice_Cert, "Alice_Cert.txt", "证书");
	cout << endl;

	/***************************
					2
	****************************/
	cout << "Bob向CA1或CA2申请证书（此处假定为CA2）" << endl;
	_Bob B;
	ZZ Bob_Cert = B.ApplyCertficate(_CA.CA2,certlib);
	WriteFile(Bob_Cert, "Bob_Cert.txt", "证书");
	cout << endl;

	/***************************
					3
	****************************/
	cout << "Eve向CA1或CA2申请证书（此处假定为CA1）" << endl;
	_Eve E;
	ZZ Eve_Cert = E.ApplyCertficate(_CA.CA1,certlib);
	//生成证书
	WriteFile(Eve_Cert, "Eve_Cert.txt", "证书");
	cout << endl;

	/***************************
					4
	****************************/
	cout << "Alice向Bob发送消息和该消息的签名" << endl;
	string tmp1 = "Alice_message.txt";
	string tmp2 = "Alice_sig.txt";
	ZZ Alice_sig=A.SignMessage(tmp1);
	WriteFile(Alice_sig, tmp2, "Alice的签名");
	cout << endl;

	/***************************
					5
	****************************/
	cout << "Bob在证书库中查询Alice的证书" << endl;
	vector<ZZ>route = B.CheckCertficate(Alice_ID, certlib);
	WriteFile(route[0], "Alice_Cert_CAroot.txt", "证书链-根CA ");
	WriteFile(route[1], "Alice_Cert_CA1.txt", "证书链-CA1 ");
	WriteFile(route[2], "Alice_Cert_User.txt", "证书链-用户 ");
	cout << endl;


	/***************************
					6
	****************************/
	cout << "Bob验证Alice的证书路径是否正确" << endl;
	ZZ n, b;
	if(B.VerifyCertRoute(_CA.CAROOT, _CA.CA1, _CA.CA2, route,n,b)){
		B.VerifySig(tmp1, tmp2,n,b);
	}

	cout << endl;
	return 0;
}