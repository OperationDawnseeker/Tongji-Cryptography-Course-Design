#include<iostream>
#include<fstream>
#include"Library.h"
#include"User.h"
using namespace std;
using namespace NTL;
//ʵ��һ���ɹ�����ѯ��֤��⡣��֤���洢�˸�PKIϵͳ������֤�顣

const int keylen = 512;//������Ĭ��512bit

CERTLIB certlib(keylen);//֤���

int WriteFile(const ZZ&Cert,const string &filename,const string &info) {
	ofstream out;
	out.open(filename, ios::out);
	if (!out.is_open()) {
		cout << filename<<"��ʧ��" << endl;
		return -1;
	}
	out << Cert << endl;
	cout << info<<"��������"<<filename << endl;
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
		//CA CA1 CA2��֤�����֤���
		ZZ tmp;
		tmp = CAROOT.Certificate(CAROOT.ID, CAROOT.n, CAROOT.b);//��CA��֤�����Լ�ǩ�����Լ����Լ��䷢��
		certlib.addtolib(tmp);

		tmp = CAROOT.Certificate(CA1.ID, CA1.n, CA1.b);//��CA����2���¼�CA��CA1,CA2�������ǵ�֤���ɸ�CAǩ���Ͱ䷢��
		certlib.addtolib(tmp);

		tmp = CAROOT.Certificate(CA2.ID, CA2.n, CA2.b);//��CA����2���¼�CA��CA1,CA2�������ǵ�֤���ɸ�CAǩ���Ͱ䷢��
		certlib.addtolib(tmp);

		cout << "CA��ʼ�����" << endl;
	}
};



int main()
{
	/********************************************
		֤����ʼ��
	*********************************************/

	CA _CA;
	_CA.Init();
	cout << endl;
	/********************************************
					ʵ�����
	*********************************************/
	cout << "ʵ�ָ�֤��ϵͳ��һ��ʹ������:" << endl;
	cout<< endl;

	/*************************
					1
	**************************/

	cout << "Alice��CA1��CA2����֤�飨�˴��ٶ�ΪCA1��" << endl;
	_Alice A;
	ZZ Alice_Cert=A.ApplyCertficate(_CA.CA1,certlib);
	WriteFile(Alice_Cert, "Alice_Cert.txt", "֤��");
	cout << endl;

	/***************************
					2
	****************************/
	cout << "Bob��CA1��CA2����֤�飨�˴��ٶ�ΪCA2��" << endl;
	_Bob B;
	ZZ Bob_Cert = B.ApplyCertficate(_CA.CA2,certlib);
	WriteFile(Bob_Cert, "Bob_Cert.txt", "֤��");
	cout << endl;

	/***************************
					3
	****************************/
	cout << "Eve��CA1��CA2����֤�飨�˴��ٶ�ΪCA1��" << endl;
	_Eve E;
	ZZ Eve_Cert = E.ApplyCertficate(_CA.CA1,certlib);
	//����֤��
	WriteFile(Eve_Cert, "Eve_Cert.txt", "֤��");
	cout << endl;

	/***************************
					4
	****************************/
	cout << "Alice��Bob������Ϣ�͸���Ϣ��ǩ��" << endl;
	string tmp1 = "Alice_message.txt";
	string tmp2 = "Alice_sig.txt";
	ZZ Alice_sig=A.SignMessage(tmp1);
	WriteFile(Alice_sig, tmp2, "Alice��ǩ��");
	cout << endl;

	/***************************
					5
	****************************/
	cout << "Bob��֤����в�ѯAlice��֤��" << endl;
	vector<ZZ>route = B.CheckCertficate(Alice_ID, certlib);
	WriteFile(route[0], "Alice_Cert_CAroot.txt", "֤����-��CA ");
	WriteFile(route[1], "Alice_Cert_CA1.txt", "֤����-CA1 ");
	WriteFile(route[2], "Alice_Cert_User.txt", "֤����-�û� ");
	cout << endl;


	/***************************
					6
	****************************/
	cout << "Bob��֤Alice��֤��·���Ƿ���ȷ" << endl;
	ZZ n, b;
	if(B.VerifyCertRoute(_CA.CAROOT, _CA.CA1, _CA.CA2, route,n,b)){
		B.VerifySig(tmp1, tmp2,n,b);
	}

	cout << endl;
	return 0;
}