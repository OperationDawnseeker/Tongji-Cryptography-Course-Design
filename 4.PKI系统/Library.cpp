//证书库
#include"Library.h"
#include"SHA.h"
#include"RSA.h"

vector<ZZ> CERTLIB::findroute(const ZZ& User_ID) {
	vector<ZZ> route;
	route.push_back(lib[0][NO_CERT]);//CAROOT 是第一个加入证书库的证书

	ZZ TA_ID;

	for (int i = 1; i < lib.size(); i++) {

		if (lib[i][NO_USERID] == User_ID) {

			TA_ID = lib[i][NO_TAID];

			for (int j = 1; j < lib.size(); j++) {

				if (lib[j][NO_USERID] == TA_ID && lib[j][NO_TAID] == lib[0][NO_USERID]) {//次级CA证书

					route.push_back(lib[j][NO_CERT]);
					break;
				}
			}

			route.push_back(lib[i][NO_CERT]);

			break;//默认每个id只会有一个证书，只会更新而不会重复
		}
	}
	return route;
}

void CERTLIB::addtolib(const ZZ& Cert) {
	vector<ZZ> tmp(3);
	tmp[NO_CERT]=(Cert);

	ZZ User_ID = power(ZZ(2), 1 + TAID_LEN + KEYLEN * 2 * 3);//flag||TAID||sig||ver ver=n||b
	User_ID = Cert / User_ID;
	//cout<<User_ID<<endl;
	tmp[NO_USERID] = (User_ID);

	ZZ TA_ID = power(ZZ(2), TAID_LEN );
	TA_ID = (Cert >> 1) % TA_ID;
	//cout<<TA_ID<<endl;
	tmp[NO_TAID] = (TA_ID);

	lib.push_back(tmp);
}
