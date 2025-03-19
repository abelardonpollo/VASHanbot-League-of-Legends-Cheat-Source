
#include "softxlic.h"
#include "miniGmp.h"

#ifndef DEVELOPER	
CSoftLicTool slt;
CSoftLicTool* CSoftLicTool::pThis = NULL;

typedef int(__stdcall *PMessageBoxTimeoutA)(IN HWND hWnd, IN LPCSTR lpText, IN LPCSTR lpCaption, IN UINT uType, IN WORD wLanguageId, IN DWORD dwMilliseconds);


const BYTE CSoftLicTool::DATA_B642BIN[128] = {
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xE0,0xF0,0xFF,0xFF,0xF1,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xE0,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x3E,0xFF,0xF2,0xFF,0x3F,
	0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0xFF,0xFF,0xFF,0x00,0xFF,0xFF,
	0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
	0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
	0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0xFF,0xFF,0xFF,0xFF,0xFF
};

void CSoftLicTool::MsgBox(string astr, string title,int waittime)
{
	static PMessageBoxTimeoutA MsgBoxTimeoutA = NULL;
	if (!MsgBoxTimeoutA)
	{
		HMODULE hUser32 = GetModuleHandleA(("user32.dll"));
		if (hUser32)
		{
			MsgBoxTimeoutA = (PMessageBoxTimeoutA)GetProcAddress(hUser32, ("MessageBoxTimeoutA"));
		}
	}
	if (MsgBoxTimeoutA)
		MsgBoxTimeoutA(NULL, astr.c_str(), title.c_str(), MB_ICONASTERISK, 0, waittime);
	else
		MessageBoxA(NULL, astr.c_str(), title.c_str(), MB_ICONASTERISK);
}

CSoftLicTool::CSoftLicTool() :
	CacheAPI(TRUE)
	, g_rsaPubKey("010001")
	, g_rsaMods("")
	, configFilePath{0}
	, g_softhead{0}
{
	pThis = this;
	make_crc32table();
	
}

CSoftLicTool::~CSoftLicTool()
{
}
//回调函数定义
int WINAPI CSoftLicTool::kscmdCallBack(const char * pread, char * pwrite, int CallBackType)
{
	string readstr = pread;
	string writestr = "";
	string mytag;
	switch (CallBackType)
	{
	case 1:   // 调用ks_cmd(set, )时的回调
			  /*
			  你可以在这做任何事
			  比如你在调用ks_cmd("set","<softcode>1000001</softcode>") 时
			  可以写成
			  cc=自定义加密("<softcode>1000001</softcode>")
			  ks_cmd("set",cc)
			  然后这里调用写成
			  writestr=自定义解密(readstr）
			  memcpy(pwrite,writestr.c_str(),writestr.size());
			  =====================================================================================
			  不处理读内容的话，请不要往"写地址"里写东西，除非你知道你想做什么
			  =========================================================
			  还可以做其它很多事，自己发挥
			  */
		//pThis->MsgBox("本信息框是在softxlic.cpp文件 kscmdCallBack回调函数中弹出\n\r你刚才调用了一条ks_cmd(set,)命令，命令的第二个参数是：" + readstr, "开发学习模式流程提醒");
		break;
	case 2:    //调用ks_cmd(check,)时第一阶段的回调
			   /*
			   你可以在这做任何事
			   比如你在调用ks_cmd("check","<advapi>v_myapi,1</advapi>") 时
			   可以写成
			   cc=自定义加密("<advapi>v_myapi,1</advapi>")
			   ks_cmd("check",cc)
			   然后这里调用写成
			   writestr=自定义解密(readstr）
			   memcpy(pwrite,writestr.c_str(),writestr.size());
			   =====================================================================================
			   不处理读内容的话，请不要往"写地址"里写东西，除非你知道你想做什么
			   =========================================================
			   还可以做其它很多事，自己发挥，比如定义一下程序运行的必要数据
			   比如你有一个变量abc本来正常值是 abc="F1ED1280"
			   abc="F000001"  调用ks_cmd前把值改成错误的
			   ks_cmd("check","******")
			   然后在回调里把a值改为正常值 abc="F1ED1280"
			   */
		//pThis->MsgBox("本信息框是在softxlic.cpp文件 kscmdCallBack回调函数中弹出\n\r你刚才调用了一条ks_cmd(check,)命令，命令的第二个参数是：" + readstr, "开发学习模式流程提醒");
		break;
	case 9:   //IPC进程通讯回调
			  /*
			  * IPC客户端可发送自定义的命令串，ipc_cmd("ipc_check","mycmd:123123123")
			  * 第一个参数必须是ipc_check
			  * 第二个参数是你自己的数据，为了方便区分，自己的数据最好加上一个头信息，例如ipc_cmd("ipc_check","mycmd:借本书给我")
			  * 如果你往writestr里写了东西，IPC服务端不会再去处理pread，而是直接将你写入的数据返回给IPC客户端
			  */
		mytag = ("mycmd:");
		if (readstr.substr(0, mytag.size()) == mytag)
		{
			//开始处理你自己的信息
			writestr = ("你发送过来的文本") + readstr.substr(mytag.size()) + (",我收到了，这是我给你的返回信息");
		}

		if (writestr != "")
			memcpy(pwrite, writestr.c_str(), writestr.size());
		break;
	default:
		break;
	}
	return 0;
}

void CSoftLicTool::myExitProcess()
{
	ks_cmd("exit", "");
	__fastfail(0);
}

string  CSoftLicTool::RSADecode(string v_data64, string v_Pubkey16, string v_Mod16)
{

	cCrypt* rsa = new cCrypt(v_Mod16.c_str(), v_Pubkey16.c_str());
	char outbuf[1024] = { 0 };
	rsa->rsa_decrypt(v_data64.c_str(), (int)v_data64.size(), outbuf);
	delete rsa;
	return outbuf;
}

/************************************************************************/
//自定义的解密函数,需要跟网站后台对应
/************************************************************************/
string CSoftLicTool::__myDecrypt(string&inData)
{
	int iRCKey = (int)inData.find(",");
	if (iRCKey>0) {
		string retRC4enKey = inData.substr(0, iRCKey);  //取出","号前的base64编码的RSA加密的RC4KEY	
		string RetEnData = inData.substr(iRCKey + 1);  //取出","后的RC4加密的数据
													   //纯静态库不需要带CBigInt.h和CBigInt.cpp,可把RSADecode的声明和定义删掉可以用 
													   //	然后替换下边一行的RSADecode为RSA_Decode
		string RC4Key = RSADecode(retRC4enKey, g_rsaPubKey, g_rsaMods);	//再rsa解密	解密结果存放到RCKey中
																		//====================================================================	
		unsigned char * buf = (unsigned char*)malloc(RetEnData.size());
		int deLen = BASE64_Decode(RetEnData, buf);
		*(buf + deLen) = '\0';
		RC4(RC4Key, buf, deLen);

		inData = (char *)buf;
		free(buf);
	}
	return inData;
}

/******格式化数据**********************************************************/
string CSoftLicTool::FD_(string &ioData)
{
	size_t pos = (int)ioData.find(g_softhead);
	if (pos != string::npos) {//发现加密标识头
		ioData = ioData.substr(pos + strlen(g_softhead));
		string data_s = __myDecrypt(ioData);  //自定义解密
		unsigned char* buf = (unsigned char*)malloc(data_s.size());
		int dlen = BASE64_Decode(data_s, buf); //必须做base64解码，data_s 结果就是以<xml>开头的一个xml格式串
		*(buf + dlen) = '\0';
		ioData = (char *)buf;
		free(buf);
	}
	else {
		if (ioData.find("<xml>") != 0) { //理论上不会运行到这里
			ioData = ("<xml><state>140</state><message>DLL内部错误，返回的数据异常") + ioData + "</message></xml>";
		}
	}
	replace_all(ioData, "<br />", "");
	return ioData;
}

/******提取XML中的值**********************************************************/
string CSoftLicTool::GD_(const string key, const string data, string defstr)
{
	string result = "";
	string stag = "<" + key + ">";
	string etag = "</" + key + ">";

	size_t spos = data.find(stag);
	if (spos != string::npos)
	{
		size_t epos = data.find(etag);  //0123xx678
		if (epos != string::npos &&  epos> spos)
		{
			result = data.substr(spos + stag.size(), epos - spos - stag.size());
		}
	}
	if (result == "")result = defstr;
	return result;
}

/************************************************************************/
//chkPass功能：对ks_cmd的check命令的基本验证的一个包装函数，里边的效验方法可以自己添加或修改
//参数connect：为0时自动判断是否连接服务器，为1时强制连接服务器
/************************************************************************/
string CSoftLicTool::chkPass(int connect)
{
	int randomstr = rand_(100000000, 200000000);
	char buf[128] = { 0 };
	sprintf(buf, ("<connect>%d</connect><randomstr>%d</randomstr>"), connect, randomstr);
	string sData = ks_cmd("check", buf);

	FD_(sData);
	if (GD_("state", sData) != "100") {//验证失败
		string errinfo = GD_("message", sData);
		errinfo += "\r\n" + GD_("webdata", sData);
		//MessageBoxA(0, errinfo.c_str(), "验证失败", MB_OK);
		myExitProcess();
	}
	else {
		//验证成功，要对数据读取和安全效验了
		string Srandomstr = GD_(("randomstr"), sData);//服务端返回的randomstr
													//这里只是做简单的等于比对，更多效验请充分发挥你的脑洞（在例子里写出来就没有什么安全性可言）
		if (randomstr != atoi(Srandomstr.c_str())) 
		{
			myExitProcess();
		}
	}
	return sData;
}
/************************************************************************/
//advapi功能：对ks_cmd的check命令取高级API函数的一个包装函数
//参数一：advapi的接口名和参数,例如 'v_getb,100,200'
//参数二：当设置缓存高级API时，本次连接是否释放当前API缓存，从服务端从新获取
//参数三：出错时是否弹出出错信息
/************************************************************************/
string CSoftLicTool::advapi(string advapicmd, bool freecache, bool msgbox)
{
	string sResult;

	unsigned int c32;
	if (CacheAPI)
	{
		c32 = crc32((char*)advapicmd.c_str(), (int)advapicmd.size());
		if (freecache)
			CacheTable.erase(c32);
		else
		{
			map<unsigned int, string>::iterator iter = CacheTable.find(c32);
			if (iter != CacheTable.end())
				return iter->second;
		}
	}

	int randomstr = rand_(100000000, 200000000);
	char buf[1024] = { 0 };
	sprintf(buf, ("<advapi>%s</advapi><randomstr>%d</randomstr>"), advapicmd.c_str(), randomstr);
	string sData = ks_cmd("check", buf);

	FD_(sData);
	if (GD_("state", sData) != "100") {//验证失败
		sResult = GD_("message", sData);
		sResult += "\r\n" + GD_("webdata", sData);
		if (msgbox) {
			//MsgBox(sResult, "验证失败");
		}
	}
	else {
		//验证成功，要对数据读取和安全效验了
		string Srandomstr = GD_("randomstr", sData);//服务端返回的randomstr
													//这里只是做简单的等于比对，更多效验请充分发挥你的脑洞（在例子里写出来就没有什么安全性可言）
		if (randomstr != atoi(Srandomstr.c_str())) {
			myExitProcess();
		}
		sResult = GD_("advapi", sData);
		if (CacheAPI)
			CacheTable[c32] = sResult;
	}
	return sResult;
}

/************************************************************************/
//扣点函数，调用advapi接口实现扣点功能。成功返回剩余的点数。失败返回-1
/************************************************************************/
int CSoftLicTool::kpoints(int v_points, string&v_errinfo)
{
	char buf[32] = { 0 };
	sprintf(buf, "v_points,%d", v_points);
	string tresult = advapi(buf, true);
	int c = atoi(tresult.c_str());
	if (c == 0) {   //返回值不是整数或为0就说明扣点失败
		v_errinfo = tresult;
		c = -1;
	}
	else
		v_errinfo = "扣点成功";
	return c;
}

int CSoftLicTool::rand_(int v_min, int v_max)
{
	int rNum = 0;
	srand(GetTickCount());
	for (int i = 0; i < 31; i++)
		rNum |= (rand() & 1) << i;
	return v_min + rNum % (v_max - v_min + 1);
}

void CSoftLicTool::BASE64ToHex(const string inputStr, string&outputStr)
{
	int i, j;
	BYTE b[4];
	char chHex[] = "0123456789ABCDEF";
	int inputCount, outlen, padlen;

	padlen = 0;
	inputCount = (int)(inputStr.size());
	if (inputStr[inputCount - 1] == '=')
		padlen++;
	if (inputStr[inputCount - 2] == '=')
		padlen++;

	outlen = inputCount / 4 * 3 - padlen;

	j = 0;
	for (i = 0; i < inputCount; i += 4)
	{
		b[0] = DATA_B642BIN[(char)inputStr[i]];
		b[1] = DATA_B642BIN[(char)inputStr[i + 1]];
		b[2] = DATA_B642BIN[(char)inputStr[i + 2]];
		b[3] = DATA_B642BIN[(char)inputStr[i + 3]];

		outputStr += chHex[(b[0] >> 2)];
		outputStr += chHex[((b[0] & 3) << 2) | b[1] >> 4];
		j++;
		if (j >= outlen)
			break;

		outputStr += chHex[(b[1] & 15)];
		outputStr += chHex[(b[2] >> 2)];
		j++;
		if (j >= outlen)
			break;

		outputStr += chHex[((b[2] & 3) << 2) | b[3] >> 4];
		outputStr += chHex[(b[3] & 15)];
		j++;
		if (j >= outlen)
			break;
	}

}
int CSoftLicTool::BASE64_Decode(string inputStr, unsigned char*outputBuffer)
{
	INT i, j;
	BYTE b[4];
	int inputCount, outlen, padlen;

	padlen = 0;
	inputCount = (int)inputStr.size();
	if (inputStr[inputCount - 1] == '=')
		padlen++;
	if (inputStr[inputCount - 2] == '=')
		padlen++;
	// 00123456 00781234 00567812 00345678 00123456 0078xxxx 00xxxxxx,00xxxxxx
	outlen = (inputCount >> 2) * 3 - padlen;

	j = 0;
	for (i = 0; i < inputCount; i += 4)
	{
		b[0] = DATA_B642BIN[(BYTE)inputStr[i]];
		b[1] = DATA_B642BIN[(BYTE)inputStr[i + 1]];
		b[2] = DATA_B642BIN[(BYTE)inputStr[i + 2]];
		b[3] = DATA_B642BIN[(BYTE)inputStr[i + 3]];

		*outputBuffer++ = (b[0] << 2) | (b[1] >> 4);
		j++;
		if (j >= outlen)
			break;
		*outputBuffer++ = (b[1] << 4) | (b[2] >> 2);
		j++;
		if (j >= outlen)
			break;
		*outputBuffer++ = (b[2] << 6) | b[3];
	}
	return outlen;
}
void CSoftLicTool::RC4(string key, unsigned char *Data, int data_length)
{
	unsigned char box[256];
	unsigned char pwd[256];
	int i, j, k, a;
	unsigned char tmp = 0;

	int pwd_length = (int)key.size();
	for (i = 0; i < 256; i++)
	{
		pwd[i] = (unsigned char)key[i % pwd_length];

		box[i] = i;
	}
	j = 0;
	for (i = 0; i < 256; i++)
	{
		j = (j + box[i] + pwd[i]) % 256;
		tmp = box[i];
		box[i] = box[j];
		box[j] = tmp;
	}

	a = 0;
	j = 0;

	for (i = 0; i < data_length; i++)
	{
		a = (a + 1) % 256;
		j = (j + box[a]) % 256;
		tmp = box[a];
		box[a] = box[j];
		box[j] = tmp;
		k = box[((box[a] + box[j]) % 256)];
		Data[i] ^= k;
	}

}

void CSoftLicTool::r_ini(const char* _key, char* rbuf, const char* _def)
{
	GetPrivateProfileStringA("config", _key, _def, rbuf, 1024, configFilePath);
}

void CSoftLicTool::w_ini(const char* _key, const char* _val)
{
	WritePrivateProfileStringA("config", _key, _val, configFilePath);
}


string CSoftLicTool::trim(string s)
{
	if (s.empty())return s;
	s.erase(0, s.find_first_not_of(" "));
	s.erase(s.find_last_not_of(" ") + 1);
	return s;
}

void CSoftLicTool::replace_all(string & s, string  t, string   w)
{
	size_t pos = s.find(t), t_size = t.size(), r_size = w.size();

	while (pos != string::npos) { // found   
		s.replace(pos, t_size, w);
		pos = s.find(t, pos + r_size);
	}
}

BOOL CSoftLicTool::IsFileExist(const string & csFile)
{
	DWORD dwAttrib = GetFileAttributesA(csFile.c_str());
	return 0xFFFFFFFF != dwAttrib && 0 == (dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}
void CSoftLicTool::make_crc32table()
{
	int i, j;
	for (i = 0; i < 256; i++)
	{
		for (j = 0, crc32table[i] = i; j < 8; j++)
		{
			crc32table[i] = (crc32table[i] >> 1) ^ ((crc32table[i] & 1) ? 0xEDB88320 : 0);
		}
	}
}

unsigned int CSoftLicTool::crc32(char* buff, int nLength)
{
	unsigned crc = 0xFFFFFFFF;
	for (int i = 0; i < nLength; i++)
		crc = (crc >> 8) ^ crc32table[(crc ^ buff[i]) & 0xff];
	return ~crc;
}

void CSoftLicTool::Edit(const char* _username, const char* _password2, const char* _password, const char* _bdinfo)
{

	char buf[512] = { 0 };
	sprintf(buf, ("<username>%s</username><password2>%s</password2><password>%s</password><bdinfo>%s</bdinfo>"), _username, _password2, _password, _bdinfo);
	string sData = ks_cmd("edit", buf);
	MsgBox(GD_("message", sData) + "\r\n" + GD_("webdata", sData), ("修改信息"));
}

void CSoftLicTool::EditK(const char* _keystr, const char* _bdinfo)
{

	char buf[512] = { 0 };
	sprintf(buf, ("<keystr>%s</keystr><bdinfo>%s</bdinfo>"), _keystr, _bdinfo);
	string sData = ks_cmd("edit", buf);
	MsgBox(GD_("message", sData) + "\r\n" + GD_("webdata", sData), ("修改信息"));
}

//HACK 注册帐号 
void CSoftLicTool::reguser(const char* _username, const char* _password2, const char* _password, const char* _bdinfo, const char* _tguser, const char* _keys)
{
	char buf[1024] = { 0 };
	sprintf(buf, ("<username>%s</username><password2>%s</password2><password>%s</password><bdinfo>%s</bdinfo><puser>%s</puser><czkey>%s</czkey>"),
		_username, _password2, _password, _bdinfo, _tguser, _keys);

	string sData = ks_cmd("reg", buf);
	MsgBox(GD_("message", sData) + "\r\n" + GD_("webdata", sData), ("注册"));

}

//HACK 帐号充值
void CSoftLicTool::cz(const char* _username, const char* _keys)
{
	char buf[1024] = { 0 };
	sprintf(buf, ("<username>%s</username><czkey>%s</czkey>"),
		_username, _keys);

	string sData = ks_cmd("cz", buf);
	MsgBox(GD_("message", sData) + "\r\n" + GD_("webdata", sData), "充值");
}


//HACK 解除帐号机器码绑定
void CSoftLicTool::Unbind(const char* _UsernameOrKeyStr, const char* _password, const char* _clientid)
{
	char buf[1024] = { 0 };
	sprintf(buf, ("<username>%s</username><password>%s</password><clientid>%s</clientid>"),
		_UsernameOrKeyStr, _password, _clientid);

	string sData = ks_cmd("unbind", buf);
	MsgBox(GD_("message", sData) + "\r\n" + GD_("webdata", sData), ("解绑机器码"));
}

//HACK 卡号机器码绑定
void CSoftLicTool::UnbindK(const char* KeyStr, const char* _clientid)
{
	char buf[1024] = { 0 };
	sprintf(buf, ("<keystr>%s</keystr><clientid>%s</clientid>"),
		KeyStr, _clientid);

	string sData = ks_cmd("unbind", buf);
	MsgBox(GD_("message", sData) + "\r\n" + GD_("webdata", sData), ("解绑机器码"));
}

//HACK 解除帐号或卡号机器码绑定
void CSoftLicTool::View(const char* _UsernameOrKeyStr)
{
	char buf[1024] = { 0 };
	sprintf(buf, ("<keyorusername>%s</keyorusername>"),
		_UsernameOrKeyStr);

	string sData = ks_cmd("search", buf);
	MsgBox(GD_("message", sData) + "\r\n" + GD_("webdata", sData), ("查 询"));
}

//HACK 下边专为MFC UNICODE工程准备
#if defined(__AFX_H__) && defined(_UNICODE)
CString str2Cstr(const char* str)
{
	int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	wchar_t *wstr = new wchar_t[len];
	memset(wstr, 0, len * sizeof(wchar_t));
	MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
	CString cstrDest = wstr;
	delete[] wstr;
	return cstrDest;
}


string CStr2str(const CString &cstrSrcW)
{
	int len = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)(LPCTSTR)cstrSrcW, -1, NULL, 0, NULL, NULL);
	char *str = new char[len];
	memset(str, 0, len);
	WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)(LPCTSTR)cstrSrcW, -1, str, len, NULL, NULL);
	string cstrDestA = str;
	delete[] str;

	return cstrDestA;
}
#endif
#endif