#pragma once
typedef unsigned long mp_limb_t;
typedef struct 
{ 
	int _mp_alloc; 
	int _mp_size; 
	mp_limb_t* _mp_d; 
} __mpz_struct;
typedef __mpz_struct mpz_t[1];
void mpz_init(mpz_t);
int mpz_init_set_str(mpz_t, unsigned char *, int);
int mpz_set_str(mpz_t, unsigned char *, int);
int mpz_get_str(char *, const mpz_t);
int mpz_init_set_hexstr(mpz_t, const char *);
int mpz_set_hexstr(mpz_t, const char *);
int mpz_get_hexstr(char *, const mpz_t);
void mpz_powm(mpz_t, const mpz_t, const mpz_t, const mpz_t);
void mpz_clear(mpz_t);


class cCrypt
{
private:
	int my_mode;
	char m_padType;

	mpz_t m_gmpKey;
	mpz_t m_gmpMod;

	static const char * chHex;
	static const char * chBase64;
	static const unsigned char Base64Ch_2_AnsiCh[128];
	static const unsigned char HexCh_2_AnsiCh[128];

	int _remove_PKCS1_padding(char* _inBuf, int _inCount);
	int _add_PKCS1_padding(const char* _inBuf, int _inCount, char* outBuf);

public:
	int m_blockSize;  //能加密解密的字节数
	cCrypt(const char * _hex_mod, const char * _ekey = "010001");
	~cCrypt();
	static int base64_encode(char* _inBuf, int _inCount, char* _outBuf);
	static int base64_decode(const char* _inBuf, int _inCount, char* _outBuf);
	static int char_hex(const char* _inBuf, int _inCount, char* _outBuf);
	static int hex_char(const char* _Buf, char* _outBuf = NULL);

	//公钥或私钥解密  (数据是公钥加密的，用模和私钥解密。同理私钥加密的，用模和公钥解密)
	int rsa_decrypt(const char* _inBuf, int _inCount, char * outBuf, bool base64 = true);

	//公钥或私钥加密
	int rsa_encrypt(const char* _inBuf, int _inCount, char * outBuf, bool base64 = true);

};