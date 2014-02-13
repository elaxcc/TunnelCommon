#include "stdafx.h"

#include "Crypting.h"

namespace TunnelCommon
{

namespace
{

const unsigned long g_rsa_key_length = 2048; /* длина ключа в битах */

} // namespace

RsaCrypting::RsaCrypting()
	: rsa_internal_(NULL)
	, rsa_external_(NULL)
{
}

RsaCrypting::~RsaCrypting()
{
	public_key_.clear();
	private_key_.clear();

	if (rsa_internal_)
	{
		RSA_free(rsa_internal_);
	}

	if (rsa_external_)
	{
		RSA_free(rsa_external_);
	}
}

void genrsa_cb(int p, int n, void *arg)
{
	char c='*';

	if (p == 0) c='.';
	if (p == 1) c='+';
	if (p == 2) c='*';
	if (p == 3) c='\n';
	BIO_write((BIO *)arg,&c,1);
	(void)BIO_flush((BIO *)arg);
#ifdef LINT
	p=n;
#endif
}

int RsaCrypting::GenerateInternalKeys()
{
	if (rsa_internal_)
	{
		RSA_free(rsa_internal_);
	}

	public_key_.clear();
	private_key_.clear();

	rsa_internal_ = RSA_new();

	/* Генерируем ключи */
	BIGNUM *e = BN_new();
	BN_set_word(e, 65537);
	int res = RSA_generate_key_ex(rsa_internal_, g_rsa_key_length, e, NULL);
	if (res < 0)
	{
		return Error_GeneratingInternalKeys;
	}

	char *pri_key = NULL; // Private key
	char *pub_key = NULL; // Public key
	size_t pri_len; // Length of private key
	size_t pub_len; // Length of public key

	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(pri, rsa_internal_, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(pub, rsa_internal_);

	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);

	pri_key = new char [pri_len];
	pub_key = new char [pub_len];

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	public_key_.insert(public_key_.begin(), pub_key, pub_key + pub_len);
	private_key_.insert(private_key_.begin(), pri_key, pri_key + pri_len);

	delete pri;
	delete pub;
	delete [] pri_key;
	delete [] pub_key;
	BN_free(e);

	return Errror_no;
}

int RsaCrypting::RSA_FromPublicKey(const std::vector<char>& public_key)
{
	if (rsa_external_)
	{
		RSA_free(rsa_external_);
	}

	BIO *bio_pub = BIO_new(BIO_s_mem());
	int res = BIO_write(bio_pub, &public_key[0], public_key.size());
	if (res <= 0)
	{
		return Error_GeneratingExternalKeys;
	}

	rsa_external_ = RSA_new();
	rsa_external_ = PEM_read_bio_RSAPublicKey(bio_pub, &rsa_external_, NULL, NULL);

	return Errror_no;
}

int RsaCrypting::RSA_FromPublicKey(char *public_key, int public_key_length)
{
	if (rsa_external_)
	{
		RSA_free(rsa_external_);
	}

	BIO *bio_pub = BIO_new(BIO_s_mem());
	int res = BIO_write(bio_pub, public_key, public_key_length);
	if (res <= 0)
	{
		return Error_GeneratingExternalKeys;
	}

	rsa_external_ = RSA_new();
	rsa_external_ = PEM_read_bio_RSAPublicKey(bio_pub, &rsa_external_, NULL, NULL);

	return Errror_no;
}

int RsaCrypting::EncryptByInternalRSA(const std::vector<char>& in_data, std::vector<char>& out_data) const
{
	if (!rsa_internal_)
	{
		return Error_BadInternalKeys;
	}

	char *ptext, *ctext;

	// Определяем длину ключа
	int key_size = RSA_size(rsa_internal_);
	ctext = new char [key_size];
	// Шифруем
	RSA_public_encrypt(in_data.size(), (const unsigned char*) &in_data[0],
		(unsigned char*) ctext, rsa_internal_, RSA_PKCS1_PADDING);

	std::vector<char>::const_iterator in_data_iter = in_data.begin();
	int int_data_size = in_data.size();
	ptext = (char*) &in_data[0];
	while(int_data_size > 0)
	{
		int data_len_for_crypting = int_data_size < key_size - 11 ? int_data_size : key_size - 11;
		int out_len = RSA_public_encrypt(data_len_for_crypting, (unsigned char*) ptext,
			(unsigned char*) ctext, rsa_internal_, RSA_PKCS1_PADDING);
		out_data.insert(out_data.begin(), ctext, ctext + out_len);
		int_data_size -= data_len_for_crypting;
	}

	delete [] ctext;

	return Errror_no;
}

int RsaCrypting::DecryptByInternalRSA(const std::vector<char>& in_data, std::vector<char>& out_data) const
{
	if (!rsa_internal_)
	{
		return Error_BadInternalKeys;
	}

	char *ptext, *ctext;

	// Определяем длину ключа
	int key_size = RSA_size(rsa_internal_);
	ctext = new char [key_size];

	std::vector<char>::const_iterator in_data_iter = in_data.begin();
	int int_data_size = in_data.size();
	ptext = (char*) &in_data[0];
	while(int_data_size > 0)
	{
		int data_len_for_crypting = int_data_size < key_size ? int_data_size : key_size;
		int out_len = RSA_private_decrypt(data_len_for_crypting, (unsigned char*) ptext,
			(unsigned char*) ctext, rsa_internal_, RSA_PKCS1_PADDING);

			
		if (out_len < 0)
		{
			return Error_InternalCrypting;
		}

		out_data.insert(out_data.begin(), ctext, ctext + out_len);
		int_data_size -= data_len_for_crypting;
	}

	delete [] ctext;

	return Errror_no;
}

int RsaCrypting::EncryptByExternalRSA(const std::vector<char>& in_data, std::vector<char>& out_data) const
{
	if (!rsa_external_)
	{
		return Error_BadInternalKeys;
	}

	char *ptext, *ctext;

	// Определяем длину ключа
	int key_size = RSA_size(rsa_external_);
	ctext = new char [key_size];

	std::vector<char>::const_iterator in_data_iter = in_data.begin();
	int int_data_size = in_data.size();
	ptext = (char*) &in_data[0];
	while(int_data_size > 0)
	{
		int data_len_for_crypting = int_data_size < key_size ? int_data_size : key_size;
		int out_len = RSA_public_encrypt(data_len_for_crypting, (unsigned char*) ptext,
			(unsigned char*) ctext, rsa_external_, RSA_PKCS1_PADDING);

		if (out_len < 0)
		{
			return Error_ExternalCrypting;
		}

		out_data.insert(out_data.begin(), ctext, ctext + out_len);
		int_data_size -= data_len_for_crypting;
	}

	delete [] ctext;

	return Errror_no;
}

} // namespace TunnelCommon
