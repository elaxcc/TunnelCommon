#pragma once

namespace TunnelCommon
{

class RsaCrypting
{
public:
	enum Error
	{
		Errror_no = 0,
		Error_BadInternalKeys = -1,
		Error_BadExtarnalKeys = -2,
		Error_InternalCrypting = -3,
		Error_ExternalCrypting = -4,
		Error_GeneratingInternalKeys = -5,
		Error_GeneratingExternalKeys = -6
	};

	RsaCrypting();
	~RsaCrypting();

	void GenerateInternalKeys();
	
	const std::vector<char>& GetInternalPublicKey() const { return public_key_; }
	const std::vector<char>& GetInternalPrivateKey() const { return private_key_; }

	int EncryptByInternalRSA(const std::vector<char>& in_data, std::vector<char>& out_data) const;
	int DecryptByInternalRSA(const std::vector<char>& in_data, std::vector<char>& out_data) const;

	int EncryptByExternalRSA(const std::vector<char>& in_data, std::vector<char>& out_data) const;

	void RSA_FromPublicKey(const std::vector<char>& public_key);
	void RSA_FromPublicKey(char *public_key, int public_key_length);

private:
	std::vector<char> public_key_;
	std::vector<char> private_key_;

	RSA *rsa_internal_;
	RSA *rsa_external_;
};

} // TunnelCommon
