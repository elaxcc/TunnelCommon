#pragma once

namespace TunnelCommon
{

class Md5_Hash
{
public:
	Md5_Hash();
	~Md5_Hash();

	void Init();
	void Update(const std::vector<char>& data);
	void Update(char *data, int data_len);
	void Final();
	void Clean();

	const std::vector<char>& GetHash() const { return hash_; };

private:
	EVP_MD_CTX mdctx_;
	const EVP_MD * md_;
	std::vector<char> hash_;
};

///////////////////////////////////////////////////////////////////////////

class CRC32_hash
{
public:
	CRC32_hash();
	~CRC32_hash();

	void Update(const std::vector<char>& data);
	void Update(char *data, int data_len);
	void Final();
	void Clean();

	boost::uint32_t GetHash() const { return hash_; };

private:
	boost::uint32_t hash_;
};

} // namespace TunnelCommon
