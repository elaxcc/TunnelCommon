#include "stdafx.h"

#include "Protocol.h"

namespace TunnelCommon
{

const std::string ProtocolParser::c_user_accept_packet_ = "Hello user!!!";

ProtocolParser::ProtocolParser()
	: got_data_len_(false)
	, got_data_(false)
	, got_crc_(false)
	, complete_(false)
	, got_rsa_key_(false)
	, got_login_data_(false)
{
	rsa_crypting_.GenerateInternalKeys();
}

ProtocolParser::~ProtocolParser()
{
	reset();
}

int ProtocolParser::parse_common(const std::vector<char>& data)
{
	buffer_.insert(buffer_.end(), data.begin(), data.end());

	if (complete_)
	{
		return Error_wait_packet;
	}

	if (!got_data_len_)
	{
		if (buffer_.size() < sizeof(boost::uint32_t))
		{
			return Error_wait_packet;
		}

		data_len_ = 0x000000FF & buffer_[0];
		data_len_ = data_len_ | (0x0000FF00 & (buffer_[1] << 8));
		data_len_ = data_len_ | (0x00FF0000 & (buffer_[2] << 16));
		data_len_ = data_len_ | (0xFF000000 & (buffer_[3] << 24));

		buffer_.erase(buffer_.begin(), buffer_.begin() + sizeof(data_len_));
		got_data_len_ = true;
	}

	if (!got_data_)
	{
		if (buffer_.size() < data_len_)
		{
			return Error_wait_packet;
		}

		data_.insert(data_.begin(), buffer_.begin(), buffer_.end());
		buffer_.erase(buffer_.begin(), buffer_.begin() + data_len_);
		got_data_ = true;

		crc_calc_.Update(data_);
	}

	if (!got_crc_)
	{
		if (buffer_.size() < sizeof(crc_))
		{
			return Error_wait_packet;
		}

		crc_ = 0x000000FF & buffer_[0];
		crc_ = crc_ | (0x0000FF00 & (buffer_[1] << 8));
		crc_ = crc_ | (0x00FF0000 & (buffer_[2] << 16));
		crc_ = crc_ | (0xFF000000 & (buffer_[3] << 24));

		got_crc_ = true;

		crc_calc_.Final();
		boost::uint32_t calculated_crc = crc_calc_.GetHash();

		if (calculated_crc == crc_)
		{
			complete_ = true;
			return Error_no;
		}
		else
		{
			flush_common();
			return Error_crc;
		}
	}

	return Error_no;
}

void ProtocolParser::flush_common()
{
	got_data_len_ = false;
	got_data_ = false;
	got_crc_ = false;
	complete_ = false;

	crc_calc_.Clean();
	data_.clear();
}

void ProtocolParser::reset()
{
	flush_common();

	buffer_.clear();
	login_.clear();
	passwd_hash_.clear();

	got_rsa_key_ = false;
	got_login_data_ = false;
}

int ProtocolParser::parse_rsa_key_packet()
{
	if (!complete_)
	{
		return Error_packet_not_complete;
	}

	// rsa public key length
	boost::uint32_t rsa_pub_kye_len;
	rsa_pub_kye_len = 0x000000FF & data_[0];
	rsa_pub_kye_len = rsa_pub_kye_len | (0x0000FF00 & (data_[1] << 8));
	rsa_pub_kye_len = rsa_pub_kye_len | (0x00FF0000 & (data_[2] << 16));
	rsa_pub_kye_len = rsa_pub_kye_len | (0xFF000000 & (data_[3] << 24));

	if (rsa_pub_kye_len + sizeof(rsa_pub_kye_len) > data_.size())
	{
		return Error_rsa_key_packet;
	}

	std::vector<char> external_public_key(data_);
	int res = rsa_crypting_.RSA_FromPublicKey(&data_[sizeof(rsa_pub_kye_len)], rsa_pub_kye_len);
	if (res == RsaCrypting::Errror_no)
	{
		got_rsa_key_ = true;
		return Error_no;
	}
	return Error_rsa_key_packet;
}

int ProtocolParser::parse_login_packet()
{
	if (!complete_)
	{
		return Error_packet_not_complete;
	}

	login_.clear();
	passwd_hash_.clear();
	got_login_data_ = false;

	// decoding data
	std::vector<char> decrypted_data;
	rsa_crypting_.DecryptByInternalRSA(data_, decrypted_data);

	boost::uint32_t processed_data = 0;

	// login length
	boost::uint32_t login_length;
	login_length = 0x000000FF & decrypted_data[0];
	login_length = login_length | (0x0000FF00 & (decrypted_data[1] << 8));
	login_length = login_length | (0x00FF0000 & (decrypted_data[2] << 16));
	login_length = login_length | (0xFF000000 & (decrypted_data[3] << 24));
	processed_data += sizeof(login_length);

	if (login_length + sizeof(login_length) >= data_.size())
	{
		return Error_parse_login_packet;
	}

	// login
	login_.insert(login_.begin(), decrypted_data[processed_data],
		decrypted_data[processed_data] + login_length);
	processed_data += login_length;

	// password length
	boost::uint32_t passwd_length;
	passwd_length = 0x000000FF & decrypted_data[processed_data];
	passwd_length = passwd_length | (0x0000FF00 & (decrypted_data[processed_data + 1] << 8));
	passwd_length = passwd_length | (0x00FF0000 & (decrypted_data[processed_data + 2] << 16));
	passwd_length = passwd_length | (0xFF000000 & (decrypted_data[processed_data + 3] << 24));
	processed_data += sizeof(passwd_length);

	if ((login_length + sizeof(login_length) + passwd_length  + sizeof(passwd_length)) > data_.size())
	{
		return Error_parse_login_packet;
	}

	// password
	passwd_hash_.insert(passwd_hash_.begin(), decrypted_data[processed_data],
		decrypted_data[processed_data] + passwd_length);

	// node name length
	boost::uint32_t node_name_length;
	node_name_length = 0x000000FF & decrypted_data[processed_data];
	node_name_length = node_name_length | (0x0000FF00 & (decrypted_data[processed_data + 1] << 8));
	node_name_length = node_name_length | (0x00FF0000 & (decrypted_data[processed_data + 2] << 16));
	node_name_length = node_name_length | (0xFF000000 & (decrypted_data[processed_data + 3] << 24));
	processed_data += sizeof(node_name_length);

	if ((login_length + sizeof(login_length) + 
		passwd_length  + sizeof(passwd_length) +
		node_name_length + sizeof(node_name_length)) > data_.size())
	{
		return Error_parse_login_packet;
	}

	if (node_name_length != 0)
	{
		node_name_.insert(0, decrypted_data[processed_data], + node_name_length);
	}

	got_login_data_ = true;

	return Error_no;
}

int ProtocolParser::parse_data_packet()
{
	return Error_no;
}

int ProtocolParser::prepare_packet(const std::vector<char>& data, std::vector<char>& out_packet) const
{
	// encrypting
	std::vector<char> encrypted_data;
	int encrypt_result = rsa_crypting_.EncryptByInternalRSA(data, encrypted_data);
	if (encrypt_result != TunnelCommon::RsaCrypting::Errror_no)
	{
		return Error_prepare_packet;
	}

	// encrypted data length
	unsigned encrypted_data_len = encrypted_data.size();
	for (int i = 0; i < sizeof(encrypted_data_len); ++i)
	{
		char tmp = (char) (encrypted_data_len >> (8 * i));
		out_packet.push_back(tmp);
	}

	// encrypted data
	out_packet.insert(out_packet.end(), encrypted_data.begin(), encrypted_data.end());

	TunnelCommon::CRC32_hash crc_calc;
	crc_calc.Update(encrypted_data);
	crc_calc.Final();
	boost::uint32_t crc = crc_calc.GetHash();
	for (int i = 0; i < sizeof(crc); ++i)
	{
		char tmp = (char) (crc >> (8 * i));
		out_packet.push_back(tmp);
	}

	return Error_no;
}

int ProtocolParser::prepare_packet(const std::string& data, std::vector<char>& out_packet) const
{
	std::vector<char> data_vec(data.c_str(), data.c_str() + data.size());
	return prepare_packet(data_vec, out_packet);
}

int ProtocolParser::prepare_rsa_internal_pub_key_packet(std::vector<char>& packet) const
{
	const std::vector<char>& pub_key = rsa_crypting_.GetInternalPublicKey();
	return prepare_packet(pub_key, packet);
}

} // namespace TunnelCommon
