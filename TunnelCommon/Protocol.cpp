#include "stdafx.h"

#include "Protocol.h"

namespace TunnelCommon
{

const std::string Protocol::c_packet_login_accept = "Hello user!!!";

Protocol::Protocol()
	: got_data_len_(false)
	, got_data_(false)
	, got_crc_(false)
	, complete_(false)
	, got_external_rsa_key_(false)
	, packet_type_(Packet_type_unknown)
{
	rsa_crypting_.GenerateInternalKeys();
}

Protocol::~Protocol()
{
	reset();
}

int Protocol::parse(const std::vector<char>& data)
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

		if (!got_rsa_key())
		{
			data_.insert(data_.begin(), buffer_.begin(), buffer_.begin() + data_len_);
			buffer_.erase(buffer_.begin(), buffer_.begin() + data_len_);
			got_data_ = true;
			crc_calc_.Update(data_);
		}
		else
		{
			rsa_crypting_.DecryptByInternalRSA(
				std::vector<char>(buffer_.begin(), buffer_.begin() + data_len_),
				data_);
			crc_calc_.Update(&buffer_[0], data_len_);
			buffer_.erase(buffer_.begin(), buffer_.begin() + data_len_);
		}
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

		buffer_.erase(buffer_.begin(), buffer_.begin() + sizeof(crc_));

		got_crc_ = true;

		crc_calc_.Final();
		boost::uint32_t calculated_crc = crc_calc_.GetHash();

		if (calculated_crc == crc_)
		{
			complete_ = true;
			parse_packet_type();
			return Error_no;
		}
		else
		{
			flush();
			return Error_crc;
		}
	}

	return Error_no;
}

void Protocol::flush()
{
	got_data_len_ = false;
	got_data_ = false;
	got_crc_ = false;
	complete_ = false;

	crc_calc_.Clean();
	data_.clear();

	packet_type_ = Packet_type_unknown;
}

void Protocol::reset()
{
	flush();

	buffer_.clear();

	got_external_rsa_key_ = false;
}

int Protocol::parse_external_rsa_key_packet()
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

	int res = rsa_crypting_.RSA_FromPublicKey(&data_[sizeof(rsa_pub_kye_len)], rsa_pub_kye_len);
	if (res == TunnelCommon::RsaCrypting::Errror_no)
	{
		got_external_rsa_key_ = true;
		return Error_no;
	}
	return Error_rsa_key_packet;
}

int Protocol::parse_packet_type()
{
	if (data_.size() < sizeof(int))
	{
		return Error_packet_too_short;
	}

	packet_type_ = 0x000000FF & data_[0];
	packet_type_ = packet_type_ | (0x0000FF00 & (data_[1] << 8));
	packet_type_ = packet_type_ | (0x00FF0000 & (data_[2] << 16));
	packet_type_ = packet_type_ | (0xFF000000 & (data_[3] << 24));

	data_.erase(data_.begin(), data_.begin() + sizeof(int));
	
	return Error_no;
}

int Protocol::prepare_packet_private(const std::vector<char>& data,
	std::vector<char>& out_packet) const
{
	// data length
	unsigned encrypted_data_len = data.size();
	for (int i = 0; i < sizeof(encrypted_data_len); ++i)
	{
		char tmp = (char) (encrypted_data_len >> (8 * i));
		out_packet.push_back(tmp);
	}

	// data
	out_packet.insert(out_packet.end(), data.begin(), data.end());

	// CRC32
	TunnelCommon::CRC32_hash crc_calc;
	crc_calc.Update(data);
	crc_calc.Final();
	boost::uint32_t crc = crc_calc.GetHash();
	for (int i = 0; i < sizeof(crc); ++i)
	{
		char tmp = (char) (crc >> (8 * i));
		out_packet.push_back(tmp);
	}

	return Error_no;
}

int Protocol::prepare_packet(int packet_type, const std::vector<char>& data,
	std::vector<char>& out_packet, bool need_encrypt) const
{
	std::vector<char> data_copy(data.begin(), data.end());

	// packet type
	for (int i = sizeof(packet_type) - 1; i >= 0; --i)
	{
		char tmp = (char) (packet_type >> (8 * i));
		data_copy.insert(data_copy.begin(), tmp);
	}

	// encrypting
	std::vector<char> encrypted_data;
	if (need_encrypt)
	{
		int encrypt_result = rsa_crypting_.EncryptByExternalRSA(data_copy, encrypted_data);
		if (encrypt_result != TunnelCommon::RsaCrypting::Errror_no)
		{
			return Error_prepare_packet;
		}
	}

	const std::vector<char>& packet_data = need_encrypt ? encrypted_data : data_copy;
	return prepare_packet_private(packet_data, out_packet);
}

int Protocol::prepare_packet(int packet_type, const std::string& data,
	std::vector<char>& out_packet, bool need_encrypt) const
{
	std::vector<char> data_vec(data.c_str(), data.c_str() + data.size());
	return prepare_packet(packet_type, data_vec, out_packet, need_encrypt);
}

int Protocol::prepare_rsa_internal_pub_key_packet(std::vector<char>& packet) const
{
	const std::vector<char>& pub_key = rsa_crypting_.GetInternalPublicKey();

	std::vector<char> data;
	unsigned pub_key_len = pub_key.size();
	for (int i = 0; i < sizeof(pub_key_len); ++i)
	{
		char tmp = (char) (pub_key_len >> (8 * i));
		data.push_back(tmp);
	}

	data.insert(data.end(), pub_key.begin(), pub_key.end());

	return prepare_packet(Packet_type_external_rsa_key, data, packet, false);
}

} // namespace TunnelCommon
