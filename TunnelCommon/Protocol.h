#pragma once

#include "Crypting.h"
#include "Hash.h"

namespace TunnelCommon
{

class ProtocolParser
{
public:
	enum Error
	{
		Error_wait_packet = 1,
		Error_no = 0,
		Error_crc = -1,
		Error_packet_not_complete = -2,
		Error_prepare_packet = -3,
		Error_rsa_key_packet = -4,
		Error_parse_login_packet = -5
	};

	ProtocolParser();
	~ProtocolParser();

	int parse_common(const std::vector<char>& data);
	void flush();
	void reset();
	bool is_complete() { return complete_; }

	int parse_rsa_key_packet();

	/*!
	 * Login packet format:
	 * 1.) Login length
	 * 2.) Login
	 * 3.) Password hash length
	 * 4.) Password hash
	 */
	int parse_login_data();
	const std::vector<char>& get_login() const { return login_; }
	const std::vector<char>& get_passwd_hash() const { return passwd_hash_; }

	/*!
	 * Data packet format
	 */
	int parse_data_packet();

	int prepare_packet(std::vector<char> data, std::vector<char>& out_packet) const;

private:
	RsaCrypting rsa_crypting_;
	CRC32_hash crc_calc_;
	std::vector<char> buffer_;
	bool got_data_len_;
	bool got_data_;
	bool got_crc_;
	bool complete_;
	boost::uint32_t data_len_;
	std::vector<char> data_;
	boost::uint32_t crc_;

	std::vector<char> login_;
	std::vector<char> passwd_hash_;
};

} // namespace TunnelCommon
