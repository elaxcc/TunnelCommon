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

	static const std::string c_user_accept_packet_;

	ProtocolParser();
	~ProtocolParser();

	int parse_common(const std::vector<char>& data);
	void flush_common();
	void reset();
	bool is_complete() { return complete_; }

	int parse_rsa_key_packet();
	bool got_rsa_key() { return got_rsa_key_; }

	/*!
	 * Login packet format:
	 * 1.) Login length
	 * 2.) Login
	 * 3.) Password hash length
	 * 4.) Password hash
	 */
	int parse_login_packet();
	bool got_login_data() { return got_login_data_; }
	const std::vector<char>& get_login() const { return login_; }
	const std::vector<char>& get_passwd_hash() const { return passwd_hash_; }
	const std::string get_node_name() const { return node_name_; }

	/*!
	 * Data packet format
	 */
	int parse_data_packet();

	int prepare_packet(const std::vector<char>& data, std::vector<char>& out_packet) const;
	int prepare_packet(const std::string& data, std::vector<char>& out_packet) const;
	int prepare_rsa_internal_pub_key_packet(std::vector<char>& packet) const;

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

	bool got_rsa_key_;

	bool got_login_data_;
	std::vector<char> login_;
	std::vector<char> passwd_hash_;
	std::string node_name_;
};

} // namespace TunnelCommon
