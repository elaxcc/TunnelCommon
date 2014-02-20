#pragma once

#include "Crypting.h"
#include "Hash.h"

namespace TunnelCommon
{

class Protocol
{
public:
	enum Packet_type
	{
		Packet_type_external_rsa_key = 1,
		Packet_type_login_data = 2,
		Packet_type_send_internal_rsa_pub_key = 3,
		Packet_type_login_accept = 4
	};

	enum Error
	{
		Error_wait_packet = 1,
		Error_no = 0,
		Error_crc = -1,
		Error_packet_not_complete = -2,
		Error_prepare_packet = -3,
		Error_rsa_key_packet = -4,
		Error_parse_login_packet = -5,
		Error_unknown_packet = -6,
		Error_parse_login_node_not_exist = -7
	};

	Protocol();
	~Protocol();

	int parse(const std::vector<char>& data);
	void flush();
	void reset();
	bool is_complete() { return complete_; }
	const std::vector<char>& get_data() { return data_; }

	virtual int process_in() = 0;
	virtual int process_out() = 0;

	int parse_external_rsa_key_packet();
	bool got_rsa_key() { return got_external_rsa_key_; }

	int prepare_packet(int packet_type, const std::vector<char>& data, std::vector<char>& out_packet) const;
	int prepare_packet(int packet_type, const std::string& data, std::vector<char>& out_packet) const;
	int prepare_rsa_internal_pub_key_packet(std::vector<char>& packet) const;

public:
	RsaCrypting rsa_crypting_;
	CRC32_hash crc_calc_;

private:
	std::vector<char> buffer_;

	bool got_data_len_;
	bool got_data_;
	bool got_crc_;
	bool complete_;
	boost::uint32_t data_len_;
	std::vector<char> data_;
	boost::uint32_t crc_;

	bool got_external_rsa_key_;
};

} // namespace TunnelCommon

