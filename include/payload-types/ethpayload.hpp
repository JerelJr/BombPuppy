#ifndef ETHPAYLOAD_HPP
#define ETHPAYLOAD_HPP
#include "../Payload.hpp"

template <typename GenericPayload>
class EthPayload : public Payload
{
public:
	EthPayload(GenericPayload *data)
	{
		this->_raw_size = sizeof(GenericPayload);
		this->_data = data;
		setProtocol();
		styleRule = styleRule.getRule(_protocol);
	}
	virtual std::string toString()
	{
		std::ostringstream header_ss;
		switch (_protocol)
		{
		case ARP:
		{
			auto arp = this->data<_arphdr>();
			header_ss << "\nARP Header";
			header_ss << "\n\t|-Hardware Type: " << ntohs(arp.hrd);
			header_ss << "\n\t|-Protocol Type: " << ntohs(arp.pro);
			header_ss << "\n\t|-Hardware Address Length: " << static_cast<int>(arp.hln); // Might need a cast
			header_ss << "\n\t|-Protocol Address Length: " << static_cast<int>(arp.pln);
			header_ss << "\n\t|-Opcode: " << ntohs(arp.op);
			header_ss << "\n\t|-Sender MAC Address: "
					  << HEXW(arp.sender_mac[0], 2) << '-' << HEXW(arp.sender_mac[1], 2) << '-' << HEXW(arp.sender_mac[2], 2) << '-'
					  << HEXW(arp.sender_mac[3], 2) << '-' << HEXW(arp.sender_mac[4], 2) << '-' << HEXW(arp.sender_mac[5], 2);
			char send_ip[50] = {0};
			snprintf(send_ip, 49, "%u.%u.%u.%u", arp.sender_ip[0], arp.sender_ip[1], arp.sender_ip[2], arp.sender_ip[4]);
			header_ss << "\n\t|-Sender IP Address: " << send_ip;
			header_ss << "\n\t|-Receiver MAC Address: "
					  << HEXW(arp.recv_mac[0], 2) << '-' << HEXW(arp.recv_mac[1], 2) << '-' << HEXW(arp.recv_mac[2], 2) << '-'
					  << HEXW(arp.recv_mac[3], 2) << '-' << HEXW(arp.recv_mac[4], 2) << '-' << HEXW(arp.recv_mac[5], 2);
			char recv_ip[50] = {0};
			snprintf(recv_ip, 49, "%u.%u.%u.%u", arp.sender_ip[0], arp.sender_ip[1], arp.sender_ip[2], arp.sender_ip[4]);
			header_ss << "\n\t|-Receiver IP Address: " << recv_ip << std::endl;
		}
		break;
		case IP4:
		{
			struct sockaddr_in source, dest;

			auto ip = this->data<_iphdr>();
			memset(&source, 0, sizeof(source));
			source.sin_addr.s_addr = ip.saddr;
			memset(&dest, 0, sizeof(dest));
			dest.sin_addr.s_addr = ip.daddr;

			header_ss << "\nIP Header";
			header_ss << "\n\t|-Version: " << static_cast<uint32_t>(ip.version);
			header_ss << "\n\t|-Internet Header Length: " << static_cast<uint32_t>(ip.ihl)
					  << " DWORDS or " << static_cast<uint32_t>(ip.ihl * 4) << " Bytes";
			header_ss << "\n\t|-Type of Service: " << static_cast<uint16_t>(ip.tos);
			header_ss << "\n\t|-Total Length: " << ntohs(ip.tot_len) << " Bytes";
			header_ss << "\n\t|-Identification: " << ntohs(ip.id);
			header_ss << "\n\t|-Time to Live: " << static_cast<uint16_t>(ip.ttl);
			header_ss << "\n\t|-Protocol: " << static_cast<uint16_t>(ip.protocol);
			header_ss << "\n\t|-Header Checksum: 0x" << HEXW(ntohs(ip.check), 4);
			header_ss << "\n\t|-Source IP: " << inet_ntoa(source.sin_addr);
			header_ss << "\n\t|-Destination IP: " << inet_ntoa(dest.sin_addr) << std::endl;
		}
		break;
		case IP6:
		{
			auto ip6 = this->data<_ip6hdr>();
			char source[INET6_ADDRSTRLEN];
			char dest[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &(ip6.ip6_src), source, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &(ip6.ip6_dst), dest, INET6_ADDRSTRLEN);

			header_ss << "\nIPv6 Header";
			header_ss << "\n\t|-Version: " << static_cast<int>(ip6.ip6_vfc >> 4);
			header_ss << "\n\t|-Traffic Class: " << std::hex << static_cast<int>((ip6.ip6_flow >> 20) & 0xFF);
			header_ss << "\n\t|-Flow Label: " << std::hex << static_cast<int>(ip6.ip6_flow & 0xFFFFF) << std::dec;
			header_ss << "\n\t|-Payload Length: " << ntohs(ip6.ip6_plen);
			header_ss << "\n\t|-Next Header: " << static_cast<int>(ip6.ip6_nxt);
			header_ss << "\n\t|-Hop Limit: " << static_cast<int>(ip6.ip6_hops);
			header_ss << "\n\t|-Source IP: " << source;
			header_ss << "\n\t|-Destination IP: " << dest << std::endl;
		}
		break;

		default:
			return std::string("");
			break;
		}

		return header_ss.str();
	}
	virtual void setProtocol() {}
};
template <>
void EthPayload<_ip6hdr>::setProtocol()
{
	_protocol = protocol_filter::IP6;
}
template <>
void EthPayload<_arphdr>::setProtocol()
{
	_protocol = protocol_filter::ARP;
}
// Template specialization to account for variable length of ip header
template <>
EthPayload<_iphdr>::EthPayload(_iphdr *data)
{
	_data = data;
	_raw_size = this->data<_iphdr>().ihl * 4;
	_protocol = protocol_filter::IP4;
	styleRule = styleRule.getRule(_protocol);
}

#endif