#ifndef IPPAYLOAD_HPP
#define IPPAYLOAD_HPP
#include "../Payload.hpp"
#include "../util.hpp"

template <typename GenericPayload>
class IPPayload : public Payload
{
private:
	uint16_t _ihl;

public:
	IPPayload(GenericPayload *data, uint16_t ihl) : _ihl(ihl)
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
		case ICMP:
		{
			auto icmp = this->data<_icmphdr>();
			header_ss << "\nICMP Header";
			header_ss << "\n\t|-Type: " << static_cast<uint16_t>(icmp.type);
			header_ss << "\n\t|-Code: " << static_cast<uint16_t>(icmp.code);
			header_ss << "\n\t|-Checksum: 0x" << HEXW(ntohs(icmp.checksum), 4) << std::endl;
		}
		break;
		case IGMP:
		{
			auto igmp = this->data<_igmphdr>();
			header_ss << "\nIGMP Header";
			header_ss << "\n\t|-Type: " << static_cast<uint16_t>(igmp.igmp_type);
			header_ss << "\n\t|-Code: " << static_cast<uint16_t>(igmp.igmp_code);
			header_ss << "\n\t|-Checksum: 0x" << HEXW(ntohs(igmp.igmp_cksum), 4);
			header_ss << "\n\t|-Group: " << inet_ntoa(igmp.igmp_group) << std::endl;
		}
		break;
		case TCP:
		{
			_tcphdr tcp = this->data<_tcphdr>();
			header_ss << "\nTCP Header";
			header_ss << "\n\t|-Source Port: " << ntohs(tcp.source);
			header_ss << "\n\t|-Destination Port: " << ntohs(tcp.dest);
			header_ss << "\n\t|-Sequence #: " << ntohl(tcp.seq);
			header_ss << "\t|-ACK #: " << ntohl(tcp.ack_seq);
			header_ss << "\n\t|-Doff: " << static_cast<uint16_t>(tcp.doff);
			header_ss << "\n\t|-Reserved: " << static_cast<uint16_t>(tcp.res1);
			header_ss << "\n\t|-Congestion Window Reduced: " << static_cast<uint16_t>(tcp.window);
			// header_ss << "\n\t|-ECN-Echo: " << static_cast<uint16_t>(tcp.ece);
			header_ss << "\n\t|-Urgent: " << static_cast<uint16_t>(tcp.urg);
			header_ss << "\n\t|-Acknowledgement: " << static_cast<uint16_t>(tcp.ack);
			header_ss << "\n\t|-Push: " << static_cast<uint16_t>(tcp.psh);
			header_ss << "\n\t|-Reset: " << static_cast<uint16_t>(tcp.rst);
			header_ss << "\n\t|-Syn: " << static_cast<uint16_t>(tcp.syn);
			header_ss << "\n\t|-Fin: " << static_cast<uint16_t>(tcp.fin) << std::endl;
		}
		break;
		case UDP:
		{
			auto udp = this->data<_udphdr>();
			header_ss << "\nUDP Header";
			header_ss << "\n\t|-Source Port: " << ntohs(udp.source);
			header_ss << "\n\t|-Destination Port: " << ntohs(udp.dest);
			header_ss << "\n\t|-UDP Length: " << ntohs(udp.len);
			header_ss << "\n\t|-UDP Checksum: 0x" << HEXW(ntohs(udp.check), 4) << std::endl;
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
void IPPayload<_icmphdr>::setProtocol()
{
	_protocol = protocol_filter::ICMP;
}
template <>
void IPPayload<_igmphdr>::setProtocol()
{
	_protocol = protocol_filter::IGMP;
}
template <>
void IPPayload<_tcphdr>::setProtocol()
{
	_protocol = protocol_filter::TCP;
}
template <>
void IPPayload<_udphdr>::setProtocol()
{
	_protocol = protocol_filter::UDP;
}
#endif