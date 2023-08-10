#ifndef RAWPACKET_HPP
#define RAWPACKET_HPP

#include <memory>
#include <variant>

#include "Parser.hpp"
#include "term-style/term-style.hpp"

class RawPacket
{
public:
    RawPacket(std::vector<uint8_t> data, size_t received) : raw_data(data), _received_size(received)
    {
        uint8_t ip_proto;
        uint16_t ip_size;
        parsedData.push_back(PacketParser::parse_raw<_ethhdr>(raw_data, protocol_filter::ETH));
        const auto ethertype = ntohs(parsedData[0]->data<_ethhdr>().h_proto);
        switch (ethertype)
        {
        case protocol_filter::ARP:
            parsedData.push_back(PacketParser::parse_raw<_arphdr>(raw_data, protocol_filter::ARP));
            break;
        case protocol_filter::IP4:
        case protocol_filter::IP6:
            if (ethertype == protocol_filter::IP4)
            {
                parsedData.push_back(PacketParser::parse_raw<_iphdr>(raw_data, protocol_filter::IP4));
                ip_proto = parsedData[1]->data<_iphdr>().protocol;
                ip_size = parsedData[1]->data<_iphdr>().ihl * 4;
            }
            else
            {
                parsedData.push_back(PacketParser::parse_raw<_ip6hdr>(raw_data, protocol_filter::IP6));
                ip_proto = parsedData[1]->data<_ip6hdr>().ip6_nxt;
                ip_size = sizeof(_ip6hdr);
            }
            switch (ip_proto)
            {
            case protocol_filter::ICMP:
                parsedData.push_back(PacketParser::parse_raw<_icmphdr>(raw_data, protocol_filter::ICMP, ip_size));
                break;
            case protocol_filter::IGMP:
                parsedData.push_back(PacketParser::parse_raw<_igmphdr>(raw_data, protocol_filter::IGMP, ip_size));
                break;
            case protocol_filter::TCP:
                parsedData.push_back(PacketParser::parse_raw<_tcphdr>(raw_data, protocol_filter::TCP, ip_size));
                break;
            case protocol_filter::UDP:
                parsedData.push_back(PacketParser::parse_raw<_udphdr>(raw_data, protocol_filter::UDP, ip_size));
                break;
            default:
                // Parse everything else as raw data
                break;
            }
            break;
        default:
            // // Parse everything else as raw data
            break;
        }
        _raw_size = 0;
        for (auto data : parsedData)
        {
            _raw_size += data->raw_size();
        }
        // Parse remaining data as raw
        parsedData.push_back(PacketParser::parse_to_raw(&raw_data[_raw_size], _received_size - _raw_size));
    }

    std::string toString()
    {
        std::ostringstream sstr;

        if (parsedData.back()->protocol() == protocol_filter::NONE && parsedData.size() > 1)
        {
            sstr << parsedData.rbegin()[1]->styleStr();
        }
        else
        {
            sstr << parsedData.back()->styleStr();
        }
        sstr << _received_size << " Bytes Received" << std::endl;

        for (auto payload : parsedData)
        {
            sstr << payload->toString();
        }
        sstr << separator();
        return sstr.str();
    }

private:
    TermStyle style;
    std::vector<std::shared_ptr<Payload>>
        parsedData;
    std::vector<uint8_t> raw_data;
    size_t _raw_size, _received_size;
};

#endif