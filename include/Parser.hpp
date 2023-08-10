#ifndef PARSER_HPP
#define PARSER_HPP
#include <iostream>
#include <memory>
#include <netinet/if_ether.h>
#include <netinet/igmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <optional>
#include <vector>

#include "Payload.hpp"
#include "payload-types/topheader.hpp"
#include "payload-types/ethpayload.hpp"
#include "payload-types/ippayload.hpp"
#include "payload-types/data.hpp"

namespace PacketParser
{
    std::shared_ptr<Payload> parse_to_raw(uint8_t *rawData, size_t len)
    {
        return std::dynamic_pointer_cast<Payload>(std::make_shared<Data>(rawData, len));
    }
    template <typename GenericPacket>
    std::shared_ptr<Payload> parse_raw(std::vector<uint8_t> &rawData, protocol_filter protocol, uint16_t ihl = 0)
    {
        switch (protocol)
        {
        case protocol_filter::ETH:
            _ethhdr *data0;
            data0 = reinterpret_cast<ethhdr *>(&rawData[0]);
            return std::dynamic_pointer_cast<Payload>(std::make_shared<TopHeader>(data0));
        case protocol_filter::IP4:
        case protocol_filter::ARP:
        case protocol_filter::IP6:
            GenericPacket *data1;
            data1 = reinterpret_cast<GenericPacket *>(&rawData[0] + sizeof(_ethhdr));
            return std::dynamic_pointer_cast<Payload>(std::make_shared<EthPayload<GenericPacket>>(data1));
        case protocol_filter::ICMP:
        case protocol_filter::IGMP:
        case protocol_filter::TCP:
        case protocol_filter::UDP:
            GenericPacket *data2;
            data2 = reinterpret_cast<GenericPacket *>(&rawData[0] + sizeof(_ethhdr) + ihl);
            return std::dynamic_pointer_cast<Payload>(std::make_shared<IPPayload<GenericPacket>>(data2, ihl));
        default:
            throw; // TODO: make an actual exception
        }
    }
};

#endif