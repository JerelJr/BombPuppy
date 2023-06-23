#ifndef TOPHEADER_HPP
#define TOPHEADER_HPP
#include "../Payload.hpp"

class TopHeader : public Payload
{
public:
    TopHeader(_ethhdr *data)
    {
        _raw_size = sizeof(_ethhdr);
        _data = data;
        _protocol = protocol_filter::ETH;
        styleRule = styleRule.getRule(_protocol);
    }
    virtual std::string toString()
    {
        std::ostringstream header_ss;
        auto eth = this->data<_ethhdr>();
        header_ss << "\nEthernet Header";
        header_ss << "\n\t|-Source Address: "
                  << HEXW(eth.h_source[0], 2) << '-' << HEXW(eth.h_source[1], 2) << '-' << HEXW(eth.h_source[2], 2) << '-'
                  << HEXW(eth.h_source[3], 2) << '-' << HEXW(eth.h_source[4], 2) << '-' << HEXW(eth.h_source[5], 2);
        header_ss
            << "\n\t|-Destination Address: "
            << HEXW(eth.h_dest[0], 2) << '-' << HEXW(eth.h_dest[1], 2) << '-' << HEXW(eth.h_dest[2], 2) << '-'
            << HEXW(eth.h_dest[3], 2) << '-' << HEXW(eth.h_dest[4], 2) << '-' << HEXW(eth.h_dest[5], 2);
        header_ss << "\n\t|-Protocol: 0x" << ntohs(eth.h_proto) << " (" << proto_to_str(ntohs(eth.h_proto)) << ")" << std::endl;

        return header_ss.str();
    }
};

#endif