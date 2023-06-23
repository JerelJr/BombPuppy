#ifndef STYLE_RULES_HPP
#define STYLE_RULES_HPP

#include "term-style.hpp"

/*
Ethernet: Yellow on Black
ARP: Black on Yellow
IPv4: Black on Cyan
IPv6: Black on Green
ICMP: HIN White on Blue
IGMP: Black on Purple
TCP: Black on HIN Purple
UDP: Black on HIN Blue
*/

class StyleRule : public TermStyle
{
public:
    StyleRule()
    {
    }
    StyleRule(BGColor background, FGColor foreground)
    {
        setBGColor(background);
        setFGColor(foreground);
    }
    StyleRule(BGColor background, FGColor foreground, std::vector<TextAttr> at)
    {
        setBGColor(background);
        setFGColor(foreground);
        setAttr(at);
    }
    StyleRule getRule(protocol_filter _protocol)
    {
        switch (_protocol)
        {
        case ETH:
            return StyleRule(BGColor(Background::REG_BLK), FGColor(Foreground::REG_YLW));
        case ARP:
            return StyleRule(BGColor(Background::REG_YLW), FGColor(Foreground::REG_BLK));
        case IP4:
            return StyleRule(BGColor(Background::REG_CYN), FGColor(Foreground::REG_BLK));
        case IP6:
            return StyleRule(BGColor(Background::REG_GRN), FGColor(Foreground::REG_BLK));
        case ICMP:
            return StyleRule(BGColor(Background::REG_BLU), FGColor(Foreground::HIN_WHT));
        case IGMP:
            return StyleRule(BGColor(Background::REG_PRP), FGColor(Foreground::REG_BLK));
        case TCP:
            return StyleRule(BGColor(Background::HIN_PRP), FGColor(Foreground::REG_BLK));
        case UDP:
            return StyleRule(BGColor(Background::HIN_BLU), FGColor(Foreground::REG_BLK));
        default:
            return StyleRule();
        }
    }
};

#endif