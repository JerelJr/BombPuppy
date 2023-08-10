#ifndef TERM_STYLE_HPP
#define TERM_STYLE_HPP

#include <iomanip>
#include <sstream>
#include <string>
#include "../util.hpp"
#include <vector>

template <typename T>
class StyleElement
{
protected:
    virtual ~StyleElement(){};
    T element;

public:
    virtual std::string str()
    {
        return std::to_string(static_cast<int>(element));
    }
};

/* Text Coloring */
namespace Foreground
{
    enum FGC
    {
        // Regular color
        REG_BLK = 30,
        REG_RED,
        REG_GRN,
        REG_YLW,
        REG_BLU,
        REG_PRP,
        REG_CYN,
        REG_WHT,
        // High-intensity color
        HIN_BLK = 90,
        HIN_RED,
        HIN_GRN,
        HIN_YLW,
        HIN_BLU,
        HIN_PRP,
        HIN_CYN,
        HIN_WHT,
    };
    class FGColor : public StyleElement<FGC>
    {

    public:
        using enum FGC;
        FGColor() {}
        FGColor(FGC color)
        {
            this->element = color;
        }
    };
};
using FGColor = Foreground::FGColor;

/* Background Coloring */
namespace Background
{
    enum BGC
    {
        // Regular color
        REG_BLK = 40,
        REG_RED,
        REG_GRN,
        REG_YLW,
        REG_BLU,
        REG_PRP,
        REG_CYN,
        REG_WHT,
        // High-intensity color
        HIN_BLK = 100,
        HIN_RED,
        HIN_GRN,
        HIN_YLW,
        HIN_BLU,
        HIN_PRP,
        HIN_CYN,
        HIN_WHT,
    };
    class BGColor : public StyleElement<BGC>
    {

    public:
        using enum BGC;
        BGColor() {}
        BGColor(BGC color)
        {
            this->element = color;
        }
    };
};
using BGColor = Background::BGColor;

/* Text Attributes */
namespace TextAttribute
{
    enum Attr
    {
        RESET = 0,   // Remove attributes
        BOLD,        // Bold
        FAINT,       // Faint
        ITLC,        // Italic
        UNDRLN,      // Underline
        SLOBLK,      // Slow blink
        FSTBLK,      // Fast blink
        SWAP,        // Swap background and foreground colors
        CNCL,        // Conceal text
        CROSS,       // Crossed-out
        FRKTR = 20,  // Fraktur
        B_DU,        // Bold off / double underline
        NRML,        // Normal color- not bold, not faint
        IF_OFF,      // Not italic/ not Fraktur
        UL_OFF,      // Underline off
        BL_OFF,      // Blink off
        IN_OFF,      // Inverse off
        REVEAL,      // Conceal off
        CX_OFF,      // Cross-out off
        FRAMED = 51, // Framed
        ENCIRC,      // Encircled
        OVRLIN,      // Overlined
        FR_OFF,      // Frame off
        EC_OFF,      // Encircle off
        OL_OFF       // Overline off
    };
    class TextAttr : public StyleElement<Attr>
    {
    public:
        using enum Attr;
        TextAttr() {}
        TextAttr(Attr attr)
        {
            this->element = attr;
        }
    };
};
using TextAttr = TextAttribute::TextAttr;

class TermStyle
{
    BGColor bg_color;
    FGColor fg_color;
    std::vector<TextAttr> attrs;

public:
    TermStyle() = default;
    TermStyle(BGColor background, FGColor foreground) : bg_color(background), fg_color(foreground)
    {
    }
    TermStyle(BGColor background, FGColor foreground, std::vector<TextAttr> at) : bg_color(background), fg_color(foreground), attrs(at)
    {
    }
    std::string str()
    {
        std::string style_str = "\033[";
        style_str += fg_color.str();
        style_str += ';';
        style_str += bg_color.str();

        for (auto &&attr : attrs)
        {
            style_str += ';';
            style_str += attr.str();
        }

        style_str += "m";
        return style_str;
    }

    void setFGColor(FGColor fg) { fg_color = fg; }
    FGColor getFGColor() { return fg_color; }

    void setBGColor(BGColor bg) { bg_color = bg; }
    BGColor getBGColor() { return bg_color; }

    void setAttr(std::vector<TextAttr> at) { attrs = at; }
    void addAttr(TextAttr attr) { attrs.push_back(attr); }
    void removeAttr() { attrs.pop_back(); }
};

std::string separator()
{
    std::ostringstream line_ss;
    // TermStyle bold, unbold;

    // bold.addAttr(TextAttr(TextAttr::BOLD));
    // unbold.addAttr(TextAttr(TextAttr::NRML));

    line_ss << '\n'
            << std::setw(56) << std::setfill('_') << '\n';

    return line_ss.str();
}

#endif