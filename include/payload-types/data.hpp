#ifndef DATA_HPP
#define DATA_HPP
#include "../Payload.hpp"

class Data : public Payload
{
public:
	Data(uint8_t *data, size_t len)
	{
		_raw_size = len;
		_data = data;
		_protocol = protocol_filter::NONE;
		styleRule = styleRule.getRule(_protocol);
	}
	virtual std::string toString()
	{
		std::ostringstream header_ss;

		auto data = &this->data<uint8_t>();
		auto len = this->raw_size();
		header_ss << "Raw Data:" << std::endl;
		for (size_t i = 0; i < len; i++)
		{
			if (i != 0 && i % 16 == 0)
			{
				header_ss << "\t";
				for (size_t j = i - 16; j < i; j++)
				{
					if (data[j] >= 32 && data[j] <= 128)
						header_ss << data[j]; // add data in ascii
					else
						header_ss << '.';
				}
				header_ss << '\n';
			}
			header_ss << HEXW(data[i], 2); // add hex data
		}
		return header_ss.str();
	}

private:
	size_t _start_index;
};

#endif