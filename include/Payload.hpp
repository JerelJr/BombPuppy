#ifndef PAYLOAD_HPP
#define PAYLOAD_HPP

#include <any>
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <vector>

#include "util.hpp"
#include "term-style/style-rules.hpp"

class Payload
{
protected:
	Payload() {}
	virtual ~Payload() {}
	virtual void setProtocol(){};
	size_t _raw_size;
	std::any _data;
	StyleRule styleRule;
	protocol_filter _protocol;

public:
	template <typename GenericData>
	const GenericData &data() const
	{
		return *std::any_cast<GenericData *>(_data);
	};
	virtual const size_t &raw_size() const { return _raw_size; };
	virtual std::string toString() = 0; // Differs for each payload
	std::string styleStr() { return styleRule.str(); }
	const protocol_filter &protocol() const { return _protocol; }
};

#endif