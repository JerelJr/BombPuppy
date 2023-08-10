#ifndef UTIL_HPP
#define UTIL_HPP

#include <cstdint>
#include <ifaddrs.h>
#include <iostream>
#include <netinet/if_ether.h>
#include <netinet/igmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <optional>
#include <string>
#include <unistd.h>
/*
#define GLUE_STR(a, b) PASTER(a, b)
#define PASTER(a, b) #a## #b
*/
#define HEXW(x, w) std::setw(w) << std::setfill('0') << std::hex << static_cast<int>(x)

typedef struct ethhdr _ethhdr;
typedef struct ip6_hdr _ip6hdr;
typedef struct iphdr _iphdr;
typedef struct icmphdr _icmphdr;
typedef struct igmp _igmphdr;
typedef struct tcphdr _tcphdr;
typedef struct udphdr _udphdr;

struct _arphdr
{
	uint16_t hrd;
	uint16_t pro;
	uint8_t hln;
	uint8_t pln;
	uint16_t op;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t recv_mac[6];
	uint8_t recv_ip[4];
};
// TODO: make union/variant of different packet protocol enum
enum protocol_filter
{
	ETH = -2,
	NONE = -1,
	ICMP = 1,
	IGMP,
	TCP = 6,
	UDP = 17,
	IP4 = 0x800,
	ARP = 0x806,
	IP6 = 0x86DD
};

struct SnifferOptions
{
	std::optional<std::string> src_IP;
	std::optional<std::string> dest_IP;
	std::optional<uint32_t> n_packets;
	std::optional<uint16_t> port;
	protocol_filter p_filter; // TODO: This should be optional as well
};

std::string proto_to_str(uint16_t proto)
{
	switch (proto)
	{
	case ICMP:
		return "ICMP";
	case IGMP:
		return "IGMP";
	case TCP:
		return "TCP";
	case UDP:
		return "UDP";
	case IP4:
		return "IPv4";
	case ARP:
		return "ARP";
	case IP6:
		return "IPv6";
	default:
		return "[UNKNOWN]";
	}
}

void print_interfaces()
{
	struct ifaddrs *addrs, *tmp;

	getifaddrs(&addrs);
	tmp = addrs;

	while (tmp)
	{
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
			std::cout << tmp->ifa_name << std::endl;

		tmp = tmp->ifa_next;
	}
	freeifaddrs(addrs);
}

SnifferOptions parse_args(int argc, char *const *argv)
{
	static SnifferOptions args;
	char opt;
	while ((opt = getopt(argc, argv, "i:I:n:p:w:x:tu")) != EOF)
		switch (opt)
		{
		case 'i':
			// filter by source IP address
			args.src_IP = optarg;
			break;
		case 'I':
			// filter by destination IP address
			args.dest_IP = optarg;
			break;
		case 'n':
			// capture n number of packets
			args.n_packets = static_cast<uint32_t>(atoi(optarg)); // !!!casting from int to uint
			break;
		case 'p':
			// filter by port number
			args.port = static_cast<ushort>(atoi(optarg));
			break;
		case 'w':
			// redirect output to a file
			if (!(freopen(optarg, "a", stdout)))
			{
				perror("Error opening write file: ");
				exit(-1);
			}
			break;
		case 'x':
			// filter by interface

			break;
		case 't':
			// display tcp packets only
			args.p_filter = protocol_filter::TCP;
			break;
		case 'u':
			// display udp packets only
			args.p_filter = protocol_filter::UDP;
			break;
		default:
			// std::cout << "Unrecognized argument: -" << opt << std::endl;
			break;
		}

	return args;
}

#endif