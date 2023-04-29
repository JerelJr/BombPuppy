#ifndef PACKET_HPP
#define PACKET_HPP

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <iomanip>
#include <iostream>
#include <linux/tcp.h>
#include <memory>
#include <netinet/if_ether.h>
#include <netinet/igmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <optional>
#include <sstream>
#include <string.h>
// #include <sys/capability.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct ethhdr _ethhdr;
typedef struct iphdr _iphdr;
typedef struct icmphdr _icmphdr;
typedef struct igmp _igmphdr;
typedef struct tcphdr _tcphdr;
typedef struct udphdr _udphdr;

enum protocol_filter
{
	NONE = -1,
	ICMP = 1,
	IGMP,
	TCP = 6,
	UDP = 17
};

struct SnifferOptions
{
	std::optional<std::string> src_IP;
	std::optional<std::string> dest_IP;
	std::optional<uint32_t> n_packets;
	std::optional<uint16_t> port;
	protocol_filter p_filter;
};

void print_interfaces();

SnifferOptions parse_args(int argc, char *const *argv);

void ethhdr_to_str(const _ethhdr &eth);

void print_iphdr(const _iphdr &ip);

void print_icmphdr(const _icmphdr &icmp);

void print_igmphdr(const _igmphdr &igmp);

void print_tcphdr(const _tcphdr &tcp);

void print_udphdr(const _udphdr &udp);

void print_data(uint8_t *data, int len);

#endif