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

struct _arphdr
{
	unsigned short int hrd;
	unsigned short int pro;
	unsigned char hln;
	unsigned char pln;
	unsigned short int op;
	uint8_t sender_mac[6];
	in_addr sender_ip;
	uint8_t recv_mac[6];
	in_addr recv_ip;
};

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
/*
template <class T>
T parsePacket(const uint8_t *buffer)
{
	uint16_t iphdrlen;
	_ethhdr *eth = reinterpret_cast<struct ethhdr *>(buffer);

	ethhdr_to_str(*eth);

	struct iphdr *ip = reinterpret_cast<struct iphdr *>(buffer + sizeof(struct ethhdr));
	iphdr_to_str(*ip);

	iphdrlen = ip->ihl * 4;
	T *packet = reinterpret_cast<T *>(buffer + iphdrlen +
									  sizeof(struct ethhdr));
	data = (buffer + sizeof(struct ethhdr) + iphdrlen +
			sizeof(T));
	rmng_data_len = rcvd_len - (sizeof(struct ethhdr) + iphdrlen +
								sizeof(T));
}
*/
void print_interfaces();

SnifferOptions parse_args(int argc, char *const *argv);

void arphdr_to_str(const _arphdr &arp);

void ethhdr_to_str(const _ethhdr &eth);

void iphdr_to_str(const _iphdr &ip);

void print_icmphdr(const _icmphdr &icmp);

void print_igmphdr(const _igmphdr &igmp);

void print_tcphdr(const _tcphdr &tcp);

void print_udphdr(const _udphdr &udp);

void print_data(uint8_t *data, int len);

#endif