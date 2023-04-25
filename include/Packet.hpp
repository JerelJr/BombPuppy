#ifndef PACKET_HPP
#define PACKET_HPP

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <iostream>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <memory>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <optional>
#include <string.h>
// #include <sys/capability.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct SnifferOptions
{
	std::optional<std::string> src_IP;
	std::optional<std::string> dest_IP;
	std::optional<uint32_t> n_packets;
	std::optional<uint16_t> port;
	enum protocol_filter
	{
		NONE = -1,
		ICMP = 1,
		IGMP,
		TCP = 6,
		UDP = 17
	} p_filter = NONE;
};

void print_interfaces();

SnifferOptions parse_args(int argc, char *const *argv);

void print_ethhdr(struct ethhdr *eth);

void print_iphdr(struct iphdr *ip);

void print_tcphdr(struct tcphdr *tcp);

void print_udphdr(struct udphdr *udp);

void print_data(uint8_t *data, int len);

#endif