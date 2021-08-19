#ifndef PACKET_HPP
#define PACKET_HPP

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <ifaddrs.h>
#include <iostream>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <string.h>
// #include <sys/capability.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct SnifferOptions
{
	char *src_IP = nullptr;
	char *dest_IP = nullptr;
	int n_packets = -1;
	unsigned short port = 0;
	enum protocol_filter
	{
		NONE = 0,
		TCP,
		UDP
	} p_filter = NONE;
};

void print_interfaces();

SnifferOptions parse_args(int argc, char *const *argv);

void print_ethhdr(struct ethhdr *eth);

void print_iphdr(struct iphdr *ip);

void print_tcphdr(struct tcphdr *tcp);

void print_udphdr(struct udphdr *udp);

void print_data(unsigned char *data, int len);

#endif