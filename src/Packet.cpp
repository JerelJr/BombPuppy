#include "../include/Packet.hpp"

#define HEXW(x, w) std::setw(w) << std::setfill('0') << std::hex << static_cast<int>(x)

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

void arphdr_to_str(const _arphdr &arp)
{
	std::ostringstream header_ss;

	header_ss << "\nARP Header";
	header_ss << "\n\t|-Hardware Type: " << arp.hrd;
	header_ss << "\n\t|-Protocol Type: " << arp.pro;
	header_ss << "\n\t|-Hardware Address Length: " << arp.hln;
	header_ss << "\n\t|-Protocol Address Length: " << arp.pln;
	header_ss << "\n\t|-Opcode: " << arp.op;
	header_ss << "\n\t|-Sender MAC Address: "
			  << HEXW(arp.sender_mac[0], 2) << '-' << HEXW(arp.sender_mac[1], 2) << '-' << HEXW(arp.sender_mac[2], 2) << '-'
			  << HEXW(arp.sender_mac[3], 2) << '-' << HEXW(arp.sender_mac[4], 2) << '-' << HEXW(arp.sender_mac[5], 2);
	header_ss << "\n\t|-Sender IP Address: " << inet_ntoa(arp.sender_ip);
	header_ss << "\n\t|-Receiver MAC Address: "
			  << HEXW(arp.recv_mac[0], 2) << '-' << HEXW(arp.recv_mac[1], 2) << '-' << HEXW(arp.recv_mac[2], 2) << '-'
			  << HEXW(arp.recv_mac[3], 2) << '-' << HEXW(arp.recv_mac[4], 2) << '-' << HEXW(arp.recv_mac[5], 2);
	header_ss << "\n\t|-Receiver IP Address: " << inet_ntoa(arp.recv_ip);
}

void ethhdr_to_str(const _ethhdr &eth)
{
	std::ostringstream header_ss;
	// \033[1;31;47m
	header_ss << "\nEthernet Header";
	header_ss << "\n\t|-Source Address: "
			  << HEXW(eth.h_source[0], 2) << '-' << HEXW(eth.h_source[1], 2) << '-' << HEXW(eth.h_source[2], 2) << '-'
			  << HEXW(eth.h_source[3], 2) << '-' << HEXW(eth.h_source[4], 2) << '-' << HEXW(eth.h_source[5], 2);
	header_ss
		<< "\n\t|-Destination Address: "
		<< HEXW(eth.h_dest[0], 2) << '-' << HEXW(eth.h_dest[1], 2) << '-' << HEXW(eth.h_dest[2], 2) << '-'
		<< HEXW(eth.h_dest[3], 2) << '-' << HEXW(eth.h_dest[4], 2) << '-' << HEXW(eth.h_dest[5], 2);
	header_ss << "\n\t|-Protocol: 0x" << ntohs(eth.h_proto) << std::endl;
	std::cout << header_ss.str();
}
void iphdr_to_str(const _iphdr &ip)
{
	std::ostringstream header_ss;
	struct sockaddr_in source, dest;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip.saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip.daddr;

	header_ss << "\nIP Header";
	header_ss << "\n\t|-Version: " << static_cast<uint32_t>(ip.version);
	header_ss << "\n\t|-Internet Header Length: " << static_cast<uint32_t>(ip.ihl)
			  << " DWORDS or " << static_cast<uint32_t>(ip.ihl * 4) << " Bytes";
	header_ss << "\n\t|-Type of Service: " << static_cast<uint16_t>(ip.tos);
	header_ss << "\n\t|-Total Length: " << ntohs(ip.tot_len) << " Bytes";
	header_ss << "\n\t|-Identification: " << ntohs(ip.id);
	header_ss << "\n\t|-Time to Live: " << static_cast<uint16_t>(ip.ttl);
	header_ss << "\n\t|-Protocol: " << static_cast<uint16_t>(ip.protocol);
	header_ss << "\n\t|-Header Checksum: 0x" << HEXW(ntohs(ip.check), 4);
	header_ss << "\n\t|-Source IP: " << inet_ntoa(source.sin_addr);
	header_ss << "\n\t|-Destination IP: " << inet_ntoa(dest.sin_addr) << std::endl;

	std::cout << header_ss.str();
}

void print_icmphdr(const _icmphdr &icmp)
{
	std::ostringstream header_ss;

	header_ss << "\nICMP Header";
	header_ss << "\n\t|-Type: " << static_cast<uint16_t>(icmp.type);
	header_ss << "\n\t|-Code: " << static_cast<uint16_t>(icmp.code);
	header_ss << "\n\t|-Checksum: 0x" << HEXW(ntohs(icmp.checksum), 4) << std::endl;

	std::cout << header_ss.str();
}

void print_igmphdr(const _igmphdr &igmp)
{
	std::ostringstream header_ss;

	header_ss << "\nIGMP Header";
	header_ss << "\n\t|-Type: " << static_cast<uint16_t>(igmp.igmp_type);
	header_ss << "\n\t|-Code: " << static_cast<uint16_t>(igmp.igmp_code);
	header_ss << "\n\t|-Checksum: 0x" << HEXW(ntohs(igmp.igmp_cksum), 4);
	header_ss << "\n\t|-Group: " << inet_ntoa(igmp.igmp_group) << std::endl;

	std::cout << header_ss.str();
}

void print_tcphdr(const _tcphdr &tcp)
{
	std::ostringstream header_ss;

	header_ss << "\nTCP Header";
	header_ss << "\n\t|-Source Port: " << ntohs(tcp.source);
	header_ss << "\n\t|-Destination Port: " << ntohs(tcp.dest);
	header_ss << "\n\t|-Sequence #: " << ntohl(tcp.seq);
	header_ss << "\t|-ACK #: " << ntohl(tcp.ack_seq);
	header_ss << "\n\t|-Doff: " << static_cast<uint16_t>(tcp.doff);
	header_ss << "\n\t|-Reserved: " << static_cast<uint16_t>(tcp.res1);
	header_ss << "\n\t|-Congestion Window Reduced: " << static_cast<uint16_t>(tcp.window);
	header_ss << "\n\t|-ECN-Echo: " << static_cast<uint16_t>(tcp.ece);
	header_ss << "\n\t|-Urgent: " << static_cast<uint16_t>(tcp.urg);
	header_ss << "\n\t|-Acknowledgement: " << static_cast<uint16_t>(tcp.ack);
	header_ss << "\n\t|-Push: " << static_cast<uint16_t>(tcp.psh);
	header_ss << "\n\t|-Reset: " << static_cast<uint16_t>(tcp.rst);
	header_ss << "\n\t|-Syn: " << static_cast<uint16_t>(tcp.syn);
	header_ss << "\n\t|-Fin: " << static_cast<uint16_t>(tcp.fin) << std::endl;

	std::cout << header_ss.str();
}
void print_udphdr(const _udphdr &udp)
{
	std::ostringstream header_ss;

	header_ss << "\nUDP Header";
	header_ss << "\n\t|-Source Port: " << ntohs(udp.source);
	header_ss << "\n\t|-Destination Port: " << ntohs(udp.dest);
	header_ss << "\n\t|-UDP Length: " << ntohs(udp.len);
	header_ss << "\n\t|-UDP Checksum: 0x" << HEXW(ntohs(udp.check), 4) << std::endl;

	std::cout << header_ss.str();
}
void print_data(uint8_t *data, int len)
{
	puts("Data");
	for (int i = 0; i < len; i++)
	{
		if (i != 0 && i % 16 == 0)
		{
			putchar('\t');
			for (int j = i - 16; j < i; j++)
			{
				if (data[j] >= 32 && data[j] <= 128)
					printf("%c", (data[j])); // print data in ascii
				else
					putchar('.');
			}
			putchar('\n');
		}
		printf("%.2X", data[i]); // print hex data
	}
}