#include "../include/Packet.hpp"

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
			strncpy(args.src_IP, optarg, strlen(optarg));
			break;
		case 'I':
			// filter by destination IP address
			strncpy(args.dest_IP, optarg, strlen(optarg));
			break;
		case 'n':
			// capture n number of packets
			args.n_packets = atoi(optarg);
			break;
		case 'p':
			// filter by port number
			args.port = (ushort)atoi(optarg);
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
			args.p_filter = SnifferOptions::TCP;
			break;
		case 'u':
			// display udp packets only
			args.p_filter = SnifferOptions::UDP;
			break;
		default:
			//std::cout << "Unrecognized argument: -" << opt << std::endl;
			break;
		}

	return args;
}

void print_ethhdr(struct ethhdr *eth)
{
	printf("\nEthernet Header\n");
	printf("\t|-Source Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
		   eth->h_source[0], eth->h_source[1], eth->h_source[2],
		   eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	printf("\n\t|-Destination Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
		   eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
		   eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	printf("\n\t|-Protocol: %d\n", eth->h_proto);
}
void print_iphdr(struct iphdr *ip)
{
	struct sockaddr_in source, dest;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->daddr;

	printf("\nIP Header\n");
	printf("\t-Version: %d\n", (unsigned int)ip->version);
	printf("\t-Internet Header Length: %d DWORDS or %d Bytes\n",
		   (unsigned int)ip->ihl, ((unsigned int)(ip->ihl)) * 4);
	printf("\t-Type of Service: %d\n", (unsigned int)ip->tos);
	printf("\t-Total Length: %d Bytes\n", ntohs(ip->tot_len));
	printf("\t-Identification: %d\n", ntohs(ip->id));
	printf("\t-Time to Live: %d\n", (unsigned int)ip->ttl);
	printf("\t-Protocol: %d\n", (unsigned int)ip->protocol);
	printf("\t-Header Checksum: %d\n", ntohs(ip->check));
	printf("\t-Source IP: %s\n", inet_ntoa(source.sin_addr));
	printf("\t-Destination IP: %s\n", inet_ntoa(dest.sin_addr));
}
void print_tcphdr(struct tcphdr *tcp)
{
	printf("\nTCP Header\n");
	printf("\t|-Source Port: %d\n", ntohs(tcp->source));
	printf("\t|-Destination Port: %d\n", ntohs(tcp->dest));
	printf("\t|-Sequence #: %d", ntohl(tcp->seq));
	printf("\t|-ACK #: %d", ntohl(tcp->ack_seq));
	printf("\n\t|-Doff: %d", (unsigned int)tcp->doff);
	printf("\n\t|-Reserved: %d", (unsigned int)tcp->res1);
	printf("\n\t|-Congestion Window Reduced: %d",
		   (unsigned int)tcp->cwr);
	printf("\n\t|-ECN-Echo: %d", (unsigned int)tcp->ece);
	printf("\n\t|-Urgent: %d", (unsigned int)tcp->urg);
	printf("\n\t|-Acknowledgement: %d", (unsigned int)tcp->ack);
	printf("\n\t|-Push: %d", (unsigned int)tcp->psh);
	printf("\n\t|-Reset: %d", (unsigned int)tcp->rst);
	printf("\n\t|-Syn: %d", (unsigned int)tcp->syn);
	printf("\n\t|-Fin: %d\n", (unsigned int)tcp->fin);
}
void print_udphdr(struct udphdr *udp)
{
	printf("\nUDP Header\n");
	printf("\t|-Source Port: %d\n", ntohs(udp->source));
	printf("\t|-Destination Port: %d\n", ntohs(udp->dest));
	printf("\t|-UDP Length: %d\n", ntohs(udp->len));
	printf("\t|-UDP Checksum: %d\n", ntohs(udp->check));
}
void print_data(unsigned char *data, int len)
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
						printf("%c", (unsigned char)data[j]); //print data in ascii
					else
						putchar('.');
				}
				putchar('\n');
			}
			printf("%.2X", data[i]); //print hex data
		}
}