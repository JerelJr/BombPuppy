//TODO: *finish code for filtering flags
//      *add linux capabilities

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

#define BUFLEN 65536

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

short parse_args(int argc, char *const *argv)
{
	SnifferOptions args;
	char opt;
	while ((opt = getopt(argc, argv, "i:I:n:p:w:x:tu")) != EOF)
		switch (opt)
		{
		case 'i':
			// filter by source IP address
			strncpy(args.src_IP, optarg, sizeof(optarg));
			break;
		case 'I':
			// filter by destination IP address
			strncpy(args.dest_IP, optarg, sizeof(optarg));
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
				return -1;
			}
			break;
		case 'x':
			// filter by interface

			break;
		case 't':
			// capture tcp packets only
			args.p_filter = SnifferOptions::TCP;
			break;
		case 'u':
			// capture udp packets only
			args.p_filter = SnifferOptions::UDP;
			break;
		default:
			//std::cout << "Unrecognized argument: -" << opt << std::endl;
			break;
		}
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

int main(int argc, char *const *argv)
{
	int raw_soc;
	int rmng_data;
	int n_packets = -1, count = 0;
	char opt;
	ssize_t rcvd_len;
	unsigned char *buffer = new unsigned char[BUFLEN];
	unsigned char *data = NULL;
	struct sockaddr addr;
	struct sockaddr_in source, dest;
	socklen_t addr_len = sizeof(addr);
	unsigned short iphdrlen;

	while ((opt = getopt(argc, argv, "i:I:n:p:w:x:tu")) != EOF)
		switch (opt)
		{
		case 'i':
			// filter by source IP address

			break;
		case 'I':
			// filter by destination IP address

			break;
		case 'n':
			// capture n number of packets
			n_packets = atoi(optarg);
			break;
		case 'p':
			// filter by port number

			break;
		case 'w':
			// redirect output to a file
			if (!(freopen(optarg, "a", stdout)))
			{
				perror("Error opening write file: ");
				return -1;
			}
			break;
		case 'x':
			// filter by interface

			break;
		case 't':
			// capture tcp packets only

			break;
		case 'u':
			// capture udp packets only

			break;
		default:
			//std::cout << "Unrecognized argument: -" << opt << std::endl;
			break;
		}

	// open raw socket
	raw_soc = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (raw_soc < 0)
	{
		perror("Error creating socket: ");
		return -1;
	}

	time_t T = time(NULL);
	struct tm lt = *localtime(&T);
	printf("Capture started: %02d:%02d:%02d %02d/%02d/%04d", lt.tm_hour,
		   lt.tm_min, lt.tm_sec, lt.tm_mon + 1, lt.tm_mday, lt.tm_year + 1900);
	/* Capture loop */
	while (count != n_packets)
	{
		rmng_data = 0;
		// clear buffer
		memset(buffer, 0, BUFLEN);
		// receive packet
		rcvd_len = recvfrom(raw_soc, buffer, BUFLEN, 0,
							&addr, &addr_len);
		if (rcvd_len < 0)
		{
			perror("Error receiving data: ");
			return -1;
		}
		/* Open ethernet header and print */
		struct ethhdr *eth = (struct ethhdr *)(buffer);

		printf("\nEthernet Header\n");
		printf("\t|-Source Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
			   eth->h_source[0], eth->h_source[1], eth->h_source[2],
			   eth->h_source[3], eth->h_source[4], eth->h_source[5]);
		printf("\n\t|-Destination Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
			   eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
			   eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
		printf("\n\t|-Protocol: %d\n", eth->h_proto);

		/* Open IP header and print */
		struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
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

		iphdrlen = ip->ihl * 4;

		/* Determine transport layer protocol */
		switch (ip->protocol)
		{
		case 6:
		{
			/* Open TCP header and print */
			struct tcphdr *tcp = (struct tcphdr *)(buffer + iphdrlen +
												   sizeof(struct ethhdr));
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

			data = (buffer + iphdrlen + sizeof(struct ethhdr) +
					sizeof(struct tcphdr));
			rmng_data = rcvd_len - (iphdrlen + sizeof(struct ethhdr) +
									sizeof(struct tcphdr));
			break;
		}
		case 17:
		{
			/* Open UDP header and print */
			struct udphdr *udp = (struct udphdr *)(buffer + iphdrlen +
												   sizeof(struct ethhdr));
			printf("\nUDP Header\n");
			printf("\t|-Source Port: %d\n", ntohs(udp->source));
			printf("\t|-Destination Port: %d\n", ntohs(udp->dest));
			printf("\t|-UDP Length: %d\n", ntohs(udp->len));
			printf("\t|-UDP Checksum: %d\n", ntohs(udp->check));

			data = (buffer + iphdrlen + sizeof(struct ethhdr) +
					sizeof(struct udphdr));
			rmng_data = rcvd_len - (iphdrlen + sizeof(struct ethhdr) +
									sizeof(struct udphdr));
			break;
		}
		default:
			puts("Unrecognized transport protocol");
			break;
		}

		/* Print data */
		puts("Data");
		for (int i = 0; i < rmng_data; i++)
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
		putchar('\n');

		count++;
	}

	delete[] buffer;
	close(raw_soc);

	return 0;
}
