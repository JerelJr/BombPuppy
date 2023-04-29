#include "../include/Packet.hpp"

#define BUFLEN 65535

int main(int argc, char *const *argv)
{
	int raw_soc;
	size_t rmng_data_len;
	uint32_t count = 0;
	ssize_t rcvd_len;
	uint8_t *buffer = new uint8_t[BUFLEN];
	uint8_t *data = NULL;
	struct sockaddr addr;
	socklen_t addr_len = sizeof(addr);
	uint16_t iphdrlen;

	SnifferOptions args = parse_args(argc, argv);

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
	while (count != args.n_packets)
	{
		rmng_data_len = 0;
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
		struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(buffer);

		ethhdr_to_str(*eth);

		/* Open IP header and print */
		struct iphdr *ip = reinterpret_cast<struct iphdr *>(buffer + sizeof(struct ethhdr));
		print_iphdr(*ip);

		iphdrlen = ip->ihl * 4;

		/* Determine transport layer protocol */
		switch (ip->protocol)
		{
			// TODO: DRY
		case protocol_filter::IGMP:
		{
			/* Open ICMP header and print */
			struct igmp *igmp = reinterpret_cast<struct igmp *>(buffer + iphdrlen +
																sizeof(struct ethhdr));
			print_igmphdr(*igmp);

			data = (buffer + sizeof(struct ethhdr) + iphdrlen +
					sizeof(struct icmphdr));
			rmng_data_len = rcvd_len - (sizeof(struct ethhdr) + iphdrlen +
										sizeof(struct igmp));
			break;
		}
		case protocol_filter::ICMP:
		{
			/* Open ICMP header and print */
			struct icmphdr *icmp = reinterpret_cast<struct icmphdr *>(buffer + iphdrlen +
																	  sizeof(struct ethhdr));
			print_icmphdr(*icmp);

			data = (buffer + sizeof(struct ethhdr) + iphdrlen +
					sizeof(struct icmphdr));
			rmng_data_len = rcvd_len - (sizeof(struct ethhdr) + iphdrlen +
										sizeof(struct icmphdr));
			break;
		}
		case protocol_filter::TCP:
		{
			/* Open TCP header and print */
			struct tcphdr *tcp = reinterpret_cast<struct tcphdr *>(buffer + iphdrlen +
																   sizeof(struct ethhdr));
			print_tcphdr(*tcp);

			data = (buffer + sizeof(struct ethhdr) + iphdrlen +
					sizeof(struct tcphdr));
			rmng_data_len = rcvd_len - (sizeof(struct ethhdr) + iphdrlen +
										sizeof(struct tcphdr));
			break;
		}
		case protocol_filter::UDP:
		{
			/* Open UDP header and print */
			struct udphdr *udp = reinterpret_cast<struct udphdr *>(buffer + iphdrlen +
																   sizeof(struct ethhdr));
			print_udphdr(*udp);

			data = (buffer + iphdrlen + sizeof(struct ethhdr) +
					sizeof(struct udphdr));
			rmng_data_len = rcvd_len - (iphdrlen + sizeof(struct ethhdr) +
										sizeof(struct udphdr));
			break;
		}
		default:
			puts("Unsupported transport protocol");
			break;
		}

		/* Print data */
		print_data(data, rmng_data_len);
		putchar('\n');

		count++;
	}

	delete[] buffer;
	close(raw_soc);

	return 0;
}
