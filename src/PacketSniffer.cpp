#include "../include/Packet.hpp"

#define BUFLEN 65536


int main(int argc, char *const *argv)
{
	int raw_soc;
	int rmng_data;
	int count = 0;
	ssize_t rcvd_len;
	unsigned char *buffer = new unsigned char[BUFLEN];
	unsigned char *data = NULL;
	struct sockaddr addr;
	socklen_t addr_len = sizeof(addr);
	unsigned short iphdrlen;

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

		print_ethhdr(eth);

		/* Open IP header and print */
		struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
		print_iphdr(ip);

		iphdrlen = ip->ihl * 4;

		/* Determine transport layer protocol */
		switch (ip->protocol)
		{
		case 6:
		{
			/* Open TCP header and print */
			struct tcphdr *tcp = (struct tcphdr *)(buffer + iphdrlen +
												   sizeof(struct ethhdr));
			print_tcphdr(tcp);

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
			print_udphdr(udp);

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
		print_data(data, rmng_data);
		putchar('\n');

		count++;
	}

	delete[] buffer;
	close(raw_soc);

	return 0;
}
