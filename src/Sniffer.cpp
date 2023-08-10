#include "../include/RawPacket.hpp"

#define BUFLEN 65535

int main(int argc, char *const *argv)
{
	int raw_soc;
	size_t rmng_data_len;
	uint32_t count = 0;
	size_t rcvd_len;
	std::vector<uint8_t> buffer(BUFLEN); // TODO:consider change to std::array
	uint8_t *data = NULL;
	struct sockaddr addr;
	socklen_t addr_len = sizeof(addr);

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
		// clear buffer
		memset(&buffer[0], 0, BUFLEN);
		// receive packet
		rcvd_len = recvfrom(raw_soc, &buffer[0], BUFLEN, 0,
							&addr, &addr_len);
		if (rcvd_len < 0)
		{
			perror("Error receiving data: ");
			return -1;
		}
		putchar('\n');

		// No clue why none of these resizing methods work without completely screwing up serialization
		// buffer.resize(rcvd_len);
		// buffer.erase(buffer.begin() + rcvd_len, buffer.end());
		// buffer.shrink_to_fit();

		RawPacket packet(buffer, rcvd_len);
		std::cout << packet.toString();

		count++;
	}

	close(raw_soc);

	return 0;
}
