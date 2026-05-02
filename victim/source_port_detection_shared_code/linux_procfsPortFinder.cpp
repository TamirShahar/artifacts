// faster version using read instead of fgets

#include "procfsPortFinder.h"
#include <cstdio>  // for FILE*, fopen, fclose, rewind, fgets
#include <cstdlib> // for exit, EXIT_FAILURE
#include <cstring> // for sscanf
#include <unistd.h>
#include <fcntl.h>
#include <sstream>
#include <fstream>
#include <iostream>
#include <string>
static int last_packet = 0;
long long get_real_time_ns()
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

ProcfsPortsFinder::ProcfsPortsFinder(int protocol, bool ipv6) : PortFinderBase(protocol)
{
	const char *proc_file = (protocol_ == PROTOCOL_TCP) ? (ipv6 ? PROC_NET_TCP6 : PROC_NET_TCP) : PROC_NET_UDP;
	fp_ = open(proc_file, O_RDONLY);

	if (fp_ < 0)
	// fp_ = fopen(proc_file,"rb");
	// if (fp_==nullptr)
	{
		perror("Failed to open proc file");
		exit(EXIT_FAILURE);
	}
	init();
}

void ProcfsPortsFinder::updatePortsImpl()
{

	/////////////////////////////////////
	if (protocol_ == PROTOCOL_TCP)
	{

		// read /proc/net/snmp read 9 columns and print its value
		const int LINE_SIZE = 512;
		const int MAX_COLUMNS = 20;
		FILE *f = fopen("/proc/net/snmp", "r");
		if (!f)
		{
			perror("fopen");
			return;
		}

		char line[LINE_SIZE];
		char tcp_labels[LINE_SIZE] = {0};
		char tcp_values[LINE_SIZE] = {0};

		while (fgets(line, sizeof(line), f))
		{
			// Look for the line starting with "Tcp:"
			if (strncmp(line, "Tcp:", 4) == 0)
			{
				// If tcp_labels is empty, store labels; otherwise store values
				if (tcp_labels[0] == '\0')
				{
					strncpy(tcp_labels, line + 4, LINE_SIZE - 1); // skip "Tcp:"
				}
				else
				{
					strncpy(tcp_values, line + 4, LINE_SIZE - 1);
					break; // got labels and values
				}
			}
		}
		fclose(f);

		if (tcp_labels[0] == '\0' || tcp_values[0] == '\0')
		{
			printf("Tcp data not found\n");
			return;
		}

		// Tokenize both lines to get first 9 columns
		char *label_tokens[MAX_COLUMNS];
		char *value_tokens[MAX_COLUMNS];

		int i = 0;
		char *tok = strtok(tcp_labels, " \t\n");
		while (tok && i < MAX_COLUMNS)
		{
			label_tokens[i++] = tok;
			tok = strtok(NULL, " \t\n");
		}
		int label_count = i;

		i = 0;
		tok = strtok(tcp_values, " \t\n");
		while (tok && i < MAX_COLUMNS)
		{
			value_tokens[i++] = tok;
			tok = strtok(NULL, " \t\n");
		}
		int value_count = i;

		int columns_to_print = label_count < value_count ? label_count : value_count;
		if (columns_to_print > 9)
			columns_to_print = 9;

		// int currEstablished = atoi(value_tokens[4]); // this is the ActiveOpens column
		int currEstablished = atoi(value_tokens[4]); // this is the ActiveOpens column
		/////////////////////////////////////////////////////////////
		if (currEstablished == last_number_of_established_)
		{
			return;
		}
		// printf("snmp new connection!\n");
		last_number_of_established_ = currEstablished;
		last_timestamp_ = get_real_time_ns();
	}
	/////////////////////////////////////////////////////////////

	if (fp_ < 0)
	// if (fp_==nullptr)
	{
		printf("ERROR: File pointer is null in updatePortsImpl!\n");
		exit(EXIT_FAILURE);
	}

	// Initialize all ports to "free" (0)
	for (int i = 0; i < TOTAL_PORTS; i++)
	{
		current_status[i] = 0;
	}

	char buf[2000];

	//     rewind(fp_);
	int ret = lseek(fp_, 0, SEEK_SET);
	if (ret < 0)
	{
		perror("lseek failed");
		exit(EXIT_FAILURE);
	}

	// loop to read all procfs content
	int n = 0, chunk = 0;
	chunk = read(fp_, buf, sizeof(buf));
	n += chunk;

	if (n < 0)
	{
		perror("read");
		exit(0);
	}
	else
	{
		// std::cout<<buf<<std::endl;
		// std::cout << n << std::endl;
	}

	for (char *line_start = (char *)memchr(buf, '\n', n); line_start != NULL; line_start = (char *)memchr(line_start, '\n', buf - line_start + n))
	{
		line_start++; // skip the LF
		if (line_start >= buf + n)
		{
			break; // We're done
		}
		char *colon1 = (char *)memchr(line_start, ':', buf + n - line_start);
		if (colon1 == NULL)
		{
			printf("Parsing error - missing first colon in the line\n");
			exit(0);
		}
		char *colon2 = (char *)memchr(colon1 + 1, ':', buf + n - (colon1 + 1));
		if (colon2 == NULL)
		{
			printf("Parsing error - missing second colon in the line\n");
			exit(0);
		}
		int hexnum = 0;
		for (char *p = colon2 + 1; p < (colon2 + 1) + 4; p++)
		{
			if (isdigit(*p))
			{
				hexnum = (hexnum << 4) + ((*p) - '0');
			}
			else if (((*p) >= 'A') && ((*p) <= 'F'))
			{
				hexnum = (hexnum << 4) + ((*p) - 'A' + 10);
			}
			else
			{
				printf("Expecting hex digit, got '%c'\n", *p);
				exit(0);
			}
		}
		current_status[hexnum] = 1;
	}
}

ProcfsPortsFinder::~ProcfsPortsFinder()
{
	if (fp_ > 0)
	{
		close(fp_);
		// fclose(fp_);
	}
}