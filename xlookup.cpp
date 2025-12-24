/*
 * xlookup.cpp | Microsoft nslookup analog
 * Copyright © xromza 2025
 */

#include <iostream>
#include <cstdint>
#include <vector>
#include <cstdio>
#include <map>
#include <sstream>
#include <string>
#include <string.h>
#include <string_view>
#include <regex>
#include <cmath>
#ifdef _WIN32
#include <WinSock2.h>
constexpr const char locale[] = "Russian";
#include <WS2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
constexpr const char locale[] = "ru_RU";
typedef int SOCKET;
#endif

using std::cerr;
using std::cout;
using std::map;
using std::string;
using std::string_view;
using std::stringstream;

#include <iostream>
#include <iomanip>
#include <cstdint>

constexpr int BUF_SIZE = 1024;

void printError(const char *msg)
{
#ifdef _WIN32
	cerr << msg << WSAGetLastError() << '\n';
#else
	std::perror(msg);
#endif
}
void cleanup()
{
#ifdef _WIN32
	WSACleanup();
#endif
}
void cleanup(SOCKET s)
{
#ifdef _WIN32
	closesocket(s);
#else
	close(s);
#endif
	cleanup();
}

const map<uint8_t, char> m = {
	{10, 'A'},
	{11, 'B'},
	{12, 'C'},
	{13, 'D'},
	{14, 'E'},
	{15, 'F'}
};

const map<uint16_t, string> dns_types = {
	{0x0001, "A"},
	{0x001C, "AAAA"},
	{0x0005, "CNAME"},
	{0x000F, "MX"},
	{0x0002, "NS"}
};

const map<uint8_t, string> rCode_values = {
	{0x00, "No error"},
	{0x01, "Format error"},
	{0x02, "Server failure"},
	{0x03, "NXDOMAIN Name error"},
	{0x04, "Not implemented"},
	{0x05, "Refused"}
};

char static resNum(unsigned int num)
{
	if (num < 10)
		return '0' + num;
	else
		return m.at(num);
}

string make_help_screen()
{
	size_t margin_arg = 4;
	size_t gap_arg_desc = 8;
	const char label[] = "Creates a request to the DNS server to resolve the specified domain name";
	const char syntax[] = "xlookup domain_name [-d dns_address[:dns_port] | [--dns dns_address[:dns_port]]] [-h | --help]";
	map<string_view, string_view> args = {
		{"domain_name", "domain name for resolving (e.g. example.com)"},
		{"-d,--dns ADDR[:PORT]", "Specify custom DNS address (default: 8.8.8.8:53)"},
		{"-h, --help", "Prints this help message"}};
	size_t maxmargin = 0;
	for (const auto &[arg, desc] : args)
		maxmargin = std::max(arg.size(), maxmargin);
	stringstream message;
	message << label << "\r\n\r\n"
			<< syntax << "\r\n\r\n";
	for (const auto &[arg, desc] : args)
	{
		message << string(margin_arg, ' ')
				<< arg
				<< string(gap_arg_desc + maxmargin - arg.size(), ' ')
				<< desc << "\r\n";
	}
	return message.str();
}

std::regex ip_port("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-3][0-5])$");
std::regex ip_not_port("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
string static parse_dns_name(const uint8_t *packet, size_t &offset, size_t max_len)
{
	string name;
	size_t current = offset;
	bool jumped = false;
	size_t stop_offset = 0;
	int hops = 0;

	while (hops < 5)
	{
		if (current >= max_len)
			break;

		uint8_t len = packet[current];

		if ((len & 0xC0) == 0xC0)
		{
			if (current + 1 >= max_len)
				break;

			if (!jumped)
			{
				stop_offset = current + 2;
				jumped = true;
			}

			uint16_t ptr = ((len & 0x3F) << 8) | packet[current + 1];

			current = ptr;
			hops++;
			continue;
		}

		if (len == 0)
		{
			if (!jumped)
			{
				stop_offset = current + 1;
			}
			break;
		}

		if (current + 1 + len > max_len)
			break;

		if (!name.empty())
			name += ".";
		for (int i = 0; i < len; ++i)
		{
			name += (char)packet[current + 1 + i];
		}
		current += 1 + len;
	}

	offset = stop_offset;

	return name;
}

struct
{
	string dns = "8.8.8.8";
	int dns_port = 53;
	string domain;
} args;

int main(int argc, char **argv)
{
	int position = 0;
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dns") == 0)
		{
			if (i + 1 >= argc)
			{
				cout << "DNS flag is here, but not specified. Fallback to 8.8.8.8:53";
			}
			else
			{
				string tempdns = argv[i + 1];
				if (std::regex_match(tempdns.data(), ip_port))
				{
					size_t splitter = tempdns.find(":");
					args.dns = tempdns.substr(0, splitter);
					args.dns_port = std::stoi(tempdns.substr(splitter + 1));
				}
				else if (std::regex_match(tempdns, ip_not_port))
				{
					cout << "DNS port is not specified. Using standard port " << args.dns_port;
					args.dns = argv[i + 1];
				}
				else
				{
					cout << "DNS input is invalid. Fallback to " << args.dns << ':' << args.dns_port;
				}
				i++;
				continue;
			}
		}
		else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
		{

			cout << make_help_screen();
			return 0;
		}
		else if (argv[i][0] != '-')
		{
			switch (position)
			{
			case 0:
				args.domain = argv[i];
				break;
			default:
				cout << "Unknown positional argument: " << argv[i] << '\n';
			}
			position++;
		}
		if (position == 0)
		{
			cout << "Not enought arguments: domain";
			return -1;
		}
	}
	if (args.domain.empty())
	{
		cerr << "Not enough arguments: domain\r\n";
		return -1;
	}
	setlocale(LC_ALL, locale);
#ifdef _WIN32
	WSADATA wsaData;
	{
		int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult)
		{
			cout << "Startup error: " << iResult;
			return -1;
		}
	}
#endif
	SOCKET s;
	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == -1)
	{
		printError("Socket init error: ");
		cleanup();
		return -1;
	}
	struct sockaddr_in local_sai = {};
	local_sai.sin_family = AF_INET;
	local_sai.sin_addr.s_addr = INADDR_ANY;
	local_sai.sin_port = htons(0);
	{
		int iResult = bind(s, (const sockaddr *)&local_sai, sizeof(local_sai));
		if (iResult)
		{
			cout << "bind error: " << iResult;
			cleanup(s);
			return -1;
		}
	}

	uint16_t id = htons(static_cast<uint16_t>(rand()));
	uint16_t flags = htons(0x0100);
	uint16_t qdcount = htons(1);
	uint16_t ancount = 0;
	uint16_t nscount = 0;
	uint16_t arcount = 0;

	std::vector<uint8_t> qname = {};
	size_t spl = args.domain.find(".");
	size_t spl_prev = -1;
	while (spl != string::npos)
	{
		string dom = args.domain.substr(spl_prev + 1, spl - spl_prev - 1);
		qname.push_back(dom.size());
		for (char c : dom)
			qname.push_back(c);
		spl_prev = spl;
		spl = args.domain.find(".", spl + 1);
	}
	string dom = args.domain.substr(spl_prev + 1);
	qname.push_back(dom.size());
	for (char c : dom)
	{
		qname.push_back(c);
	}
	qname.push_back(0);
	uint16_t qtype = htons(0x01);
	uint16_t qclass = htons(0x01);

	std::vector<uint8_t> packet;
	packet.resize(12 + qname.size() + 4);
	size_t offset = 0;
	memcpy(&packet[offset], &id, 2);
	offset += 2;
	memcpy(&packet[offset], &flags, 2);
	offset += 2;
	memcpy(&packet[offset], &qdcount, 2);
	offset += 2;
	memcpy(&packet[offset], &ancount, 2);
	offset += 2;
	memcpy(&packet[offset], &nscount, 2);
	offset += 2;
	memcpy(&packet[offset], &arcount, 2);
	offset += 2;

	memcpy(&packet[offset], qname.data(), qname.size());
	offset += qname.size();
	memcpy(&packet[offset], &qtype, 2);
	offset += 2;
	memcpy(&packet[offset], &qclass, 2);

	cout << '\n';
	struct sockaddr_in dns_server = {};
	int dns_size = sizeof(dns_server);
	inet_pton(AF_INET, args.dns.c_str(), &(dns_server.sin_addr));
	dns_server.sin_family = AF_INET;
	dns_server.sin_port = htons(args.dns_port);
	{
		int iResult = sendto(s, (const char *)packet.data(), packet.size(), 0, (sockaddr *)&dns_server, sizeof(dns_server));
		if (iResult == -1)
		{
			printError("Sendto() error: ");
			cleanup(s);
			return -1;
		}
		cout << "Sended " << iResult << " bytes to resolve the domain name " << args.domain << " to DNS " << args.dns << ":" << args.dns_port << "...\n\n";

	}
	uint8_t response[BUF_SIZE] = {};
	int n = recvfrom(s, (char *)&response, BUF_SIZE - 1, 0, (sockaddr *)&dns_server, (unsigned int *)&dns_size);
	if (n < 0)
	{
		printError("recvfrom() error: ");
		cleanup(s);
		return -1;
	}
	std::printf("Received %d bytes from %s:%d\n", n, args.dns.c_str(), args.dns_port);

	// parsing
	offset = 2;
	uint16_t flags_net, flags_resp;
	memcpy(&flags_net, &response[offset], 2); flags_resp = ntohs(flags_net);
	uint8_t rCode = flags_resp & 0xF;
	if (rCode != 0x00) {
		cerr << "Error: " << rCode_values.at(rCode) << "\r\n\r\n"; 
		cleanup(s);
		return -1;
	}
	offset += 10;
	string ans_qname = parse_dns_name(response, offset, n);
	offset += 4;
	string ans_name = parse_dns_name(response, offset, n);
	if (offset + 10 > sizeof(response))
	{
		cout << "not enough data to parse\n";
		return -1;
	}
	uint16_t type_net, type;
	memcpy(&type_net, &response[offset], 2);
	offset += 2;
	type = ntohs(type_net);
	uint16_t dns_class_net, dns_class;
	memcpy(&dns_class_net, &response[offset], 2);
	offset += 2;
	dns_class = ntohs(dns_class_net);
	uint32_t ttl_net, ttl;
	memcpy(&ttl_net, &response[offset], 4);
	offset += 4;
	ttl = ntohl(ttl_net);
	uint16_t rdlen_net, rdlen;
	memcpy(&rdlen_net, &response[offset], 2);
	offset += 2;
	rdlen = ntohs(rdlen_net);
	stringstream info;
	
	info << "\n\nResponse\n===============" << "\nName:       " << ans_name << "\nType:       " << dns_types.at(type) << "\nClass:      " << (dns_class == 0x0001 ? "IN" : "Unknown")
		 << "\nTTL:        " << ttl << "\nRD Length:  " << rdlen << "\nIP-address: ";
	switch (type)
	{
	case (0x01):
	{
		info << (int)response[offset] << "."
			 << (int)response[offset + 1] << "."
			 << (int)response[offset + 2] << "."
			 << (int)response[offset + 3];
		break;
	}
	default:
		info << "Unknown";
	}
	cout << info.str() << "\r\n\r\n";
	cleanup(s);
	return 0;
}
