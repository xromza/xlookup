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
#include <algorithm>
#include <vector>
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
using std::pair;
using std::map;
using std::string;
using std::string_view;
using std::stringstream;
using std::vector;

#include <iostream>
#include <iomanip>
#include <cstdint>

constexpr int BUF_SIZE = 1024;

void printHex(const uint8_t* data, size_t size)
{
	std::ios_base::fmtflags originalFlags = std::cout.flags(); // сохраняем флаги потока

	for (size_t i = 0; i < size; ++i)
	{
		if (i > 0)
			std::cout << ' ';
		std::cout << std::uppercase << std::setfill('0') << std::setw(2) << std::hex
			<< static_cast<int>(data[i]);
	}
	std::cout << std::dec << std::endl; // возвращаем в десятичный режим и новая строка

	std::cout.flags(originalFlags); // восстанавливаем исходные флаги (опционально, но аккуратно)
}

void printError(const char* msg)
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

enum DNS_TYPES
{
	A = 0x0001,
	AAAA = 0x001C,
	CNAME = 0x0005,
	MX = 0x000F,
	NS = 0x0002
};

const map<uint16_t, string> dns_types = {
	{0x0001, "A"},
	{0x001C, "AAAA"},
	{0x0005, "CNAME"},
	{0x000F, "MX"},
	{0x0002, "NS"} };
const map<string, uint16_t> input_dns_types = {
	{"A", 0x0001},
	{"AAAA", 0x001C},
	{"CNAME", 0x0005},
	{"MX", 0x000F},
	{"NS", 0x0002} };
const map<uint8_t, string> rCode_values = {
	{0x00, "No error"},
	{0x01, "Format error"},
	{0x02, "Server failure"},
	{0x03, "NXDOMAIN Name error"},
	{0x04, "Not implemented"},
	{0x05, "Refused"} };

vector<string> ipv4s;
vector<string> cnames;
vector<pair<uint16_t, string>> mxs;

void printAll(bool& AA, string& ans_qname, uint16_t& type, uint16_t& dns_class, uint32_t& ttl, uint16_t& rdlen, uint16_t& ANCOUNT)
{
	stringstream info;
	info << "\n\n"
		<< ((AA) ? ("Authoritative") : ("Non-authoritative")) << " response\n===============" << "\nName:       " << ans_qname << "\nClass:      " << (dns_class == 0x0001 ? "IN" : "Unknown")
		<< "\nTTL:        " << ttl << "\nRD Length:  " << rdlen << "\nANCOUNT:    " << ANCOUNT << "\n\n";

	if (!cnames.empty())
	{
		info << "Canonical names: \n\n"
			<< ans_qname << " -> " << cnames[0] << '\n';
		for (vector<string>::iterator i = cnames.begin() + 1; i < cnames.end(); i++)
		{
			info << *(i - 1) << " -> " << *i << '\n';
		}
		info << '\n';
	}
	if (!mxs.empty())
	{
		std::sort(mxs.begin(), mxs.end());
		info << "Mail Exchange: \n\n"
			<< "Priority " << " Host\n";
		for (auto& [priority, mail] : mxs) {
			string priorityStr = std::to_string(priority);
			priorityStr.resize(10, ' ');
			info << priorityStr << mail << '\n';
		}
		info << '\n';
	}
	if (!ipv4s.empty())
	{
		info << "IPv4 addresses" << (cnames.empty() ? "" : " for " + cnames.back()) << ": \n\n";
		for (auto& ip : ipv4s)
		{
			info << ip << '\n';
		}
		info << '\n';
	}
	cout << info.str() << '\n';
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
		{"-h, --help", "Prints this help message"} };
	size_t maxmargin = 0;
	for (const auto& [arg, desc] : args)
		maxmargin = (((arg.size()) > (maxmargin)) ? (arg.size()) : (maxmargin));
	stringstream message;
	message << label << "\r\n\r\n"
		<< syntax << "\r\n\r\n";
	for (const auto& [arg, desc] : args)
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
string static parse_dns_name(const uint8_t* packet, size_t& offset, size_t max_len)
{
	string name;
	size_t current = offset;
	bool jumped = false;
	size_t stop_offset = offset;
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
	uint16_t type = A;
} args;

int main(int argc, char** argv)
{
	int position = 0;
	for (int i = 1; i < argc; i++)
	{
		string_view arg(argv[i]);
		if (arg == "-d" || arg == "--dns")
		{
			if (i + 1 >= argc)
				cerr << "\"--dns\" flag is here, but not specified. Fallback to 8.8.8.8:53";
			else
			{
				string tempdns = argv[i + 1];
				if (std::regex_match(tempdns.data(), ip_port))
				{
					size_t splitter = tempdns.find(":");
					args.dns = tempdns.substr(0, splitter);
					args.dns_port = std::stoi(tempdns.substr(splitter + 1));
					i++;
				}
				else if (std::regex_match(tempdns, ip_not_port))
				{
					cout << "DNS port is not specified. Using standard port " << args.dns_port << '\n';
					args.dns = argv[i + 1];
					i++;
				}
				else
				{
					cout << "DNS input is invalid. Fallback to " << args.dns << ':' << args.dns_port << '\n';
				}

				continue;
			}
		}
		else if (arg == "-h" || arg == "--help")
		{
			cout << make_help_screen() << '\n';
			return 0;
		}
		else if (arg == "-t" || arg == "--type")
		{
			if (i + 1 >= argc)
			{
				cerr << "\"--type\" flag is here, but not specified. Fallback to A type\n";
			}
			else
			{
				string type = argv[i + 1];
				if (input_dns_types.find(type) == input_dns_types.end())
				{
					cerr << "Specified unknown DNS type \"" << type << "\". Fallback to A type\n";
					i++;
				}
				else
				{
					args.type = input_dns_types.at(type);
					i++;
				}
				cout << args.type;
			}
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
		else
		{
			cerr << "Unknown flag \"" << argv[i] << "\" Use xlookup -h or xlookup --help for help. Skipping..." << '\n';
		}
	}
	if (position == 0)
	{
		cout << "Not enough arguments: domain_name2@\n";
		return -1;
	}
	if (args.domain.empty())
	{
		cerr << "Not enough arguments: domain_name2!\r\n";
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
		int iResult = bind(s, (const sockaddr*)&local_sai, sizeof(local_sai));
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
	cout << "args.type = " << args.type;
	uint16_t qtype = htons(args.type);
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
	#ifdef _WIN32
	int dns_size;
#else
	unsigned int dns_size;
#endif
	dns_size = sizeof(dns_server);
	inet_pton(AF_INET, args.dns.c_str(), &(dns_server.sin_addr));
	dns_server.sin_family = AF_INET;
	dns_server.sin_port = htons(args.dns_port);
	{
		int iResult = sendto(s, (const char*)packet.data(), packet.size(), 0, (sockaddr*)&dns_server, sizeof(dns_server));
		if (iResult == -1)
		{
			printError("Sendto() error: ");
			cleanup(s);
			return -1;
		}
		cout << "Sended " << iResult << " bytes to resolve the domain name " << args.domain << " to DNS " << args.dns << ":" << args.dns_port << "...\n\n";
	}
	uint8_t response[BUF_SIZE] = {};
	int n = recvfrom(s, (char*)&response, BUF_SIZE - 1, 0, (sockaddr*)&dns_server, &dns_size);
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
	memcpy(&flags_net, &response[offset], 2);
	flags_resp = ntohs(flags_net);
	uint8_t rCode = flags_resp & 0xF;
	if (rCode != 0x00)
	{
		cerr << "Error: " << rCode_values.at(rCode) << "\r\n\r\n";
		cleanup(s);
		return -1;
	}
	bool AA = (flags_resp & 0x400) != 0;
	offset += 4;
	printHex(response, n);
	uint16_t ANCOUNT_net, ANCOUNT_resp;
	memcpy(&ANCOUNT_net, &response[6], 2);
	ANCOUNT_resp = ntohs(ANCOUNT_net);
	offset += 6;
	string ans_qname = parse_dns_name(response, offset, n);
	offset += 4;
	stringstream info;
	string ans_name;
	uint16_t type, dns_class, rdlen;
	uint32_t ttl;
	for (int i = 0; i < ANCOUNT_resp; i++)
	{
		ans_name = parse_dns_name(response, offset, n);
		if (offset + 10 > sizeof(response))
		{
			cout << "not enough data to parse\n";
			return -1;
		}
		uint16_t type_net;
		memcpy(&type_net, &response[offset], 2);
		offset += 2;
		type = ntohs(type_net);
		uint16_t dns_class_net;
		memcpy(&dns_class_net, &response[offset], 2);
		offset += 2;
		dns_class = ntohs(dns_class_net);
		uint32_t ttl_net;
		memcpy(&ttl_net, &response[offset], 4);
		offset += 4;
		ttl = ntohl(ttl_net);
		uint16_t rdlen_net;
		memcpy(&rdlen_net, &response[offset], 2);
		offset += 2;
		rdlen = ntohs(rdlen_net);
		switch (type)
		{
		case (A):
		{
			stringstream ipv4;

			ipv4 << (int)response[offset] << "."
				<< (int)response[offset + 1] << "."
				<< (int)response[offset + 2] << "."
				<< (int)response[offset + 3];
			ipv4s.push_back(ipv4.str());
			offset += 4;
			break;
		}
		case (CNAME):
		{
			cnames.push_back(parse_dns_name(response, offset, n));
			break;
		}
		case (MX): {
			if (rdlen < 2) {
				offset += rdlen;
				break;
			}
			uint16_t priority = ntohs(*(uint16_t*)&response[offset]);
			offset += 2;
			std::pair<uint16_t, string> mail_server = std::make_pair(priority, parse_dns_name(response, offset, n));
			mxs.push_back(mail_server);
			break;
		}
		default:
			info << "Unknown type \"" << type << "\"\n";
			offset += rdlen;
		}
	}
	printAll(AA, ans_qname, type, dns_class, ttl, rdlen, ANCOUNT_resp);
	cleanup(s);
	return 0;
}
