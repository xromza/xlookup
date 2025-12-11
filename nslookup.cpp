#include <iostream>
#include <cstdint>
#include <vector>
#include <map>
#include <WinSock2.h>
#include <sstream>
#include <WS2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#include <random>
#define BUF_SIZE 1024

const std::map <uint8_t, char> m = {
	{10, 'A'},
	{11, 'B'},
	{12, 'C'},
	{13, 'D'},
	{14, 'E'},
	{15, 'F'}
};

const std::map <uint8_t, std::string> dns_types = {
	{0x01, "A"},
	{0x1C, "AAAA"},
	{0x05, "CNAME"},
	{0x0F, "MX"},
	{0x02, "NS"}
};

char resNum(unsigned int num) {
	if (num < 10) return '0' + num;
	else return m.at(num);
}

std::string parse_dns_name(const uint8_t* packet, size_t& offset, size_t max_len) {
	std::string name;
	size_t current = offset; // Используем локальный курсор, чтобы не ломать offset из main при прыжках
	bool jumped = false;     // Флаг: переходили ли мы по ссылке?
	size_t stop_offset = 0;  // Позиция, которую мы вернем в main (куда сдвинуть курсор)
	int hops = 0;

	while (hops < 5) { // Защита от зацикливания
		if (current >= max_len) break;

		uint8_t len = packet[current];

		// 1. Сжатая ссылка (начинается с 11xxxxxx, т.е. >= 0xC0)
		if ((len & 0xC0) == 0xC0) {
			if (current + 1 >= max_len) break;

			// Если мы встретили ссылку впервые, то реальный сдвиг курсора в main
			// должен быть только на 2 байта (размер самой ссылки),
			// независимо от того, насколько длинное имя, на которое она указывает.
			if (!jumped) {
				stop_offset = current + 2;
				jumped = true;
			}

			uint16_t ptr = ((len & 0x3F) << 8) | packet[current + 1];

			// Прыгаем по ссылке
			current = ptr;
			hops++;
			continue;
		}

		// 2. Конец имени
		if (len == 0) {
			// Если мы никуда не прыгали, то курсор в main должен встать сразу после этого нуля
			if (!jumped) {
				stop_offset = current + 1;
			}
			break;
		}

		// 3. Обычная метка
		if (current + 1 + len > max_len) break;

		if (!name.empty()) name += ".";
		for (int i = 0; i < len; ++i) {
			name += (char)packet[current + 1 + i];
		}
		current += 1 + len;
	}

	// Возвращаем обновленный offset
	offset = stop_offset;

	return name;
}

std::string itoh(unsigned int num) {
	std::string temp = "";
	while (num > 0) {
		temp = resNum(num % 16) + temp;
		num /= 16;
	}
	while (temp.size() != 2) temp = "0" + temp;
	return temp;
}

int main() {
	setlocale(LC_ALL, "Russian");
	WSADATA wsaData;
	{
		int iResult = WSAStartup(0x202, &wsaData);
		if (iResult) {
			std::cerr << "Startup error: " << iResult;
			return -1;
		}
	}
	SOCKET s;
	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET) {
		std::cerr << "Socket init error: " << WSAGetLastError();
		WSACleanup();
		return -1;
	}
	struct sockaddr_in local_sai = {};
	local_sai.sin_family = AF_INET;
	local_sai.sin_addr.s_addr = INADDR_ANY;
	local_sai.sin_port = htons(0);
	{
		int iResult = bind(s, (const sockaddr*)&local_sai, sizeof(local_sai));
		if (iResult) {
			std::cerr << "bind error: " << iResult;
			closesocket(s);
			WSACleanup();
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
	std::string domain;
	std::cin >> domain;
	size_t spl = domain.find(".");
	std::string dom = domain.substr(0, spl);
	std::string ras = domain.substr(spl + 1);
	qname.push_back(dom.size());
	for (char c : dom) {
		qname.push_back(c);
	}
	qname.push_back(ras.size());
	for (char c : ras) qname.push_back(c);
	qname.push_back(0);
	uint16_t qtype = htons(0x01);
	uint16_t qclass = htons(0x01);

	std::vector<uint8_t> packet;
	packet.resize(12 + qname.size() + 4);
	size_t offset = 0;
	memcpy(&packet[offset], &id, 2); offset += 2;
	memcpy(&packet[offset], &flags, 2); offset += 2;
	memcpy(&packet[offset], &qdcount, 2); offset += 2;
	memcpy(&packet[offset], &ancount, 2); offset += 2;
	memcpy(&packet[offset], &nscount, 2); offset += 2;
	memcpy(&packet[offset], &arcount, 2); offset += 2;

	memcpy(&packet[offset], qname.data(), qname.size()); offset += qname.size();
	memcpy(&packet[offset], &qtype, 2); offset += 2;
	memcpy(&packet[offset], &qclass, 2);
	std::cout << "Сформировал запрос к DNS-серверу: ";
	for (uint8_t i : packet) {
		std::cout << itoh(i) << ' ';
	}
	std::cout << '\n';

	struct sockaddr_in dns_server = {};
	int dns_size = sizeof(dns_server);
	inet_pton(AF_INET, "77.88.8.8", &(dns_server.sin_addr));
	dns_server.sin_family = AF_INET;
	dns_server.sin_port = htons(53);
	
	{
		int iResult = sendto(s, (const char*)packet.data(), packet.size(), 0, (sockaddr*)&dns_server, sizeof(dns_server));
		if (iResult == -1) {
			std::cerr << "sendto error: " << WSAGetLastError();
			closesocket(s);
			WSACleanup();
			return -1;
		}
		std::cout << "Отправил запрос (" << iResult << " bytes) на разрешение имени " << domain << " серверу 77.88.8.8:53...\n\n";
	}
	uint8_t response[BUF_SIZE];
	int n = recvfrom(s, (char*)&response, BUF_SIZE - 1, 0, (sockaddr*)&dns_server, &dns_size);
	std::cout << n;
	if (n < 0) {
		std::cerr << "Recvfrom error: " << WSAGetLastError();
		closesocket(s);
		WSACleanup();
		return -1;
	}
	std::printf("Received (%d bytes): ", n);
	for (int i = 0; i < n; i++) {
		std::cout << itoh(response[i]) << ' ';
	}

	// parsing

	offset = 12;
	std::string ans_qname = parse_dns_name(response, offset, n);
	std::cout << "After ans_qname: " << offset << "\n";
	offset += 4;
	std::string ans_name = parse_dns_name(response, offset, n);
	if (offset + 10 > sizeof(response)) {
		std::cerr << "not enough data to parse\n";
		return -1;
	}
	
	uint16_t type_net, type;
	std::cout << "Before memcpy type_net" << offset << "\n";
	memcpy(&type_net, &response[offset], 2); offset += 2; type = ntohs(type_net);
	uint16_t dns_class_net, dns_class;
	std::cout << "Before memcpy dns_class_net" << offset << "\n";
	memcpy(&dns_class_net, &response[offset], 2); offset += 2; dns_class = ntohs(dns_class_net);
	std::cout << "Before ttl_net" << offset << "\n";
	uint32_t ttl_net, ttl;
	memcpy(&ttl_net, &response[offset], 4); offset += 4; ttl = ntohl(ttl_net);
	std::cout << "Before rdlen" << offset << "\n";
	uint16_t rdlen_net, rdlen;
	memcpy(&rdlen_net, &response[offset], 2); offset += 2; rdlen = ntohs(rdlen_net);
	std::stringstream info;
	info << "Response\n===============\nType: " << (type == 1 ? "A" : std::to_string(type)) << "\nClass: " << (dns_class == 0x0001 ? "IN" : "Unknown")
		<< "\nTTL: " << ttl << "\nRD Length: " << rdlen << "\nIP-address: ";
	switch (type) {
	case (0x01):
		{
		std::cout << "вычисляем ip: " << offset << "\n";
		info << (int)response[offset] << "."
		<< (int)response[offset+1] << "."
		<< (int)response[offset+2] << "."
		<< (int)response[offset+3];
		break;
		}
	default:
		info << "Unknown";
	}
	std::cout << info.str();
	closesocket(s);
	WSACleanup();
	return 0;
}