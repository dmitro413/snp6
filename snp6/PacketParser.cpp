#include "PacketParser.h"
#include <iostream>
#include <iomanip>
#include <sstream>

namespace PacketParser {

    std::string FormatMac(const unsigned char* mac) {
        std::stringstream ss;
        for (int i = 0; i < 6; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)mac[i];
            if (i < 5) ss << ":";
        }
        return ss.str();
    }

    std::string FormatIp(unsigned int ip) {
        struct in_addr addr;
        addr.s_addr = ip;
        return std::string(inet_ntoa(addr));
    }

    std::string FormatTcpFlags(unsigned short flags) {
        std::string res = "";
        // Прапорці знаходяться у молодших 6 бітах поля offset_flags
        if (flags & 0x0001) res += "FIN ";
        if (flags & 0x0002) res += "SYN ";
        if (flags & 0x0004) res += "RST ";
        if (flags & 0x0008) res += "PSH ";
        if (flags & 0x0010) res += "ACK ";
        if (flags & 0x0020) res += "URG ";
        return res.empty() ? "[NONE]" : res;
    }

    void ProcessPacket(const char* buffer, int size) {
        if (size < (int)sizeof(ip_header)) return;

        int ipOffset = 0;

        // Перевіряємо, чи буфер починається з Ethernet-заголовка (якщо кадр передано повністю),
        // чи відразу з IP-заголовка (стандартна поведінка SIO_RCVALL у Windows).
        unsigned char firstByte = (unsigned char)buffer[0];

        if (size >= 14 && (unsigned char)buffer[12] == 0x08 && (unsigned char)buffer[13] == 0x00) {
            // Маємо повний Ethernet II кадр (14 байт)
            const eth_header* eth = reinterpret_cast<const eth_header*>(buffer);
            std::cout << "[ETH]  SRC MAC: " << FormatMac(eth->src)
                << " -> DST MAC: " << FormatMac(eth->dst)
                << " | Type: 0x" << std::hex << std::setw(4) << std::setfill('0') << ntohs(eth->type) << std::dec << "\n";
            ipOffset = 14;
        }

        // Парсимо IP-заголовок
        const ip_header* ip = reinterpret_cast<const ip_header*>(buffer + ipOffset);

        // Перевіряємо версію IPv4 (старші 4 біти поля ihl_version мають дорівнювати 4)
        unsigned char ipVersion = (ip->ihl_version >> 4) & 0x0F;
        if (ipVersion != 4) {
            return; // Пропускаємо пакети, які не є IPv4
        }

        // Обчислюємо реальну довжину IP-заголовка: IHL * 4 байти (мінімум 20 байт)
        unsigned int ipHeaderLen = (ip->ihl_version & 0x0F) * 4;
        unsigned short totalLen = ntohs(ip->total_length);

        std::string protoStr = "UNKNOWN";
        if (ip->protocol == 1)  protoStr = "ICMP";
        else if (ip->protocol == 6)  protoStr = "TCP";
        else if (ip->protocol == 17) protoStr = "UDP";

        std::cout << "[IP]   SRC: " << FormatIp(ip->src)
            << " -> DST: " << FormatIp(ip->dst)
            << " | Proto: " << protoStr
            << " | TTL: " << (int)ip->ttl
            << " | Len: " << totalLen << " B\n";

        // Зсув до заголовка транспортного рівня (L4)
        int l4Offset = ipOffset + ipHeaderLen;

        // 1. Якщо це TCP
        if (ip->protocol == 6 && size >= (l4Offset + (int)sizeof(tcp_header))) {
            const tcp_header* tcp = reinterpret_cast<const tcp_header*>(buffer + l4Offset);

            unsigned short srcPort = ntohs(tcp->src_port);
            unsigned short dstPort = ntohs(tcp->dst_port);
            unsigned short flags = ntohs(tcp->offset_flags) & 0x003F; // Молодші 6 біт 
            unsigned int seq = ntohl(tcp->seq);

            std::cout << "[TCP]  " << srcPort << " -> " << dstPort
                << " | Flags: " << FormatTcpFlags(flags)
                << " | SEQ: " << seq << "\n";
        }
        // 2. Якщо це UDP
        else if (ip->protocol == 17 && size >= (l4Offset + (int)sizeof(udp_header))) {
            const udp_header* udp = reinterpret_cast<const udp_header*>(buffer + l4Offset);

            unsigned short srcPort = ntohs(udp->src_port);
            unsigned short dstPort = ntohs(udp->dst_port);
            unsigned short length = ntohs(udp->length);

            std::cout << "[UDP]  " << srcPort << " -> " << dstPort
                << " | Length: " << length << " B\n";
        }
        // 3. Якщо це ICMP
        else if (ip->protocol == 1 && size >= (l4Offset + (int)sizeof(icmp_header))) {
            const icmp_header* icmp = reinterpret_cast<const icmp_header*>(buffer + l4Offset);
            std::cout << "[ICMP] Type: " << (int)icmp->type
                << " | Code: " << (int)icmp->code << "\n";
        }

        std::cout << "----------------------------------------------------------------------\n";
    }
}
