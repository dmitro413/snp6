#pragma once
#include "ProtocolHeaders.h"
#include <string>

namespace PacketParser {
    // Головний метод розбору буфера сирих байтів 
    void ProcessPacket(const char* buffer, int size);

    // Допоміжні методи форматування адрес
    std::string FormatMac(const unsigned char* mac);
    std::string FormatIp(unsigned int ip);
    std::string FormatTcpFlags(unsigned short flags);
}
