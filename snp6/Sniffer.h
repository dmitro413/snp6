#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <vector>
#include <string>

namespace SnifferCore {
    // Ініціалізація Winsock2
    bool InitWinsock();

    // Отримання списку доступних локальних IPv4 адрес для прив'язки bind() 
    std::vector<std::string> GetLocalIpAddresses();

    // Запуск прослуховування на обраній IP-адресі
    void StartSniffer(const std::string& bindIp);

    // Зупинка роботи та звільнення ресурсів
    void StopSniffer();
}
