#define _WINSOCK_DEPRECATED_NO_WARNINGS 
#include "Sniffer.h"
#include "PacketParser.h"
#include <iostream>

#pragma comment(lib, "ws2_32.lib")

namespace SnifferCore {
    static SOCKET g_rawSocket = INVALID_SOCKET;
    static bool g_isRunning = false;

    bool InitWinsock() {
        WSADATA wsa;
        // КРОК 1: Ініціалізуємо версію Winsock 2.2
        int res = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (res != 0) {
            std::cerr << "[ПОМИЛКА] WSAStartup завершився з кодом: " << res << "\n";
            return false;
        }
        return true;
    }

    std::vector<std::string> GetLocalIpAddresses() {
        std::vector<std::string> ips;
        char hostName[256];

        if (gethostname(hostName, sizeof(hostName)) == SOCKET_ERROR) {
            return ips;
        }

        // КРОК 2: Отримуємо структуру хоста з IP-адресами інтерфейсів
        struct hostent* host = gethostbyname(hostName);
        if (host == nullptr) return ips;

        for (int i = 0; host->h_addr_list[i] != nullptr; ++i) {
            struct in_addr addr;
            memcpy(&addr, host->h_addr_list[i], sizeof(struct in_addr));
            ips.push_back(inet_ntoa(addr));
        }
        return ips;
    }

    void StartSniffer(const std::string& bindIp) {
        // КРОК 3: Створення сирого сокета (Raw Socket) для сімейства AF_INET
        g_rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        if (g_rawSocket == INVALID_SOCKET) {
            int err = WSAGetLastError();
            std::cerr << "[ПОМИЛКА] Не вдалося створити сирий сокет! Код помилки: " << err << "\n";
            if (err == WSAEACCES) {
                std::cerr << ">> ПРИЧИНА: Створення сирих сокетів вимагає прав АДМІНІСТРАТОРА!\n";
            }
            return;
        }

        // КРОК 4: Прив'язка сокета (bind) до обраної локальної IP-адреси
        sockaddr_in localAddr;
        ZeroMemory(&localAddr, sizeof(localAddr)); 

        localAddr.sin_family = AF_INET;
        localAddr.sin_port = htons(0); 
        localAddr.sin_addr.s_addr = inet_addr(bindIp.c_str());

        if (bind(g_rawSocket, (struct sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR) {
            std::cerr << "[ПОМИЛКА] Помилка прив'язки bind() до адреси " << bindIp << ". Код: " << WSAGetLastError() << "\n";
            closesocket(g_rawSocket);
            return;
        }

        // КРОК 5: Переведення адаптера у режим перехоплення всіх пакетів (Promiscuous Mode)
        // Використовуємо WSAIoctl із керуючим кодом SIO_RCVALL
        DWORD flag = RCVALL_ON; // 1 = перехоплювати всі пакети (SIO_RCVALL)
        DWORD bytesReturned = 0;

        if (WSAIoctl(g_rawSocket, SIO_RCVALL, &flag, sizeof(flag), NULL, 0, &bytesReturned, NULL, NULL) == SOCKET_ERROR) {
            std::cerr << "[ПОМИЛКА] WSAIoctl(SIO_RCVALL) завершився з помилкою: " << WSAGetLastError() << "\n";
            closesocket(g_rawSocket);
            return;
        }

        std::cout << "[УСПІХ] Проміскуїті-режим активовано на інтерфейсі " << bindIp << ".\n";
        std::cout << "[ІНФО] Початок перехоплення трафіку (натисніть Ctrl+C для зупинки)...\n";
        std::cout << "======================================================================\n";

        g_isRunning = true;
        char packetBuffer[65536]; // Максимальний можливий розмір IPv4 пакета (64 КБ) 

        // КРОК 6: Цикл безперервного прийому пакетів
        while (g_isRunning) {
            int bytesReceived = recv(g_rawSocket, packetBuffer, sizeof(packetBuffer), 0);

            if (bytesReceived > 0) {
                // КРОК 7: Розбір та вивід кожного отриманого пакета
                PacketParser::ProcessPacket(packetBuffer, bytesReceived);
            }
            else if (bytesReceived == SOCKET_ERROR) {
                if (g_isRunning) {
                    std::cerr << "[ЗБІЙ] recv() повернув помилку: " << WSAGetLastError() << "\n";
                }
                break;
            }
        }
    }

    void StopSniffer() {
        g_isRunning = false;
        if (g_rawSocket != INVALID_SOCKET) {
            // КРОК 8: Вимикаємо проміскуїті-режим та закриваємо сокет
            DWORD flag = RCVALL_OFF;
            DWORD bytesReturned = 0;
            WSAIoctl(g_rawSocket, SIO_RCVALL, &flag, sizeof(flag), NULL, 0, &bytesReturned, NULL, NULL);

            closesocket(g_rawSocket);
            g_rawSocket = INVALID_SOCKET;
        }
        WSACleanup();
        std::cout << "\n[ІНФО] Роботу сніфера коректно зупинено. Ресурси звільнено.\n";
    }
}
