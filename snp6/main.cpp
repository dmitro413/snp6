#include "Sniffer.h"
#include <iostream>
#include <io.h>
#include <fcntl.h>

// Обробник сигналу Ctrl+C для коректного закриття сокета 
BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_CLOSE_EVENT) {
        SnifferCore::StopSniffer();
        return TRUE;
    }
    return FALSE;
}

int main() {
    system("chcp 65001 > nul");
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);

    std::cout << "     МЕРЕЖЕВИЙ СНІФЕР ПАКЕТІВ WINSOCK2 RAW SOCKETS (ЛАБ. №6)\n";

    // Реєструємо перехоплювач натискання Ctrl+C
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    if (!SnifferCore::InitWinsock()) {
        return 1;
    }

    // Отримуємо список локальних інтерфейсів
    auto ips = SnifferCore::GetLocalIpAddresses();
    if (ips.empty()) {
        std::cerr << "[ПОМИЛКА] Не знайдено жодного активного мережевого IPv4 інтерфейсу!\n";
        WSACleanup();
        return 1;
    }

    std::cout << "Знайдені мережеві інтерфейси хоста:\n";
    for (size_t i = 0; i < ips.size(); ++i) {
        std::cout << " [" << i + 1 << "] " << ips[i] << "\n";
    }

    std::cout << "\nОберіть номер інтерфейсу для прослуховування (1-" << ips.size() << "): ";
    int choice = 1;
    std::cin >> choice;

    if (choice < 1 || choice >(int)ips.size()) {
        choice = 1;
    }

    std::string selectedIp = ips[choice - 1];
    std::cout << "Обрано інтерфейс: " << selectedIp << "\n\n";

    // Запускаємо перехоплення (потрібні права Адміністратора!)
    SnifferCore::StartSniffer(selectedIp);

    SnifferCore::StopSniffer();
    return 0;
}
