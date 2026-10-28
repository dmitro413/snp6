#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS 
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>

#pragma pack(push, 1)

// 1. Заголовок Ethernet II (Layer 2) — 14 байт
struct eth_header {
    unsigned char dst[6];   // MAC-адреса призначення
    unsigned char src[6];   // MAC-адреса джерела
    unsigned short type;    // EtherType (0x0800 = IPv4, 0x0806 = ARP)
};

// 2. Заголовок IPv4 (Layer 3) — мінімум 20 байт
struct ip_header {
    unsigned char  ihl_version;   // 4 біти: версія (4), 4 біти: довжина заголовка (IHL)
    unsigned char  tos;           // Type of Service (DSCP/ECN)
    unsigned short total_length;  // Загальна довжина пакета (заголовок + корисне навантаження)
    unsigned short id;            // Ідентифікатор пакета для фрагментації
    unsigned short flags_offset;  // Прапорці (3 біти) та зсув фрагмента (13 біт)
    unsigned char  ttl;           // Час життя пакета (Time To Live)
    unsigned char  protocol;      // Протокол верхнього рівня (1 = ICMP, 6 = TCP, 17 = UDP)
    unsigned short checksum;      // Контрольна сума IP-заголовка
    unsigned int   src;           // IPv4-адреса джерела (32 біти)
    unsigned int   dst;           // IPv4-адреса призначення (32 біти) 
};

// 3. Заголовок TCP (Layer 4) — мінімум 20 байт
struct tcp_header {
    unsigned short src_port;      // Порт відправника
    unsigned short dst_port;      // Порт одержувача
    unsigned int   seq;           // Порядковий номер (Sequence Number)
    unsigned int   ack;           // Номер підтвердження (Acknowledgment Number)
    unsigned short offset_flags;  // 4 біти Data Offset + 6 бітів Reserved + 6 бітів Flags
    unsigned short window;        // Розмір вікна прийому
    unsigned short checksum;      // Контрольна сума TCP
    unsigned short urgent_ptr;    // Вказівник терміновості (Urgent Pointer)
};

// 4. Заголовок UDP (Layer 4) — фіксовані 8 байт
struct udp_header {
    unsigned short src_port;      // Порт відправника
    unsigned short dst_port;      // Порт одержувача
    unsigned short length;        // Довжина UDP заголовка + даних
    unsigned short checksum;      // Контрольна сума UDP
};

// 5. Заголовок ICMP (Layer 3/4) — 8 байт
struct icmp_header {
    unsigned char  type;          // Тип повідомлення (0 = Echo Reply, 8 = Echo Request)
    unsigned char  code;          // Код типу
    unsigned short checksum;      // Контрольна сума ICMP
    unsigned short id;            // Ідентифікатор сесії
    unsigned short seq;           // Номер послідовності
};

#pragma pack(pop)
