#include <Winsock2.h>
#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <string>
#include <iomanip>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")
#pragma warning(disable:4996)
using namespace std;

/*���ĸ�ʽ���� */
struct ethernet_header
{
    uint8_t mac_dhost[6];     /*Ŀ��MAC��ַ*/
    uint8_t mac_shost[6];     /*ԴMAC��ַ*/
    uint16_t frame_type;        /*֡����*/
};

/*ip��ַ��ʽ*/
typedef uint32_t in_addr_t;

struct ip_header
{
#ifdef WORKS_BIGENDIAN
    uint8_t ip_version : 4,                     /*version:4*/
        ip_header_length : 4;                       /*IPЭ���ײ�����Header Length*/
#else
    uint8_t ip_header_length : 4,
        ip_version : 4;
#endif
    uint8_t ip_tos;                             /*��������Differentiated Services  Field*/
    uint16_t total_len;                         /*�ܳ���Total Length*/
    uint16_t ip_id;                             /*��ʶidentification*/
    uint16_t ip_off;                            /*Ƭƫ��*/
    uint8_t ip_ttl;                             /*����ʱ��Time To Live*/
    uint8_t ip_protocol;                        /*Э�����ͣ�TCP����UDPЭ�飩*/
    uint16_t ip_checksum;                       /*�ײ������*/
    struct in_addr  ip_source_address;          /*ԴIP*/
    struct in_addr  ip_destination_address;     /*Ŀ��IP*/
};

/*IP���ݰ������ĺ�������ethernet_protocol_packet_callback*/
void ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
    struct ip_header* ip_protocol;                                          /*ipЭ�����*/
    u_int  header_length;                                                   /*����*/
    u_int  offset;                                                          /*Ƭƫ��*/
    u_char  tos;                                                            /*��������*/
    uint16_t checksum;                                                      /*�ײ������*/
    ip_protocol = (struct ip_header*)(packet_content + 14);                 /*���ip���ݰ�������ȥ����̫ͷ��*/
    checksum = ntohs(ip_protocol->ip_checksum);                      /*���У���*/
    header_length = ip_protocol->ip_header_length * 4;                      /*��ó���*/
    tos = ip_protocol->ip_tos;                                              /*���tos*/
    offset = ntohs(ip_protocol->ip_off);                            /*���ƫ����*/
    cout << "\n====================    ����㣨IPЭ�飩      ====================\n";
    printf("IP�汾:\t\tIPv%01X\n", ip_protocol->ip_version);
    cout << "IPЭ���ײ�����:\t" << header_length << endl;
    cout << "��������:\t" << tos << endl;
    cout << "�ܳ���:\t\t" << ntohs(ip_protocol->total_len) << endl;        /*����ܳ���*/
    cout << "��ʶ:\t\t" << ntohs(ip_protocol->ip_id) << endl;              /*��ñ�ʶ*/
    cout << "Ƭƫ��:\t\t" << (offset & 0x1fff) * 8 << endl;
    printf("����ʱ��:\t%01X\n", ip_protocol->ip_ttl);                   /*���ttl*/
    cout << "�ײ������:\t" << checksum << endl;
    cout << "ԴIP:\t" << inet_ntoa(ip_protocol->ip_source_address) << endl;    /*���Դip��ַ*/
    cout << "Ŀ��IP:\t" << inet_ntoa(ip_protocol->ip_destination_address) << endl;/*���Ŀ��ip��ַ*/
    printf("Э���:\t%01X\n", ip_protocol->ip_protocol);                /*���Э������*/
    cout << "\n�����Э����:\t";
    switch (ip_protocol->ip_protocol) {
    case 6:
        cout << "TCP\n";
        //tcp_protocol_packet_callback(argument, packet_header, packet_content);
        break;
    case 17:
        cout << "UDP\n";
        break;
    case 1:
        cout << "ICMP\n";
        break;
    case 2:
        cout << "IGMP\n";
        break;
    default:break;
    }
}

void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
    u_short ethernet_type;                                                  /*��̫��Э������*/
    struct ethernet_header* ethernet_protocol;                              /*��̫��Э�����*/
    u_char* mac_string;
    static int packet_number = 1;
    cout << endl;
    cout << "\t�ڡ�" << packet_number << "����IP���ݰ�������" << endl;
    cout << "====================    ��·��(��̫��Э��)    ====================" << endl;
    ethernet_protocol = (struct ethernet_header*)packet_content;           /*���һ̫��Э����������*/
    cout << "��̫������Ϊ :\t";
    ethernet_type = ntohs(ethernet_protocol->frame_type);           /*�����̫������*/
    cout << ethernet_type << endl;
    switch (ethernet_type) {                                                /*�ж���̫�����͵�ֵ*/
    case 0x0800:
        cout << "������ǣ�      IPv4Э��\n" << endl; break;
    case 0x0806:
        cout << "������ǣ�      ARPЭ��\n" << endl; break;
    case 0x8035:
        cout << "������ǣ�      RARP Э��\n" << endl; break;
    default: break;
    }

    cout << "MacԴ��ַ:\t";
    mac_string = ethernet_protocol->mac_shost;
    printf("%02X-", mac_string[0]);
    printf("%02X-", mac_string[1]);
    printf("%02X-", mac_string[2]);
    printf("%02X-", mac_string[3]);
    printf("%02X-", mac_string[4]);
    printf("%02X", mac_string[5]);
    cout << endl;

    cout << "MacĿ�ĵ�ַ:\t";
    mac_string = ethernet_protocol->mac_dhost;
    printf("%02X-", mac_string[0]);
    printf("%02X-", mac_string[1]);
    printf("%02X-", mac_string[2]);
    printf("%02X-", mac_string[3]);
    printf("%02X-", mac_string[4]);
    printf("%02X", mac_string[5]);

    switch (ethernet_type) {
    case 0x0800:
        ip_protocol_packet_callback(argument, packet_header, packet_content);
        break;
    default:break;
    }
    packet_number++;
}

int main() {
    cout << "====================    ����IP���ݰ�    ====================\n";
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum = 0;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cout << stderr << "Error in pcap_findalldevs: %s\n" << errbuf;
        exit(1);
    }

    for (d = alldevs; d; d = d->next) {
        cout << ++i << d->name;
        if (d->description)
            cout << d->description;
        else
            cout << "No description available\n";
        cout << endl;
    }

    if (i == 0) {
        return -1;
    }

    cout << "\n������Ҫѡ��򿪵������� (1-" << i << ")��:\t";
    cin >> inum;

    if (inum < 1 || inum > i) {
        cout << "ERROR";
        pcap_freealldevs(alldevs);
        return -1;
    }

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
        cout << stderr << "ERROR";
        pcap_freealldevs(alldevs);
        return -1;
    }

    cout << "\n����" << d->description;
    pcap_freealldevs(alldevs);
    int cnt = 0;
    cout << "\n����Ҫ�������ݰ��ĸ�����:\t\t";
    cin >> cnt;
    pcap_loop(adhandle, cnt, ethernet_protocol_packet_callback, NULL);
    cout << "\n\t������IP���ݰ�������\n";
    return 0;
}