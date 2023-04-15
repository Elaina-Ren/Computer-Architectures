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

/*报文格式定义 */
struct ethernet_header
{
    uint8_t mac_dhost[6];     /*目的MAC地址*/
    uint8_t mac_shost[6];     /*源MAC地址*/
    uint16_t frame_type;        /*帧类型*/
};

/*ip地址格式*/
typedef uint32_t in_addr_t;

struct ip_header
{
#ifdef WORKS_BIGENDIAN
    uint8_t ip_version : 4,                     /*version:4*/
        ip_header_length : 4;                       /*IP协议首部长度Header Length*/
#else
    uint8_t ip_header_length : 4,
        ip_version : 4;
#endif
    uint8_t ip_tos;                             /*服务类型Differentiated Services  Field*/
    uint16_t total_len;                         /*总长度Total Length*/
    uint16_t ip_id;                             /*标识identification*/
    uint16_t ip_off;                            /*片偏移*/
    uint8_t ip_ttl;                             /*生存时间Time To Live*/
    uint8_t ip_protocol;                        /*协议类型（TCP或者UDP协议）*/
    uint16_t ip_checksum;                       /*首部检验和*/
    struct in_addr  ip_source_address;          /*源IP*/
    struct in_addr  ip_destination_address;     /*目的IP*/
};

/*IP数据包分析的函数定义ethernet_protocol_packet_callback*/
void ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
    struct ip_header* ip_protocol;                                          /*ip协议变量*/
    u_int  header_length;                                                   /*长度*/
    u_int  offset;                                                          /*片偏移*/
    u_char  tos;                                                            /*服务类型*/
    uint16_t checksum;                                                      /*首部检验和*/
    ip_protocol = (struct ip_header*)(packet_content + 14);                 /*获得ip数据包的内容去掉以太头部*/
    checksum = ntohs(ip_protocol->ip_checksum);                      /*获得校验和*/
    header_length = ip_protocol->ip_header_length * 4;                      /*获得长度*/
    tos = ip_protocol->ip_tos;                                              /*获得tos*/
    offset = ntohs(ip_protocol->ip_off);                            /*获得偏移量*/
    cout << "\n====================    网络层（IP协议）      ====================\n";
    printf("IP版本:\t\tIPv%01X\n", ip_protocol->ip_version);
    cout << "IP协议首部长度:\t" << header_length << endl;
    cout << "服务类型:\t" << tos << endl;
    cout << "总长度:\t\t" << ntohs(ip_protocol->total_len) << endl;        /*获得总长度*/
    cout << "标识:\t\t" << ntohs(ip_protocol->ip_id) << endl;              /*获得标识*/
    cout << "片偏移:\t\t" << (offset & 0x1fff) * 8 << endl;
    printf("生存时间:\t%01X\n", ip_protocol->ip_ttl);                   /*获得ttl*/
    cout << "首部检验和:\t" << checksum << endl;
    cout << "源IP:\t" << inet_ntoa(ip_protocol->ip_source_address) << endl;    /*获得源ip地址*/
    cout << "目的IP:\t" << inet_ntoa(ip_protocol->ip_destination_address) << endl;/*获得目的ip地址*/
    printf("协议号:\t%01X\n", ip_protocol->ip_protocol);                /*获得协议类型*/
    cout << "\n传输层协议是:\t";
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
    u_short ethernet_type;                                                  /*以太网协议类型*/
    struct ethernet_header* ethernet_protocol;                              /*以太网协议变量*/
    u_char* mac_string;
    static int packet_number = 1;
    cout << endl;
    cout << "\t第【" << packet_number << "】个IP数据包被捕获" << endl;
    cout << "====================    链路层(以太网协议)    ====================" << endl;
    ethernet_protocol = (struct ethernet_header*)packet_content;           /*获得一太网协议数据内容*/
    cout << "以太网类型为 :\t";
    ethernet_type = ntohs(ethernet_protocol->frame_type);           /*获得以太网类型*/
    cout << ethernet_type << endl;
    switch (ethernet_type) {                                                /*判断以太网类型的值*/
    case 0x0800:
        cout << "网络层是：      IPv4协议\n" << endl; break;
    case 0x0806:
        cout << "网络层是：      ARP协议\n" << endl; break;
    case 0x8035:
        cout << "网络层是：      RARP 协议\n" << endl; break;
    default: break;
    }

    cout << "Mac源地址:\t";
    mac_string = ethernet_protocol->mac_shost;
    printf("%02X-", mac_string[0]);
    printf("%02X-", mac_string[1]);
    printf("%02X-", mac_string[2]);
    printf("%02X-", mac_string[3]);
    printf("%02X-", mac_string[4]);
    printf("%02X", mac_string[5]);
    cout << endl;

    cout << "Mac目的地址:\t";
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
    cout << "====================    解析IP数据包    ====================\n";
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

    cout << "\n【输入要选择打开的网卡号 (1-" << i << ")】:\t";
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

    cout << "\n监听" << d->description;
    pcap_freealldevs(alldevs);
    int cnt = 0;
    cout << "\n【将要捕获数据包的个数】:\t\t";
    cin >> cnt;
    pcap_loop(adhandle, cnt, ethernet_protocol_packet_callback, NULL);
    cout << "\n\t【解析IP数据包结束】\n";
    return 0;
}