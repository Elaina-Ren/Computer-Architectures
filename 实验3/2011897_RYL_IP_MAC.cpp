#include <Winsock2.h>
#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <string>
#include <iomanip>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")
#pragma pack(1)//以1byte方式对齐
#pragma warning(disable:4996)
using namespace std;

/*报文格式定义 */
struct ethernet_header
{
    uint8_t mac_dhost[6];     /*目的MAC地址*/
    uint8_t mac_shost[6];     /*源MAC地址*/
    uint16_t frame_type;        /*帧类型*/
};

typedef struct FrameHeader_t {//帧首部
    BYTE DesMAC[6];//目的地址
    BYTE SrcMAC[6];//源地址
    WORD FrameType;//帧类型
}FrameHeader_t;

typedef struct ARPFrame_t {//IP首部
    FrameHeader_t FrameHeader;
    WORD HardwareType;//硬件类型
    WORD ProtocolType;//协议类型
    BYTE HLen;//硬件地址长度
    BYTE PLen;//协议地址长度
    WORD Operation;//操作类型
    BYTE SendHa[6];//发送方MAC地址
    DWORD SendIP;//发送方IP地址
    BYTE RecvHa[6];//接收方MAC地址
    DWORD RecvIP;//接收方IP地址
}ARPFrame_t;

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


/*==============================MAC地址输出================================*/
int mac_addr(BYTE MACaddr[6]) {          //按照规定格式输出MAC地址
    int i = 0;
    while (i <= 5) {
        cout << setw(2) << setfill('0') << hex << (int)MACaddr[i];
        if (i != 5)
            cout << " - ";
        else
            cout << endl;
        i++;
    }
    return i;
}

/*==============================IP地址输出================================*/
int ip_protocal_addr(DWORD IPaddr) {
    BYTE* p = (BYTE*)&IPaddr;
    int i = 0;
    while (i <= 3) {
        cout << dec << (int)*p;
        if (i != 3)
            cout << " - ";
        else
            cout << endl;
        p++;
        i++;
    }
    return i;
}


int main() {
    cout << "==========    获取IP地址与MAC地址映射关系    ==========\n";
    pcap_if_t* alldevs;
    pcap_if_t* d;
    pcap_addr_t* a;
    BYTE* ip;
    int netcard_id = 0;//需要打开的网卡号
    int i = 0, inum;
    pcap_t* adhandle;
    ARPFrame_t ARPFrame;
    ARPFrame_t* IPPacket;
    DWORD SerIP, ReIP, MIP;
    char errbuf[PCAP_ERRBUF_SIZE];
    //利用pcap_findalldevs_ex函数获取本机网络接口卡以及网卡绑定的IP地址
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)//获得网卡列表
    {
        printf("获得网卡列表错误\n");
        exit(1);
    }

    for (d = alldevs; d; d = d->next)
    {
        cout << "==============================="<<++i<<"======================================"<<endl;
        printf("%d. %s", i, d->name);
        if (d->description) {
            printf(" (%s)\n", d->description);

        }
        else
            printf(" (No description available)\n");
        a = d->addresses;
    A:	if (a != NULL) //相对第一次试验，增加输出IP地址，掩码，广播地址的代码
    {
        if (a->addr->sa_family == AF_INET)
        {
            cout << "  IP地址：\t\t" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
            cout << "  网络掩码：\t\t" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;
            cout << "  广播地址：\t\t" << inet_ntoa(((struct sockaddr_in*)(a->broadaddr))->sin_addr) << endl;
        }
        a = a->next;
        goto A;
    }
    }
    if (i == 0)
    {
        printf("没有发现网卡\n");
        exit(1);
    }
    printf("\n===========输入要选择打开的网卡号 (1-%d)==========\t", i);
    cout << endl;
    scanf_s("%d", &netcard_id);               //输入要选择打开的网卡号
    //此时要选择正在联网的网卡,如果你不知道就一个个试
    if (netcard_id < 1 || netcard_id > i) //判断网卡号的合法性
    {
        printf("\n网卡号超出范围\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }
    // 找到要选择的网卡结构
    for (d = alldevs, i = 0; i < netcard_id - 1; d = d->next, i++);

    if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
    {
        pcap_freealldevs(alldevs);
        exit(1);
    }

    printf("\n接入对应端口 %s...\n", d->description);


    //报文内容
    //将APRFrame.FrameHeader.DesMAC设置为广播地址
    for (int i = 0; i < 6; i++)
        ARPFrame.FrameHeader.DesMAC[i] = 0xff;//表示广播
    //将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
    for (int i = 0; i < 6; i++)
        ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;

    ARPFrame.FrameHeader.FrameType = htons(0x806);//帧类型为ARP
    ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
    ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
    ARPFrame.HLen = 6;//硬件地址长度为6
    ARPFrame.PLen = 4;//协议地址长为4
    ARPFrame.Operation = htons(0x0001);//操作为ARP请求
    SerIP = ARPFrame.SendIP = htonl(0x00000000);//设置为任意IP地址
    //本机网卡的MAC地址
    for (int i = 0; i < 6; i++)
        ARPFrame.SendHa[i] = 0x0f;
    //本机网卡上绑定的IP地址
    ARPFrame.SendIP = htonl(0x00000000);
    //设置为0
    for (int i = 0; i < 6; i++)
        ARPFrame.RecvHa[i] = 0;//表示目的地址未知


    //将所选择的网卡的IP设置为请求的IP地址
    for (a = d->addresses; a != NULL; a = a->next)
    {
        if (a->addr->sa_family == AF_INET)
        {
            ReIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
        }
    }
    //向以太网广播ARP请求
    struct pcap_pkthdr* adhandleheader;
    const u_char* adhandledata;
    int tjdg = 0;
    //
    if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
    {
        pcap_freealldevs(alldevs);
        throw - 7;
    }
    else
    {
        inum = 0;
    B:	int jdg_catch_re_arp_p = pcap_next_ex(adhandle, &adhandleheader, &adhandledata);
        IPPacket = (ARPFrame_t*)adhandledata;
        if (SerIP == IPPacket->SendIP)
            if (ReIP == IPPacket->RecvIP)
            {
                goto B;
            }
        //根据网卡号寻找IP地址，并输出IP地址与MAC地址映射关系
        if (SerIP == IPPacket->RecvIP)
            if (ReIP == IPPacket->SendIP)
            {
                cout << "IP地址与MAC地址的对应关系如下：" << endl << "IP："; ip_protocal_addr(IPPacket->SendIP);
                cout << "MAC："; mac_addr(IPPacket->SendHa);
                cout << endl;
            }
            else
                goto B;
        else
            goto B;
    }

    //输入IP地址然后找到并输出对应MAC地址
    cout << endl;
    char pip[16];
    cout << "=====================请输入目的IP地址===================" << endl;
    cin >> pip;
    ReIP = ARPFrame.RecvIP = inet_addr(pip);
    cout << "=================请输入是否为本机,是:1,否:0=============" << endl;
    int ifIP;
    cin >> ifIP;
    if (!ifIP) {
        SerIP = ARPFrame.SendIP = IPPacket->SendIP;
        for (i = 0; i < 6; i++)
        {
            ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i];
        }
    }
    if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
    {
        cout << "发送失败！" << endl;
        pcap_freealldevs(alldevs);
        throw - 6;
    }
    else
    {
        inum = 0;
    C:	int jdg_catch_re_arp_p = pcap_next_ex(adhandle, &adhandleheader, &adhandledata);
        IPPacket = (ARPFrame_t*)adhandledata;
        if (SerIP == IPPacket->SendIP)
            if (ReIP == IPPacket->RecvIP)
            {
                goto C;
            }
        if (SerIP == IPPacket->RecvIP)
            if (ReIP == IPPacket->SendIP)
            {
                cout << "IP地址与MAC地址的对应关系如下：" << endl << "IP："; ip_protocal_addr(IPPacket->SendIP);
                cout << "MAC："; mac_addr(IPPacket->SendHa);
                cout << endl;
            }
            else
                goto C;
        else
            goto C;
    }
}