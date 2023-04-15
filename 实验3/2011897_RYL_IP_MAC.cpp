#include <Winsock2.h>
#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <string>
#include <iomanip>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")
#pragma pack(1)//��1byte��ʽ����
#pragma warning(disable:4996)
using namespace std;

/*���ĸ�ʽ���� */
struct ethernet_header
{
    uint8_t mac_dhost[6];     /*Ŀ��MAC��ַ*/
    uint8_t mac_shost[6];     /*ԴMAC��ַ*/
    uint16_t frame_type;        /*֡����*/
};

typedef struct FrameHeader_t {//֡�ײ�
    BYTE DesMAC[6];//Ŀ�ĵ�ַ
    BYTE SrcMAC[6];//Դ��ַ
    WORD FrameType;//֡����
}FrameHeader_t;

typedef struct ARPFrame_t {//IP�ײ�
    FrameHeader_t FrameHeader;
    WORD HardwareType;//Ӳ������
    WORD ProtocolType;//Э������
    BYTE HLen;//Ӳ����ַ����
    BYTE PLen;//Э���ַ����
    WORD Operation;//��������
    BYTE SendHa[6];//���ͷ�MAC��ַ
    DWORD SendIP;//���ͷ�IP��ַ
    BYTE RecvHa[6];//���շ�MAC��ַ
    DWORD RecvIP;//���շ�IP��ַ
}ARPFrame_t;

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


/*==============================MAC��ַ���================================*/
int mac_addr(BYTE MACaddr[6]) {          //���չ涨��ʽ���MAC��ַ
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

/*==============================IP��ַ���================================*/
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
    cout << "==========    ��ȡIP��ַ��MAC��ַӳ���ϵ    ==========\n";
    pcap_if_t* alldevs;
    pcap_if_t* d;
    pcap_addr_t* a;
    BYTE* ip;
    int netcard_id = 0;//��Ҫ�򿪵�������
    int i = 0, inum;
    pcap_t* adhandle;
    ARPFrame_t ARPFrame;
    ARPFrame_t* IPPacket;
    DWORD SerIP, ReIP, MIP;
    char errbuf[PCAP_ERRBUF_SIZE];
    //����pcap_findalldevs_ex������ȡ��������ӿڿ��Լ������󶨵�IP��ַ
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)//��������б�
    {
        printf("��������б����\n");
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
    A:	if (a != NULL) //��Ե�һ�����飬�������IP��ַ�����룬�㲥��ַ�Ĵ���
    {
        if (a->addr->sa_family == AF_INET)
        {
            cout << "  IP��ַ��\t\t" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
            cout << "  �������룺\t\t" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;
            cout << "  �㲥��ַ��\t\t" << inet_ntoa(((struct sockaddr_in*)(a->broadaddr))->sin_addr) << endl;
        }
        a = a->next;
        goto A;
    }
    }
    if (i == 0)
    {
        printf("û�з�������\n");
        exit(1);
    }
    printf("\n===========����Ҫѡ��򿪵������� (1-%d)==========\t", i);
    cout << endl;
    scanf_s("%d", &netcard_id);               //����Ҫѡ��򿪵�������
    //��ʱҪѡ����������������,����㲻֪����һ������
    if (netcard_id < 1 || netcard_id > i) //�ж������ŵĺϷ���
    {
        printf("\n�����ų�����Χ\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }
    // �ҵ�Ҫѡ��������ṹ
    for (d = alldevs, i = 0; i < netcard_id - 1; d = d->next, i++);

    if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
    {
        pcap_freealldevs(alldevs);
        exit(1);
    }

    printf("\n�����Ӧ�˿� %s...\n", d->description);


    //��������
    //��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
    for (int i = 0; i < 6; i++)
        ARPFrame.FrameHeader.DesMAC[i] = 0xff;//��ʾ�㲥
    //��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
    for (int i = 0; i < 6; i++)
        ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;

    ARPFrame.FrameHeader.FrameType = htons(0x806);//֡����ΪARP
    ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
    ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
    ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
    ARPFrame.PLen = 4;//Э���ַ��Ϊ4
    ARPFrame.Operation = htons(0x0001);//����ΪARP����
    SerIP = ARPFrame.SendIP = htonl(0x00000000);//����Ϊ����IP��ַ
    //����������MAC��ַ
    for (int i = 0; i < 6; i++)
        ARPFrame.SendHa[i] = 0x0f;
    //���������ϰ󶨵�IP��ַ
    ARPFrame.SendIP = htonl(0x00000000);
    //����Ϊ0
    for (int i = 0; i < 6; i++)
        ARPFrame.RecvHa[i] = 0;//��ʾĿ�ĵ�ַδ֪


    //����ѡ���������IP����Ϊ�����IP��ַ
    for (a = d->addresses; a != NULL; a = a->next)
    {
        if (a->addr->sa_family == AF_INET)
        {
            ReIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
        }
    }
    //����̫���㲥ARP����
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
        //����������Ѱ��IP��ַ�������IP��ַ��MAC��ַӳ���ϵ
        if (SerIP == IPPacket->RecvIP)
            if (ReIP == IPPacket->SendIP)
            {
                cout << "IP��ַ��MAC��ַ�Ķ�Ӧ��ϵ���£�" << endl << "IP��"; ip_protocal_addr(IPPacket->SendIP);
                cout << "MAC��"; mac_addr(IPPacket->SendHa);
                cout << endl;
            }
            else
                goto B;
        else
            goto B;
    }

    //����IP��ַȻ���ҵ��������ӦMAC��ַ
    cout << endl;
    char pip[16];
    cout << "=====================������Ŀ��IP��ַ===================" << endl;
    cin >> pip;
    ReIP = ARPFrame.RecvIP = inet_addr(pip);
    cout << "=================�������Ƿ�Ϊ����,��:1,��:0=============" << endl;
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
        cout << "����ʧ�ܣ�" << endl;
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
                cout << "IP��ַ��MAC��ַ�Ķ�Ӧ��ϵ���£�" << endl << "IP��"; ip_protocal_addr(IPPacket->SendIP);
                cout << "MAC��"; mac_addr(IPPacket->SendHa);
                cout << endl;
            }
            else
                goto C;
        else
            goto C;
    }
}