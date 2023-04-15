#pragma once
#include "pcap.h"
#include <minwindef.h>
#include <WinSock2.h>
#pragma pack(1)//��1byte��ʽ����

//	�����ײ�
typedef struct FrameHeader_t {
	BYTE DesMAC[6];//Ŀ�ĵ�ַ
	BYTE SrcMAC[6];//Դ��ַ
	WORD FrameType;//֡����
}FrameHeader_t;

//	ARP���ĸ�ʽ
typedef struct ARPFrame_t {
	FrameHeader_t FrameHeader;	//֡�ײ�
	WORD HardwareType;			//Ӳ������
	WORD ProtocolType;			//Э������
	BYTE HLen;					//Ӳ����ַ����
	BYTE PLen;					//Э���ַ
	WORD Operation;				//����
	BYTE SendHa[6];				//���ͷ�MAC
	DWORD SendIP;				//���ͷ�IP
	BYTE RecvHa[6];				//���շ�MAC
	DWORD RecvIP;				//���շ�IP
}ARPFrame_t;

//	IP�����ײ�
typedef struct IPHeader_t {
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;					//��������
	BYTE Protocol;
	WORD Checksum;				//У���
	ULONG SrcIP;				//ԴIP
	ULONG DstIP;				//Ŀ��IP
}IPHeader_t;

//	����֡�ײ���IP�ײ������ݰ�
typedef struct Data_t {
	FrameHeader_t FrameHeader;	//֡�ײ�
	IPHeader_t IPHeader;		//IP�ײ�
}Data_t;

//	����֡�ײ���IP�ײ������ݰ�
typedef struct ICMP {
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
	char buf[0x80];
}ICMP_t;

#pragma pack()//�ָ�4bytes����
#pragma pack(1)//��1byte��ʽ����

//	·�ɱ����
class Route_item{
public:
	DWORD mask;				//����
	DWORD net;				//Ŀ������
	DWORD nextip;			//��һ��
	BYTE nextMAC[6];		//��һ����MAC��ַ
	int index;				//�ڼ���
	int type;				//0Ϊֱ������(����ɾ��)��1Ϊ�û����
	Route_item* nextitem;
	Route_item(){
		memset(this, 0, sizeof(*this));
	}
	//	��ӡ�������ݣ���ӡ�����롢Ŀ���������һ��IP�����ͣ��Ƿ���ֱ�� Ͷ�ݣ�
	void Print_item();		
};

#pragma pack()//�ָ�4bytes����
#pragma pack(1)//�ָ�4bytes����
// ·�ɱ�ṹ�� ���� ����洢·�ɱ���
class Route_table{
public:
	Route_item* head, * tail;	//�������� ���� ֧��������50ת����
	int num;					//����
	Route_table();				//��ʼ�������ֱ�����ӵ�����
	//·�ɱ����� ���� 1.ֱ��Ͷ������ǰ 2.���ఴ�ƥ��ԭ��
	void add(Route_item* a);
	//ɾ����type = 0����ɾ��
	void remove(int index);
	//·�ɱ�Ĵ�ӡ mask net next type
	void Print_file();
	//���� ���� �ƥ��ԭ�򷵻���һ����ip
	DWORD lookup(DWORD ip);
};
#pragma pack()//�ָ�4bytes����
class arpitem{
public:
	DWORD ip;
	BYTE mac[6];
};
class ipitem{
public:
	DWORD sip, dip;
	BYTE smac[6], dmac[6];
};
//	IP��MAC��Ӧ��ϵ ���� �洢��
class Arp_table{
public:
	DWORD ip;			//IP��ַ
	BYTE mac[6];		//MAC��ַ
	static int num;		//��������
	static void insert(DWORD ip, BYTE mac[6]);	//�������
	static int lookup(DWORD ip, BYTE mac[6]);	//ɾ������
}atable[50];

//	·����������־
class Log_file{
public:
	Log_file();		//���ļ�����д��
	~Log_file();	//�ر��ļ�
	int index;		//����
	char type[5];	//arp��ip
	//��������
	ipitem ip; arpitem arp;
	static int num;	//����
	static Log_file diary[50];//��־
	static FILE* fp;
	//д����־
	static void write2log_ip(Data_t*);					//ip����
	static void write2log_arp(ARPFrame_t*);				//arp����
	static void write2log_ip(const char* a, Data_t*);	//ip����
	static void Print_file();							//��ӡ��־
};
pcap_if_t* alldevs;
pcap_if_t* d;
pcap_t* ahandle;			//open������
pcap_addr* a;				//������Ӧ�ĵ�ַ
char errbuf[PCAP_ERRBUF_SIZE];
char* pcap_src_if_string;

pcap_if_t* net[10];
char ip[10][20];
char mask[10][20];
BYTE selfmac[6];
char name[100];


BYTE broadcast[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };
//�Ƚ����������Ƿ���ͬ
bool Compare_MAC(BYTE a[], BYTE b[]);
//	��ȡ�Լ���IP
void find_alldevs();	//��ȡ�������豸�б�������ip����ip������,��ȡIP��mask��������������
//	����ip�����������������
DWORD getnet(DWORD ip, DWORD mask);
//	������ӿ�
pcap_t* open(char* name);
//	��ȡ�Լ���MAC
void Get_SelfMac(DWORD ip);
//	��ȡֱ�����ӵ�����mac
void getothermac(DWORD ip_, BYTE mac[]);
//	�������ݱ���д����־
int iprecv(pcap_pkthdr* pkt_header, const u_char* pkt_data);
//	���ݱ�ת��,�޸�Դmac��Ŀ��mac
void resend(ICMP_t, BYTE dmac[]);
//	��ӡmac
void Print_Mac(BYTE MAC[]);
//	�̺߳���
DWORD WINAPI handlerRequest(LPVOID lparam);
//	��ӡIp
void ipprint(DWORD ip);
//	���У���
bool Check_checksum(Data_t*);
//	����У���
void setchecksum(Data_t*);