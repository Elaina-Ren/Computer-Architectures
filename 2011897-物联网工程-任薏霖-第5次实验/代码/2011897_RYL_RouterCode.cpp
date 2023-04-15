#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "header.h"
#include <stdio.h>
#pragma comment(lib,"ws2_32.lib")	//����ws2_32.lib���ļ�������Ŀ��
//	�궨��
#define PACAP_ERRBUF_SIZE 10
#define MAX_IP_NUM 10


//	���߳�
HANDLE hThread;
DWORD dwThreadId;
Log_file ltable;
int index;
//	MAIN����
int main(){
	printf("============================================================\n");
	printf("\n");
	printf("|| ������Ŀ��������");
	scanf("%d", &index);
	//	const char* ��char*��ת��
	pcap_src_if_string = new char[strlen(PCAP_SRC_IF_STRING)];
	strcpy(pcap_src_if_string, PCAP_SRC_IF_STRING);
	//	��ȡ����ip
	find_alldevs();
	//	�����ʱ�洢��IP��ַ��MAC��ַ
	for (int i = 0; i < 2; i++){
		printf("%s\t", ip[i]);
		printf("%s\n", mask[i]);
	}
	//	��ȡ����MAC
	Get_SelfMac(inet_addr(ip[0]));
	//	��ӡ����MAC
	Print_Mac(selfmac);
	BYTE mac[6];
	int Choice;
	//	��ʼ��·�ɱ�ṹ��
	Route_table Router;
	//	��ʼ��·�ɱ���
	Route_item Item;
	hThread = CreateThread(NULL, NULL, handlerRequest, LPVOID(&Router), 0, &dwThreadId);
	while (1){
		printf("==================== 1. ���·�ɱ��� ====================\n");
		printf("==================== 2. ɾ��·�ɱ��� ====================\n");
		printf("==================== 3.  ��ӡ·�ɱ�  ====================\n");
		printf("\n");
		printf("|| ������������ ��");
		scanf("%d", &Choice);
		printf("\n");
		if (Choice == 1){
			Route_item Item_2;
			char t[30];
			printf("==========  ���������룺");
			scanf("%s", &t);
			Item_2.mask = inet_addr(t);
			printf("==========  ������Ŀ�����磺");
			scanf("%s", &t);
			Item_2.net = inet_addr(t);
			printf("==========  ��������һ����ַ��");
			scanf("%s", &t);
			Item_2.nextip = inet_addr(t);
			Item_2.type = 1;
			Router.add(&Item_2);
			printf("\n");
		}
		else if (Choice == 2){
			printf("==========  ������ɾ�������ţ�\n");
			int number;
			scanf("%d", &number);
			Router.remove(number);
			printf("\n");
		}
		else if (Choice == 3){
			Router.Print_file();
			printf("\n");
		}
		else {
			printf("==========  ��Ч������������ѡ��  ==========\n");
		}
	}
	Route_table table;
	table.Print_file();
	return 0;
}
//	==================== �������� ====================
//	��ȡ��Ӧ������������IP��ַ
void find_alldevs()	{
	if (pcap_findalldevs_ex(pcap_src_if_string, NULL, &alldevs, errbuf) == -1){
		printf("%s", "error");
	}
	else{
		int i = 0;
		//	��ȡ������ӿ��豸��ip��ַ��Ϣ
		for (d = alldevs; d != NULL; d = d->next){
			if (i == index){
				net[i] = d;
				int t = 0;
				for (a = d->addresses; a != nullptr; a = a->next){
					if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr){
						printf("%d ", i);
						printf("%s\t", d->name, d->description);
						printf("%s\t%s\n", "IP��ַ:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
						//	�洢��ӦIP��ַ��MAC��ַ
						strcpy(ip[t], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
						strcpy(mask[t++], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
					}
				}
				//	�򿪸�����
				ahandle = open(d->name);
			}
			i++;
		}
	}
	pcap_freealldevs(alldevs);
}
//	������ӿ�
pcap_t* open(char* name){
	pcap_t* temp = pcap_open(name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
	if (temp == NULL)
		printf("==========  error  ==========");
	return temp;
}
//	ʶ��Ƚ�MAC��ַ�����˱���
bool Compare_MAC(BYTE a[6], BYTE b[6]){
	//	�д�ģ�ע�⣡
	for (int i = 0; i < 6; i++){
		if (a[i] != b[i])
			return false;
	}
	return true;
}
//	��ñ���IP��ַ�Լ���Ӧ��MAC��ַ
void Get_SelfMac(DWORD ip){
	memset(selfmac, 0, sizeof(selfmac));
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++) {
		//	��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
		//	��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
		ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;
		//	��ARPFrame.SendHa����Ϊ����������MAC��ַ
		ARPFrame.SendHa[i] = 0x0f;
		//	��ARPFrame.RecvHa����Ϊ0
		ARPFrame.RecvHa[i] = 0;
	}
	ARPFrame.FrameHeader.FrameType = htons(0x806);	//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);			//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);			//Э������ΪIP
	ARPFrame.HLen = 6;								//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;								//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);				//����ΪARP����
	//	��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARPFrame.SendIP = inet_addr("122.122.122.122");
	ARPFrame.RecvIP = ip;
	u_char* h = (u_char*)&ARPFrame;
	int len = sizeof(ARPFrame_t);
	if (ahandle == nullptr) 
		printf("�����ӿڴ򿪴���\n");
	else{
		/*
		adhandle ���� ָ��ͨ���Ŀ�ӿ������������ݰ���ͨ���ǵ��� pcap_open()�����ɹ��󷵻ص�ֵ
		ARPFrame ���� ָ����Ҫ���͵����ݰ������а�������ͷ����Ϣ
		size ���� ָ����С
		*/
		if (pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0){
			//	���ʹ�����
			printf("senderror\n");
		}
		else{
			//	���ͳɹ�
			while (1){
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
				if (rtn == 1){
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					//	���Ŀ��MAC��ַ
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x806){
						if (!Compare_MAC(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC) && Compare_MAC(IPPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC)){
							ltable.write2log_arp(IPPacket);
							//	���ԴMAC��ַ��ԴMAC��ַ��Ϊ����MAC��ַ
							for (int i = 0; i < 6; i++)
								selfmac[i] = IPPacket->FrameHeader.SrcMAC[i];
							//	�Ѿ�������MAC��ַ������˳�
							break;
						}
					}
				}
			}
		}
	}
}
//	��ȡĿ��ip��Ӧ��mac
void getothermac(DWORD ip_, BYTE mac[]){
	memset(mac, 0, sizeof(mac));
	ARPFrame_t ARPFrame;
	//	��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++){
		ARPFrame.FrameHeader.SrcMAC[i] = selfmac[i];
		ARPFrame.SendHa[i] = selfmac[i];
	}
	ARPFrame.FrameHeader.FrameType = htons(0x806);	//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);			//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);			//Э������ΪIP
	ARPFrame.HLen = 6;								//Ӳ����ַ����Ϊ 6
	ARPFrame.PLen = 4;								//Э���ַ��Ϊ 4
	ARPFrame.Operation = htons(0x0001);				//����ΪARP����
	//	��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARPFrame.SendIP = inet_addr(ip[0]);
	//	ipprint(ARPFrame.SendIP);
	//	��ARPFrame.RecvHa����Ϊ0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;
	//	��ARPFrame.RecvIP����Ϊ�����IP��ַ
	ARPFrame.RecvIP = ip_;
	u_char* h = (u_char*)&ARPFrame;
	int len = sizeof(ARPFrame_t);
	if (ahandle == nullptr) 
		printf("�����ӿڴ򿪴���\n");
	else{
		if (pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0){
			//	���ʹ�����
			printf("senderror\n");
		}
		else{
			//���ͳɹ�
			while (1){
				//printf("send\n");
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
				//pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
				if (rtn == 1){
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					//���Ŀ��MAC��ַ
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x806){
						//&&ip==IPPacket->SendIP
						if (!Compare_MAC(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC) && Compare_MAC(IPPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC) && IPPacket->SendIP == ip_){
							ltable.write2log_arp(IPPacket);
							//	���ԴMAC��ַ
							for (int i = 0; i < 6; i++)
								mac[i] = IPPacket->FrameHeader.SrcMAC[i];
							break;
						}
					}
				}
			}
		}
	}
}
//	��ӡmac
void Print_Mac(BYTE MAC[]){
	printf("MAC��ַΪ�� ");
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}
//	���·�ɱ���
void Route_table::add(Route_item* item){
	Route_item* pointer;
	// Ĭ��·�������·�ɱ�����ͷ��
	if (item->type == 0){
		item->nextitem = head->nextitem;
		head->nextitem = item;
		item->type = 0;
	}
	//�����������ƥ��ԭ��
	else{
		for (pointer = head->nextitem; pointer != tail && pointer->nextitem != tail; pointer = pointer->nextitem){
			if (item->mask < pointer->mask && item->mask >= pointer->nextitem->mask || pointer->nextitem == tail)
				break;
		}
		//���뵽����λ��
		item->nextitem = pointer->nextitem;
		pointer->nextitem = item;
		//a->type = 1;
	}
	//	��������
	Route_item* p = head->nextitem;
	for (int i = 0; p != tail; p = p->nextitem, i++){
		p->index = i;
	}
	num++;
}
//	��ӡ·�ɱ���
void Route_item::Print_item(){
	//index mask net nextip
	in_addr addr;
	//printf("%d   ", index);
	//printf("%d   ");
	addr.s_addr = mask;
	char* pchar = inet_ntoa(addr);
	printf("%s\t    ", pchar);

	addr.s_addr = net;
	pchar = inet_ntoa(addr);
	printf("%s\t   ", pchar);

	addr.s_addr = nextip;
	pchar = inet_ntoa(addr);
	printf("%s\t\t", pchar);
	printf("\n");
}
//	��ӡ·�ɱ�
void Route_table::Print_file(){
	Route_item* p = head->nextitem;
	printf("     ����             Ŀ��IP             ��һ��   \n");
	for (; p != tail; p = p->nextitem){
		p->Print_item();
	}
}
//	��ʼ��·�ɱ����Ĭ��·��
Route_table::Route_table(){
	head = new Route_item;
	tail = new Route_item;
	head->nextitem = tail;
	num = 0;
	for (int i = 0; i < 2; i++){
		Route_item* temp = new Route_item;
		//	����������ip ��������а�λ�뼴Ϊ��������
		temp->net = (inet_addr(ip[i])) & (inet_addr(mask[i]));
		temp->mask = inet_addr(mask[i]);
		temp->type = 0;		//0��ʾֱ��Ͷ�ݵ����磬����ɾ��
		this->add(temp);	//��ӱ���
	}
}
//	ɾ��·�ɱ���
void Route_table::remove(int index){
	for (Route_item* t = head; t->nextitem != tail; t = t->nextitem){
		if (t->nextitem->index == index){
			//	ֱ��Ͷ�ݵ�·�ɱ����ɾ��
			if (t->nextitem->type == 0){
				printf("==========  �����ɾ��  ==========\n");
				return;
			}
			else{
				t->nextitem = t->nextitem->nextitem;
				return;
			}
		}
	}
	printf("�޸ñ���\n");
}
//	�������ݱ�
int iprecv(pcap_pkthdr* pkt_header, const u_char* pkt_data){
	int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
	return rtn;
}
//	���ݱ�ת�� 
void resend(ICMP_t data, BYTE dmac[]){
	Data_t* temp = (Data_t*)&data;
	//	�޸�MAC��ַ
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);	//ԴMACΪ����MAC
	memcpy(temp->FrameHeader.DesMAC, dmac, 6);						//Ŀ��MACΪ��һ��MAC
	//	�޸�TTLֵ
	temp->IPHeader.TTL -= 1;			//TTL-1
		//	��ʱ����
	if (temp->IPHeader.TTL < 0)
		return;//����
	setchecksum(temp);												//��������У���
	int rtn = pcap_sendpacket(ahandle, (const u_char*)temp, sizeof(temp));	//�������ݱ�
	if (rtn == 0)
		ltable.write2log_ip("[forward IP]", temp);//д����־
}
//	����·�ɱ��Ӧ���� ���� ��������һ����ip��ַ
DWORD Route_table::lookup(DWORD ip){
	Route_item* t = head->nextitem;
	for (; t != tail; t = t->nextitem){
		//	Ŀ��IP������ ȷ��Ŀ������ ���� �ٷ�����һ��
		if ((t->mask & ip) == t->net)
			return t->nextip;
	}
	return -1;
}

int Log_file::num = 0;
Log_file Log_file::diary[50] = {};
FILE* Log_file::fp = nullptr;
//	���ļ�д��
Log_file::Log_file(){
	fp = fopen("Log_File.txt", "a + "); //��һ������ǰ���ļ�λ�á�����֮���Ǵ��ļ���ʽ
}
//	�ر��ļ�
Log_file::~Log_file(){
	fclose(fp);
}

//	��ӡ��־
void Log_file::Print_file(){
	int i;
	if (num > 50)
		i = (num + 1) % 50;
	else i = 0;
	for (; i < num % 50; i++){
		printf("%d ", diary[i].index);
		printf("%s\t ", diary[i].type);
		//printf("%s\n",diary[i].detail);
		if (!strcmp(diary[i].type, "ARP")){
			in_addr addr;
			addr.s_addr = diary[i].arp.ip;
			char* pchar = inet_ntoa(addr);
			printf("%s\t", pchar);
			for (int i = 0; i < 5; i++){
				printf("%02X.", diary[i].arp.mac[i]);
			}
			printf("%02X\n", diary[i].arp.mac[5]);
		}
		else if (!strcmp(diary[i].type, "IP")){
			in_addr addr;
			addr.s_addr = diary[i].ip.sip;
			char* pchar = inet_ntoa(addr);
			printf("SrcIP��%s\t", pchar);
			addr.s_addr = diary[i].ip.dip;
			pchar = inet_ntoa(addr);
			printf("DesIP��%s\t", pchar);
			printf("SrcMAC: ");
			for (int i = 0; i < 5; i++){
				printf("%02X.", diary[i].ip.smac[i]);
			}
			printf("%02X\t", diary[i].ip.smac[5]);
			printf("DesMAC: ");
			for (int i = 0; i < 5; i++){
				printf("%02X.", diary[i].ip.dmac[i]);
			}
			printf("%02X\n", diary[i].ip.dmac[5]);
		}
	}
}
//	��¼ ip ����
void Log_file::write2log_ip(Data_t* pkt){
	diary[num % 100].index = num++;
	strcpy(diary[num % 100].type, "IP");
	diary[num % 100].ip.sip = pkt->IPHeader.SrcIP;
	diary[num % 100].ip.dip = pkt->IPHeader.DstIP;

	memcpy(diary[num % 100].ip.smac, pkt->FrameHeader.SrcMAC, 6);
	memcpy(diary[num % 100].ip.dmac, pkt->FrameHeader.DesMAC, 6);
}
//	��¼IP/Ŀ��IP/ԴMAC...������
void Log_file::write2log_ip(const char* a, Data_t* pkt)
{
	//fprintf(fp, "IP  ");
	fprintf(fp, a);
	fprintf(fp, "  ");
	in_addr addr;
	addr.s_addr = pkt->IPHeader.SrcIP;
	char* pchar = inet_ntoa(addr);

	fprintf(fp, "SrcIP�� ");
	fprintf(fp, "%s  ", pchar);
	fprintf(fp, "DesIP�� ");
	addr.s_addr = pkt->IPHeader.DstIP;
	fprintf(fp, "%s  ", pchar);
	fprintf(fp, "SrcMAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.SrcMAC[i]);
	fprintf(fp, "%02X  ", pkt->FrameHeader.SrcMAC[5]);
	fprintf(fp, "DesMAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.DesMAC[i]);
	fprintf(fp, "%02X\n", pkt->FrameHeader.DesMAC[5]);

}

//	��¼arp����
void Log_file::write2log_arp(ARPFrame_t* pkt){
	fprintf(fp, "[ ARP ] ");
	in_addr addr;
	addr.s_addr = pkt->SendIP;
	char* pchar = inet_ntoa(addr);
	fprintf(fp, "DesIP�� ");
	fprintf(fp, "%s  ", pchar);
	fprintf(fp, "DesMAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->SendHa[i]);
	fprintf(fp, "%02X\n", pkt->SendHa[5]);
}
//	���պʹ����̺߳���
DWORD WINAPI handlerRequest(LPVOID lparam){
	Route_table rtable = *(Route_table*)(LPVOID)lparam;
	while (1){
		pcap_pkthdr* pkt_header; 
		const u_char* pkt_data;
		//	ͨ��pcap_next_ex()�����Ա����������յ������ݰ�����ѭ������
		while (1){
			int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
			//	���յ���Ϣ ���� ����
			if (rtn)	
				break;
		}
		FrameHeader_t* header = (FrameHeader_t*)pkt_data;
		//	�жϲ����ĵ�Ŀ��MAC�Ǳ���MAC
		if (Compare_MAC(header->DesMAC, selfmac)){
			//	�յ�IP��ʽ���ݱ�
			if (ntohs(header->FrameType) == 0x800){
				Data_t* data = (Data_t*)pkt_data;
				//	д����־
				ltable.write2log_ip("[receive IP]", data);	
				DWORD ip1_ = data->IPHeader.DstIP;	// ��ip1����ΪĿ��Ipͷ�ײ�

				//	�ж��Ƿ��ܲ��ҵ���һ��ip ip1
				DWORD ip_ = rtable.lookup(ip1_);	//�����Ƿ��ж�Ӧ����
				if (ip_ == -1)						//���û���ҵ���һ��IP��ַ����
					continue;

				//	�ж�У��� ���� У��Ͳ���ȷ����ֱ�Ӷ��������д���
				if (Check_checksum(data)){
					if (data->IPHeader.DstIP != inet_addr(ip[0]) && data->IPHeader.DstIP != inet_addr(ip[1])){
						int t1 = Compare_MAC(data->FrameHeader.DesMAC, broadcast);
						int t2 = Compare_MAC(data->FrameHeader.SrcMAC, broadcast);
						if (!t1 && !t2){
							//	ICMP���İ���IP���ݰ���ͷ����������
							ICMP_t* temp_ = (ICMP_t*)pkt_data;
							ICMP_t temp = *temp_;
							BYTE mac[6];
							//	����鵽��һ��IP��ַ
							if (ip_ == 0){
								//���ARP����û���������ݣ�����Ҫ��ȡARP
								if (!Arp_table::lookup(ip1_, mac))
									Arp_table::insert(ip1_, mac);
								//printMac(mac);
								resend(temp, mac);
							}
							//	���û���ҵ���һ��IP
							else if (ip_ != -1){
								//	û�ڱ��в��ҵ� ���� ��Ӳ�ת��
								if (!Arp_table::lookup(ip_, mac))
									Arp_table::insert(ip_, mac);
								resend(temp, mac);
							}
						}
					}
				}
			}
		}
	}
}
//	��ӡIP
void ipprint(DWORD ip){
	in_addr addr;
	addr.s_addr = ip;
	char* pchar = inet_ntoa(addr);
	printf("%s\t", pchar);
	printf("\n");
}
//	����У���
void setchecksum(Data_t* temp){
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++){
		sum += t[i];
		while (sum >= 0x10000){
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//ȡ��
}
//	���У���
bool Check_checksum(Data_t* temp){
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++){
		sum += t[i];
		//����ԭ��У������
		while (sum >= 0x10000){
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	//printf("%d", (WORD)~temp->IPHeader.Checksum);
	if (sum == 65535)
		return 1;
	return 0;
}

int Arp_table::num = 0;
void Arp_table::insert(DWORD ip, BYTE mac[6]){
	atable[num].ip = ip;
	//	ͨ��α��ARP�� ��ȡԶ��MAC��ַ
	getothermac(ip, atable[num].mac);
	memcpy(mac, atable[num].mac, 6);
	num++;
}
int Arp_table::lookup(DWORD ip, BYTE mac[6]){
	memset(mac, 0, 6);
	for (int i = 0; i < num; i++){
		if (ip == atable[i].ip){
			memcpy(mac, atable[i].mac, 6);
			return 1;
		}
	}
	//	δ�ҵ� ���� ����0
	return 0;
}