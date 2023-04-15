#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "header.h"
#include <stdio.h>
#pragma comment(lib,"ws2_32.lib")	//链接ws2_32.lib库文件到此项目中
//	宏定义
#define PACAP_ERRBUF_SIZE 10
#define MAX_IP_NUM 10


//	多线程
HANDLE hThread;
DWORD dwThreadId;
Log_file ltable;
int index;
//	MAIN函数
int main(){
	printf("============================================================\n");
	printf("\n");
	printf("|| 请输入目标网卡：");
	scanf("%d", &index);
	//	const char* 到char*的转换
	pcap_src_if_string = new char[strlen(PCAP_SRC_IF_STRING)];
	strcpy(pcap_src_if_string, PCAP_SRC_IF_STRING);
	//	获取本机ip
	find_alldevs();
	//	输出此时存储的IP地址与MAC地址
	for (int i = 0; i < 2; i++){
		printf("%s\t", ip[i]);
		printf("%s\n", mask[i]);
	}
	//	获取本机MAC
	Get_SelfMac(inet_addr(ip[0]));
	//	打印本机MAC
	Print_Mac(selfmac);
	BYTE mac[6];
	int Choice;
	//	初始化路由表结构体
	Route_table Router;
	//	初始化路由表项
	Route_item Item;
	hThread = CreateThread(NULL, NULL, handlerRequest, LPVOID(&Router), 0, &dwThreadId);
	while (1){
		printf("==================== 1. 添加路由表项 ====================\n");
		printf("==================== 2. 删除路由表项 ====================\n");
		printf("==================== 3.  打印路由表  ====================\n");
		printf("\n");
		printf("|| 请输入操作序号 ：");
		scanf("%d", &Choice);
		printf("\n");
		if (Choice == 1){
			Route_item Item_2;
			char t[30];
			printf("==========  请输入掩码：");
			scanf("%s", &t);
			Item_2.mask = inet_addr(t);
			printf("==========  请输入目的网络：");
			scanf("%s", &t);
			Item_2.net = inet_addr(t);
			printf("==========  请输入下一跳地址：");
			scanf("%s", &t);
			Item_2.nextip = inet_addr(t);
			Item_2.type = 1;
			Router.add(&Item_2);
			printf("\n");
		}
		else if (Choice == 2){
			printf("==========  请输入删除表项编号：\n");
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
			printf("==========  无效操作，请重新选择  ==========\n");
		}
	}
	Route_table table;
	table.Print_file();
	return 0;
}
//	==================== 函数定义 ====================
//	获取对应网卡网卡号与IP地址
void find_alldevs()	{
	if (pcap_findalldevs_ex(pcap_src_if_string, NULL, &alldevs, errbuf) == -1){
		printf("%s", "error");
	}
	else{
		int i = 0;
		//	获取该网络接口设备的ip地址信息
		for (d = alldevs; d != NULL; d = d->next){
			if (i == index){
				net[i] = d;
				int t = 0;
				for (a = d->addresses; a != nullptr; a = a->next){
					if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr){
						printf("%d ", i);
						printf("%s\t", d->name, d->description);
						printf("%s\t%s\n", "IP地址:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
						//	存储对应IP地址与MAC地址
						strcpy(ip[t], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
						strcpy(mask[t++], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
					}
				}
				//	打开该网卡
				ahandle = open(d->name);
			}
			i++;
		}
	}
	pcap_freealldevs(alldevs);
}
//	打开网络接口
pcap_t* open(char* name){
	pcap_t* temp = pcap_open(name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
	if (temp == NULL)
		printf("==========  error  ==========");
	return temp;
}
//	识别比较MAC地址，过滤报文
bool Compare_MAC(BYTE a[6], BYTE b[6]){
	//	有大改！注意！
	for (int i = 0; i < 6; i++){
		if (a[i] != b[i])
			return false;
	}
	return true;
}
//	获得本地IP地址以及对应的MAC地址
void Get_SelfMac(DWORD ip){
	memset(selfmac, 0, sizeof(selfmac));
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++) {
		//	将APRFrame.FrameHeader.DesMAC设置为广播地址
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
		//	将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
		ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;
		//	将ARPFrame.SendHa设置为本机网卡的MAC地址
		ARPFrame.SendHa[i] = 0x0f;
		//	将ARPFrame.RecvHa设置为0
		ARPFrame.RecvHa[i] = 0;
	}
	ARPFrame.FrameHeader.FrameType = htons(0x806);	//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);			//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);			//协议类型为IP
	ARPFrame.HLen = 6;								//硬件地址长度为6
	ARPFrame.PLen = 4;								//协议地址长为4
	ARPFrame.Operation = htons(0x0001);				//操作为ARP请求
	//	将ARPFrame.SendIP设置为本机网卡上绑定的IP地址
	ARPFrame.SendIP = inet_addr("122.122.122.122");
	ARPFrame.RecvIP = ip;
	u_char* h = (u_char*)&ARPFrame;
	int len = sizeof(ARPFrame_t);
	if (ahandle == nullptr) 
		printf("网卡接口打开错误\n");
	else{
		/*
		adhandle —— 指定通过哪块接口网卡发送数据包，通常是调用 pcap_open()函数成功后返回的值
		ARPFrame —— 指向需要发送的数据包，其中包含各层头部信息
		size —— 指定大小
		*/
		if (pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0){
			//	发送错误处理
			printf("senderror\n");
		}
		else{
			//	发送成功
			while (1){
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
				if (rtn == 1){
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					//	输出目的MAC地址
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x806){
						if (!Compare_MAC(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC) && Compare_MAC(IPPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC)){
							ltable.write2log_arp(IPPacket);
							//	输出源MAC地址，源MAC地址即为所需MAC地址
							for (int i = 0; i < 6; i++)
								selfmac[i] = IPPacket->FrameHeader.SrcMAC[i];
							//	已经捕获到了MAC地址，因此退出
							break;
						}
					}
				}
			}
		}
	}
}
//	获取目的ip对应的mac
void getothermac(DWORD ip_, BYTE mac[]){
	memset(mac, 0, sizeof(mac));
	ARPFrame_t ARPFrame;
	//	将APRFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	//将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++){
		ARPFrame.FrameHeader.SrcMAC[i] = selfmac[i];
		ARPFrame.SendHa[i] = selfmac[i];
	}
	ARPFrame.FrameHeader.FrameType = htons(0x806);	//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);			//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);			//协议类型为IP
	ARPFrame.HLen = 6;								//硬件地址长度为 6
	ARPFrame.PLen = 4;								//协议地址长为 4
	ARPFrame.Operation = htons(0x0001);				//操作为ARP请求
	//	将ARPFrame.SendIP设置为本机网卡上绑定的IP地址
	ARPFrame.SendIP = inet_addr(ip[0]);
	//	ipprint(ARPFrame.SendIP);
	//	将ARPFrame.RecvHa设置为0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;
	//	将ARPFrame.RecvIP设置为请求的IP地址
	ARPFrame.RecvIP = ip_;
	u_char* h = (u_char*)&ARPFrame;
	int len = sizeof(ARPFrame_t);
	if (ahandle == nullptr) 
		printf("网卡接口打开错误\n");
	else{
		if (pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0){
			//	发送错误处理
			printf("senderror\n");
		}
		else{
			//发送成功
			while (1){
				//printf("send\n");
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
				//pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
				if (rtn == 1){
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					//输出目的MAC地址
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x806){
						//&&ip==IPPacket->SendIP
						if (!Compare_MAC(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC) && Compare_MAC(IPPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC) && IPPacket->SendIP == ip_){
							ltable.write2log_arp(IPPacket);
							//	输出源MAC地址
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
//	打印mac
void Print_Mac(BYTE MAC[]){
	printf("MAC地址为： ");
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}
//	添加路由表项
void Route_table::add(Route_item* item){
	Route_item* pointer;
	// 默认路由添加在路由表链表头部
	if (item->type == 0){
		item->nextitem = head->nextitem;
		head->nextitem = item;
		item->type = 0;
	}
	//其它，按照最长匹配原则
	else{
		for (pointer = head->nextitem; pointer != tail && pointer->nextitem != tail; pointer = pointer->nextitem){
			if (item->mask < pointer->mask && item->mask >= pointer->nextitem->mask || pointer->nextitem == tail)
				break;
		}
		//插入到合适位置
		item->nextitem = pointer->nextitem;
		pointer->nextitem = item;
		//a->type = 1;
	}
	//	更新索引
	Route_item* p = head->nextitem;
	for (int i = 0; p != tail; p = p->nextitem, i++){
		p->index = i;
	}
	num++;
}
//	打印路由表项
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
//	打印路由表
void Route_table::Print_file(){
	Route_item* p = head->nextitem;
	printf("     掩码             目的IP             下一跳   \n");
	for (; p != tail; p = p->nextitem){
		p->Print_item();
	}
}
//	初始化路由表，添加默认路由
Route_table::Route_table(){
	head = new Route_item;
	tail = new Route_item;
	head->nextitem = tail;
	num = 0;
	for (int i = 0; i < 2; i++){
		Route_item* temp = new Route_item;
		//	本机网卡的ip 和掩码进行按位与即为所在网络
		temp->net = (inet_addr(ip[i])) & (inet_addr(mask[i]));
		temp->mask = inet_addr(mask[i]);
		temp->type = 0;		//0表示直接投递的网络，不可删除
		this->add(temp);	//添加表项
	}
}
//	删除路由表项
void Route_table::remove(int index){
	for (Route_item* t = head; t->nextitem != tail; t = t->nextitem){
		if (t->nextitem->index == index){
			//	直接投递的路由表项不可删除
			if (t->nextitem->type == 0){
				printf("==========  该项不可删除  ==========\n");
				return;
			}
			else{
				t->nextitem = t->nextitem->nextitem;
				return;
			}
		}
	}
	printf("无该表项\n");
}
//	接收数据报
int iprecv(pcap_pkthdr* pkt_header, const u_char* pkt_data){
	int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
	return rtn;
}
//	数据报转发 
void resend(ICMP_t data, BYTE dmac[]){
	Data_t* temp = (Data_t*)&data;
	//	修改MAC地址
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);	//源MAC为本机MAC
	memcpy(temp->FrameHeader.DesMAC, dmac, 6);						//目的MAC为下一跳MAC
	//	修改TTL值
	temp->IPHeader.TTL -= 1;			//TTL-1
		//	超时则丢弃
	if (temp->IPHeader.TTL < 0)
		return;//丢弃
	setchecksum(temp);												//重新设置校验和
	int rtn = pcap_sendpacket(ahandle, (const u_char*)temp, sizeof(temp));	//发送数据报
	if (rtn == 0)
		ltable.write2log_ip("[forward IP]", temp);//写入日志
}
//	查找路由表对应表项 —— 并给出下一跳的ip地址
DWORD Route_table::lookup(DWORD ip){
	Route_item* t = head->nextitem;
	for (; t != tail; t = t->nextitem){
		//	目的IP和掩码 确定目的网络 —— 再返回下一跳
		if ((t->mask & ip) == t->net)
			return t->nextip;
	}
	return -1;
}

int Log_file::num = 0;
Log_file Log_file::diary[50] = {};
FILE* Log_file::fp = nullptr;
//	打开文件写入
Log_file::Log_file(){
	fp = fopen("Log_File.txt", "a + "); //第一个逗号前是文件位置。逗号之后是打开文件方式
}
//	关闭文件
Log_file::~Log_file(){
	fclose(fp);
}

//	打印日志
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
			printf("SrcIP：%s\t", pchar);
			addr.s_addr = diary[i].ip.dip;
			pchar = inet_ntoa(addr);
			printf("DesIP：%s\t", pchar);
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
//	记录 ip 类型
void Log_file::write2log_ip(Data_t* pkt){
	diary[num % 100].index = num++;
	strcpy(diary[num % 100].type, "IP");
	diary[num % 100].ip.sip = pkt->IPHeader.SrcIP;
	diary[num % 100].ip.dip = pkt->IPHeader.DstIP;

	memcpy(diary[num % 100].ip.smac, pkt->FrameHeader.SrcMAC, 6);
	memcpy(diary[num % 100].ip.dmac, pkt->FrameHeader.DesMAC, 6);
}
//	记录IP/目的IP/源MAC...等类型
void Log_file::write2log_ip(const char* a, Data_t* pkt)
{
	//fprintf(fp, "IP  ");
	fprintf(fp, a);
	fprintf(fp, "  ");
	in_addr addr;
	addr.s_addr = pkt->IPHeader.SrcIP;
	char* pchar = inet_ntoa(addr);

	fprintf(fp, "SrcIP： ");
	fprintf(fp, "%s  ", pchar);
	fprintf(fp, "DesIP： ");
	addr.s_addr = pkt->IPHeader.DstIP;
	fprintf(fp, "%s  ", pchar);
	fprintf(fp, "SrcMAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.SrcMAC[i]);
	fprintf(fp, "%02X  ", pkt->FrameHeader.SrcMAC[5]);
	fprintf(fp, "DesMAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.DesMAC[i]);
	fprintf(fp, "%02X\n", pkt->FrameHeader.DesMAC[5]);

}

//	记录arp类型
void Log_file::write2log_arp(ARPFrame_t* pkt){
	fprintf(fp, "[ ARP ] ");
	in_addr addr;
	addr.s_addr = pkt->SendIP;
	char* pchar = inet_ntoa(addr);
	fprintf(fp, "DesIP： ");
	fprintf(fp, "%s  ", pchar);
	fprintf(fp, "DesMAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->SendHa[i]);
	fprintf(fp, "%02X\n", pkt->SendHa[5]);
}
//	接收和处理线程函数
DWORD WINAPI handlerRequest(LPVOID lparam){
	Route_table rtable = *(Route_table*)(LPVOID)lparam;
	while (1){
		pcap_pkthdr* pkt_header; 
		const u_char* pkt_data;
		//	通过pcap_next_ex()函数对本机网卡接收到的数据包进行循环捕获
		while (1){
			int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
			//	接收到消息 —— 跳出
			if (rtn)	
				break;
		}
		FrameHeader_t* header = (FrameHeader_t*)pkt_data;
		//	判断捕获报文的目的MAC是本机MAC
		if (Compare_MAC(header->DesMAC, selfmac)){
			//	收到IP格式数据报
			if (ntohs(header->FrameType) == 0x800){
				Data_t* data = (Data_t*)pkt_data;
				//	写入日志
				ltable.write2log_ip("[receive IP]", data);	
				DWORD ip1_ = data->IPHeader.DstIP;	// 将ip1设置为目的Ip头首部

				//	判断是否能查找到下一跳ip ip1
				DWORD ip_ = rtable.lookup(ip1_);	//查找是否有对应表项
				if (ip_ == -1)						//如果没有找到下一跳IP地址则丢弃
					continue;

				//	判断校验和 —— 校验和不正确，则直接丢弃不进行处理
				if (Check_checksum(data)){
					if (data->IPHeader.DstIP != inet_addr(ip[0]) && data->IPHeader.DstIP != inet_addr(ip[1])){
						int t1 = Compare_MAC(data->FrameHeader.DesMAC, broadcast);
						int t2 = Compare_MAC(data->FrameHeader.SrcMAC, broadcast);
						if (!t1 && !t2){
							//	ICMP报文包含IP数据包报头和其它内容
							ICMP_t* temp_ = (ICMP_t*)pkt_data;
							ICMP_t temp = *temp_;
							BYTE mac[6];
							//	如果查到下一跳IP地址
							if (ip_ == 0){
								//如果ARP表中没有所需内容，则需要获取ARP
								if (!Arp_table::lookup(ip1_, mac))
									Arp_table::insert(ip1_, mac);
								//printMac(mac);
								resend(temp, mac);
							}
							//	如果没有找到下一跳IP
							else if (ip_ != -1){
								//	没在表中查找到 —— 添加并转发
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
//	打印IP
void ipprint(DWORD ip){
	in_addr addr;
	addr.s_addr = ip;
	char* pchar = inet_ntoa(addr);
	printf("%s\t", pchar);
	printf("\n");
}
//	设置校验和
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
	temp->IPHeader.Checksum = ~sum;//取反
}
//	检查校验和
bool Check_checksum(Data_t* temp){
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++){
		sum += t[i];
		//包含原有校验和相加
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
	//	通过伪造ARP包 获取远程MAC地址
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
	//	未找到 —— 返回0
	return 0;
}