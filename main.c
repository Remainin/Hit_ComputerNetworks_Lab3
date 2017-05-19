/*
* THIS FILE IS FOR IP TEST
*/
// system support
#include "sysInclude.h"

extern void ip_DiscardPkt(char* pBuffer,int type);

extern void ip_SendtoLower(char*pBuffer,int length);

extern void ip_SendtoUp(char *pBuffer,int length);

extern unsigned int getIpv4Address();

// implemented by students

//定义Ipv4结构体，保存Ivp4的头部相关信息
struct Ipv4
{
  char version_ihl;			//版本号&收首部长度
  char type_of_service;			//服务类型
  short total_length;			//总长度
  short identification;			//标识
  short fragment_offset;		//段偏移量
  char time_to_live;			//生存时间
  char protocol;				//协议类型
  short header_checksum;		//首部校验和
  unsigned int source_address;	//源IP地址
  unsigned int destination_address;	//目的IP地址
  Ipv4() {					//初始化归0
    memset(this,0,sizeof(Ipv4));
  }
  Ipv4(unsigned int len,unsigned int srcAddr,unsigned int dstAddr,
    byte _protocol,byte ttl) {	//另外一种初始化方法，传入参数，构造IP头部字段
    memset(this,0,sizeof(Ipv4));
    version_ihl = 0x45;
    total_length = htons(len+20);
    time_to_live = ttl;
    protocol = _protocol;
    source_address = htonl(srcAddr);
    destination_address = htonl(dstAddr);
    
    char *pBuffer;
    memcpy(pBuffer,this,sizeof(Ipv4));//将头部先输入到接受缓冲区中
    int sum = 0;				//开始计算头部校验和
    for(int i = 0; i < 10; i++) {
        if(i != 5) {
          sum += (int)((unsigned char)pBuffer[i*2] << 8);
          sum += (int)((unsigned char)pBuffer[i*2+1]);
        }
    }
    while((sum & 0xffff0000) != 0) {//将进位的1回加到尾部
      sum = (sum & 0xffff) + ((sum >> 16) & 0xffff);
    }
    unsigned short int ssum = sum;
    header_checksum = htons(~ssum);	//取反码作为校验和
  }
};

int stud_ip_recv(char *pBuffer,unsigned short length) //接收接口
{
  Ipv4 *ipv4 = new Ipv4();
  *ipv4 = *(Ipv4*)pBuffer;	//获取接收缓冲区的IP头部字段
  int version = 0xf & ((ipv4->version_ihl)>> 4);
  if(version != 4)  {		//判断版本号是否为4
    ip_DiscardPkt(pBuffer,STUD_IP_TEST_VERSION_ERROR);
    return 1;
  }
  int ihl = 0xf & ipv4->version_ihl;
  if(ihl < 5) {			//判断头部字段是否为20字节
    ip_DiscardPkt(pBuffer,STUD_IP_TEST_HEADLEN_ERROR);
    return 1;
  }
  int ttl = (int)ipv4->time_to_live;
  if(ttl == 0) {			//判断TTL是否合法
    ip_DiscardPkt(pBuffer,STUD_IP_TEST_TTL_ERROR);
    return 1;
  }
  int destination_address = ntohl(ipv4->destination_address);  	//判断目的地址是否为本机地址
  if(destination_address != getIpv4Address() && destination_address != 0xffffffff) {
    ip_DiscardPkt(pBuffer,STUD_IP_TEST_DESTINATION_ERROR);
    return 1;
  }
  int header_checksum = ntohs(ipv4->header_checksum);
  int sum = 0;
  for(int i = 0; i < ihl*2; i++) {	//计算目前接收到的头部的校验和
    if(i!=5)
    {
      sum += (int)((unsigned char)pBuffer[i*2] << 8);
      sum += (int)((unsigned char)pBuffer[i*2+1]);
    }
  }

  while((sum & 0xffff0000) != 0) {
    sum = (sum & 0xffff) + ((sum >> 16) & 0xffff);
  }
  unsigned short int ssum = (~sum) & 0xffff;
  if(ssum != header_checksum) {	//通过和曾经的校验和字段对比判断IP头部是否发生了改变
    ip_DiscardPkt(pBuffer,STUD_IP_TEST_CHECKSUM_ERROR);
    return 1;
  }
  ip_SendtoUp(pBuffer,length);	//一切均合法，发送给上一层
  return 0;
}
			//发送接口
int stud_ip_Upsend(char *pBuffer,unsigned short len,unsigned int srcAddr,
           unsigned int dstAddr,byte protocol,byte ttl)
{
  char *pack_to_sent = new char[len+20];	//加上头部字段的长度
  memset(pack_to_sent,0,len+20);		//初始化头部字段
  *((Ipv4*)pack_to_sent) = Ipv4(len,srcAddr,dstAddr,protocol,ttl);//填充头部字段
  memcpy(pack_to_sent+20,pBuffer,len);	//将上层协议数据报文填充形成完整IP报文
  ip_SendtoLower(pack_to_sent,len+20);	//发送给下一层
  delete[] pack_to_sent;
  
  return 0;
}
