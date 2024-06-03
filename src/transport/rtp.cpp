#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "rtp.h"


void rtpHeaderInit(struct RtpPacket* rtpPacket, uint8_t csrcLen, uint8_t extension,
                    uint8_t padding, uint8_t version, uint8_t payloadType, uint8_t marker,
                    uint16_t seq, uint32_t timestamp, uint32_t ssrc)
{
    rtpPacket->rtpheader.csrcLen = csrcLen;
    rtpPacket->rtpheader.extension = extension;
    rtpPacket->rtpheader.marker= marker;
    rtpPacket->rtpheader.padding = padding;
    rtpPacket->rtpheader.payloadType = payloadType;
    rtpPacket->rtpheader.seq = seq;
    rtpPacket->rtpheader.ssrc = ssrc;
    rtpPacket->rtpheader.timestamp = timestamp;
    rtpPacket->rtpheader.version = version;

}

int rtpSendpacket(int socket,const char* ip,int16_t port,struct RtpPacket* rtpPacket,uint32_t dateSize)
{
    struct sockaddr_in addr;
    int ret = 0;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    rtpPacket->rtpheader.seq = htons(rtpPacket->rtpheader.seq);
    rtpPacket->rtpheader.timestamp = htonl(rtpPacket->rtpheader.timestamp);
    rtpPacket->rtpheader.ssrc = htonl(rtpPacket->rtpheader.ssrc);

    ret = sendto(socket,(void*)rtpPacket,dateSize+RTP_HEADER_SIZE,0,(struct sockaddr*)&addr,sizeof(addr));

    rtpPacket->rtpheader.seq = ntohs(rtpPacket->rtpheader.seq);
    rtpPacket->rtpheader.timestamp = ntohl(rtpPacket->rtpheader.timestamp);
    rtpPacket->rtpheader.ssrc = ntohl(rtpPacket->rtpheader.ssrc);

    return ret;

}