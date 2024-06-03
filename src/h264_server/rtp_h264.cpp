#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "rtp.h"

#define CLIENT_IP  "127.0.0.1"
#define CLIENT_PORT  9832

#define FPS 25



static inline int startCode3(char* buf)
{
    // printf("buf[0]=%d,buf[1]=%d,buf[2]=%d",buf[0],buf[1],buf[2]);
    if(buf[0] == 0 && buf[1] == 0 && buf[2] == 1)
    {
        // printf("find startcode 00 00 01\n");
        return 1;
    }
    else
        return 0;
}


static inline int startCode4(char* buf)
{
    if(buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 1)
    {
        // printf("find startcode 00 00 00 01\n");
        return 1;
    }

    else
        return 0;
}


static char* findNextStartCode(char* buf,int len)
{
    int i = 0;
    if(len < 3)
    {
        return NULL;
    }

    for(i = 0;i < len - 3 ; ++i)
    {
        if(startCode3(buf) || startCode4(buf))
            return buf;
        ++buf;
    }

    if(startCode3(buf))
    {
        return buf;
    }

    return NULL;
    
}

static int getFrameFromH264File(int fd,char* frame, int size)
{
    int rSize, frameSize;
    char* nextStartCode;

    if(fd < 0)
    {
        return fd;
    }

    rSize = read(fd,frame,size);
    if(!startCode3(frame) && !startCode4(frame))
    {
        return -1;
    }

    nextStartCode = findNextStartCode(frame+3,rSize-3);

    if(!nextStartCode)
    {
        lseek(fd,0,SEEK_SET);
        frameSize = rSize;
    }
    else
    {
        frameSize = (nextStartCode - frame);
        lseek(fd,frameSize - rSize, SEEK_CUR);

    }

    return frameSize;


}

static int createUdpSocket()
{
    int fd;
    int on = 1;

    fd = socket(AF_INET,SOCK_DGRAM,0);
    if(fd < 0)
    {

        return -1;
    }
    setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(const char*)&on,sizeof(on));

    return fd;
}


static int rtpSendH264Frame(int socket,char* ip,int16_t port,struct RtpPacket* rtpPacket,uint8_t* frame,uint32_t frameSize)
{
    uint8_t naluType;
    int sendBytes = 0;
    int ret;

    naluType = frame[0];

    if(frameSize <= RTP_MAX_PKT_SIZE)
    {
        memcpy(rtpPacket->payload,frame,frameSize);
        ret = rtpSendpacket(socket,ip,port,rtpPacket,frameSize);
        if(ret < 0)
        {
            return -1;
        }

        rtpPacket->rtpheader.seq++;
        sendBytes += ret;

        //如果pps/sps则不需要增加时间戳
        if( (naluType & 0x1F) == 7 || (naluType & 0x1F) == 8)
        {
            goto out;
        }

    }
    else
    {
        int pktNum = frameSize / RTP_MAX_PKT_SIZE;
        int remainPktSize = frameSize % RTP_MAX_PKT_SIZE;
        int i,pos = 1;

        for(i = 0; i< pktNum ;i++)
        {
            rtpPacket->payload[0] = (naluType & 0x60) | 28;
            rtpPacket->payload[1] = naluType & 0x1F;

            if(i == 0)
            {
                rtpPacket->payload[1] |= 0x80;
            }
            else if(remainPktSize == 0 && i == pktNum -1)
            {
                rtpPacket->payload[1] |= 0x40;
            }

            memcpy(rtpPacket->payload + 2,frame + pos,RTP_MAX_PKT_SIZE);
            ret = rtpSendpacket(socket,ip,port,rtpPacket,RTP_MAX_PKT_SIZE + 2);
            if(ret < 0 )
            {
                return 1;
            }
            rtpPacket->rtpheader.seq++;
            sendBytes += ret;

            pos += RTP_MAX_PKT_SIZE;

        }

        if(remainPktSize > 0)
        {
            rtpPacket->payload[0] = (naluType & 0x60) | 28;
            rtpPacket->payload[1] = naluType & 0x1F;
            rtpPacket->payload[1] |= 0x40;

            memcpy(rtpPacket->payload + 2,frame + pos, remainPktSize + 2);
            ret = rtpSendpacket(socket,ip,port,rtpPacket,remainPktSize + 2); 
            if(ret < 0)
            {
                return -1;
            }

            rtpPacket->rtpheader.seq++;
            sendBytes += ret;
        }
    }
out:
    return sendBytes;
}


int main(int argc,char* argv[])
{
    int socket;
    int fd;
    int fps = 25;
    int startCode;
    struct RtpPacket* rtpPacket;
    uint8_t* frame;
    uint32_t frameSize;


    printf("open file = %s\n",argv[1]);
    fd = open(argv[1],O_RDONLY);
    if(fd < 0)
    {
        printf("file %s open failed!\n",argv[1]);
        return -1;
    }

    socket = createUdpSocket();
    if(socket < 0)
    {
        printf("failed to create udp socket\n");
        return -1;
    }

    rtpPacket = (struct RtpPacket*)malloc(500000);
    frame = (uint8_t*)malloc(500000);

    rtpHeaderInit(rtpPacket,0,0,0,RTP_VERSION,RTP_PAYLOAD_TYPE_H264,0,0,0,0x88923423);

    while(1)
    {
        frameSize = getFrameFromH264File(fd,(char*)frame,500000);
        if(frameSize < 0)
        {
            printf("read err!\n");
            continue;
        }

        if(startCode3((char*)frame))
        {
            startCode = 3;
        }
        else
        {
            startCode = 4;
        }

        // char ipstr[12] = "127.0.0.1";
        frameSize -= startCode;
        int sendBytes = rtpSendH264Frame(socket,CLIENT_IP,CLIENT_PORT,rtpPacket,frame + startCode,frameSize);
        // printf("send %d rtp frame:%d\n", sendBytes, rtpPacket->rtpheader.seq);
        rtpPacket->rtpheader.timestamp += 90000 / FPS;

        usleep(1000 * 1000 / fps);
    }

    free(rtpPacket);
    free(frame);

    return 0;
}





