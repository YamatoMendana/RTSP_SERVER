#include <stdio.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "rtp.h"

#define AAC_FILE "/root/10s.aac"
#define CLIENT_IP "127.0.0.1"
#define CLIENT_PORT 9832


struct AdtsHeader{
    unsigned int syncword;//总是0xFFF, 代表一个ADTS帧的开始, 用于同步.
    unsigned int id;//MPEG Version: 0 for MPEG-4，1 for MPEG-2
    unsigned int layer;//always: ‘00’
    unsigned int protectionAbsent;//Warning, set to 1 if there is no CRC and 0 if there is CRC
    unsigned int profile;//表示使用哪个级别的AAC，如01 Low Complexity(LC) – AAC LC
    unsigned int samplingFreqIndex;//采样率的下标
    unsigned int privateBit;
    unsigned int channelCfg;
    unsigned int originalCopy;
    unsigned int home;


    unsigned int copyrightIdentificationBit;
    unsigned int copyrightIdentificationStart;
    unsigned int aacFrameLength;    //一个ADTS帧的长度包括ADTS头和AAC原始流
    unsigned int adtsBufferFullness; //0x7FF 说明是码率可变的码流

    unsigned int numberOfRawDataBlockInFrame; //表示ADTS帧中有number_of_raw_data_blocks_in_frame + 1个AAC原始帧

};



static int parseAdtsHeader(uint8_t* in, struct AdtsHeader* res)
{
    static int frame_number = 0;
    memset(res,0,sizeof(*res));

    if((in[0] == 0xFF && (in[1] & 0xF0) == 0xF0))
    {
        res->id = ((unsigned int )in[1] & 0x08) >> 3;
        printf("adts:id = %d",res->id);
        res->layer = ((unsigned int)in[1] && 0x06) >> 1;
        printf( "adts:layer = %d\n", res->layer);
        res->protectionAbsent = (unsigned int) in[1] & 0x01;
        printf( "adts:protection_absent = %d\n", res->protectionAbsent);
        res->profile = ((unsigned int) in[2] & 0xc0) >> 6;
        printf( "adts:profile = %d\n", res->profile);
        res->samplingFreqIndex = ((unsigned int) in[2] & 0x3c) >> 2;
        printf( "adts:sf_index = %d\n", res->samplingFreqIndex);
        res->privateBit = ((unsigned int) in[2] & 0x02) >> 1;
        printf( "adts:pritvate_bit = %d\n", res->privateBit);
        res->channelCfg = ((((unsigned int) in[2] & 0x01) << 2) | (((unsigned int) in[3] & 0xc0) >> 6));
        printf( "adts:channel_configuration = %d\n", res->channelCfg);
        res->originalCopy = ((unsigned int) in[3] & 0x20) >> 5;
        printf( "adts:original = %d\n", res->originalCopy);
        res->home = ((unsigned int) in[3] & 0x10) >> 4;
        printf( "adts:home = %d\n", res->home);
        res->copyrightIdentificationBit = ((unsigned int) in[3] & 0x08) >> 3;
        printf( "adts:copyright_identification_bit = %d\n", res->copyrightIdentificationBit);
        res->copyrightIdentificationStart = (unsigned int) in[3] & 0x04 >> 2;
        printf( "adts:copyright_identification_start = %d\n", res->copyrightIdentificationStart);
        res->aacFrameLength = (((((unsigned int) in[3]) & 0x03) << 11) |
                                (((unsigned int)in[4] & 0xFF) << 3) |
                                    ((unsigned int)in[5] & 0xE0) >> 5) ;
        printf( "adts:aac_frame_length = %d\n", res->aacFrameLength);
        res->adtsBufferFullness = (((unsigned int) in[5] & 0x1f) << 6 |
                                        ((unsigned int) in[6] & 0xfc) >> 2);
        printf( "adts:adts_buffer_fullness = %d\n", res->adtsBufferFullness);
        res->numberOfRawDataBlockInFrame = ((unsigned int) in[6] & 0x03);
        printf( "adts:no_raw_data_blocks_in_frame  %d\n", res->numberOfRawDataBlockInFrame);

        return 0;
    }
    else
    {
        printf("failed to parse adts header\n");
        return -1;
    }
}


static int createUdpSocket()
{
    int fd;
    int on = 1;

    fd = socket(AF_INET,SOCK_DGRAM,0);
    if(fd < 0)
        return -1;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

    return fd;
}


static int rtpSendAACFrame(int socket , char* ip,int16_t port,struct RtpPacket* rtpPacket,uint8_t* frame,uint32_t frameSize)
{
    int ret;

    rtpPacket->payload[0] = 0x00;
    rtpPacket->payload[1] = 0x10;
    rtpPacket->payload[2] = (frameSize & 0x1FE0) >> 5;
    rtpPacket->payload[3] = (frameSize & 0x1F) <<3;

    memcpy(rtpPacket->payload + 4,frame,frameSize);

    ret = rtpSendpacket(socket,ip,port,rtpPacket,frameSize + 4);
    if(ret < 0 )
    {
        printf("failed to send rtp packet\n");
        return -1;
    }

    rtpPacket->rtpheader.seq++;


    /*
     * 如果采样频率是44100
     * 一般AAC每个1024个采样为一帧
     * 所以一秒就有 44100 / 1024 = 43帧
     * 时间增量就是 44100 / 43 = 1025
     * 一帧的时间为 1 / 43 = 23ms
     */

    rtpPacket->rtpheader.timestamp += 1043 ;

    return 0;
}


int main(int argc,char* argv[])
{
    int fd;
    int ret;
    int socket;
    uint8_t* frame;
    struct AdtsHeader adtsHeader;
    struct RtpPacket* rtpPacket;


    if(argc != 2)
    {
        printf("Usage: %s <dest ip>\n", argv[0]);
        return -1;
    }

    fd = open(AAC_FILE, O_RDONLY);
    if(fd < 0)
    {
        printf("failed to open %s\n", AAC_FILE); 
        return -1;
    }    

    socket = createUdpSocket();
    if(socket < 0)
    {
        printf("failed to create udp socket\n");
        return -1;
    }

    frame = (uint8_t*)malloc(5000);
    rtpPacket = (RtpPacket*)malloc(5000);

    rtpHeaderInit(rtpPacket, 0, 0, 0, RTP_VERSION, RTP_PAYLOAD_TYPE_AAC, 1, 0, 0, 0x32411);

    while(1)
    {
        printf("--------------------------------\n");

        ret = read(fd, frame, 7);
        if(ret <= 0)
        {
            lseek(fd, 0, SEEK_SET);
            continue;            
        }

        if(parseAdtsHeader(frame, &adtsHeader) < 0)
        {
            printf("parse err\n");
            break;
        }

        ret = read(fd, frame, adtsHeader.aacFrameLength - 7);
        if(ret < 0)
        {
            printf("read err\n");
            break;
        }


        rtpSendAACFrame(socket, CLIENT_IP,CLIENT_PORT,rtpPacket,frame,adtsHeader.aacFrameLength - 7);

        usleep(23000);

    }


    return 0;
}









