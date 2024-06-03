#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <string>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <assert.h>

#include "rtp.h"

#define H264_FILE_NAME  "../avsource/10s.h264"

#define SERVER_PORT 8686
#define SERVER_RTP_PORT 55532
#define SERVER_RTCP_PORT 55533
#define BUF_MAX_SIZE (1024*1024)

#define FPS 25


static int createTcpSocket()
{
    int sockfd;
    int on = 1;
    sockfd = socket(AF_INET,SOCK_STREAM,0);
    if(sockfd < 0)
    {
        printf("socket create err\n");
        return 1;
    }

    setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,(const char*)&on,sizeof(on));

    return sockfd;

}

static int createUdpSocket()
{
    int sockfd;
    int on = 1;

    sockfd = socket(AF_INET,SOCK_DGRAM,0);
    if(sockfd < 0)
    {
        printf("udp socket create err\n");
        return -1;
    }

    setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,(const char*)&on,sizeof(on));

    return sockfd;

}

static int bindSocketAddr(int sockfd,const char* ip,int port)
{
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    if(bind(sockfd,(struct sockaddr*)&addr,sizeof(struct sockaddr)) < 0)
    {
        printf("bind err\n");
        return -1;
    }

    return 0;
}

static int acceptClient(int sockfd,char* ip,int* port)
{
    int clientfd;
    socklen_t len = 0;
    struct sockaddr_in addr;

    memset(&addr,0,sizeof(addr));
    len = sizeof(addr);

    clientfd = accept(sockfd,(struct sockaddr*)&addr,&len);
    if(clientfd < 0 )
    {
        printf("accept err\n");
        return 1;
    }

    strcpy(ip,inet_ntoa(addr.sin_addr));
    *port = ntohs(addr.sin_port);

    return clientfd;
}

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

static char* getLineFromBuf(char* buf,std::string* str)
{
    char src[400] = {0};
    char* line = src;
    while(*buf != '\n')
    {
        *line = *buf;
        line++;
        buf++;
    }


    *line = '\n';
    ++line;
    *line = '\0';

    *str = src;
    
    buf++;
    return buf;
}


static int handleCmd_OPTIONS(char* result, int cseq)
{
    sprintf(result,"RTSP/1.0 200 OK\r\n"
            "CSeq: %d\r\n"
            "Public: OPTIONS, DESCRIBE, SETUP, PLAY\r\n"
            "\r\n",
            cseq
    );

    return 0;
}

static int handleCmd_DESCRIBE(char* result,int cseq,char* url)
{
    char sdp[1024]={0};
    char localIp[40]={0};

    sscanf(url,"rtsp://%[^:]:",localIp);

    sprintf(sdp,"v=0\r\n"
            "o=- 9%ld 1 IN IP4 %s\r\n"
            "t=0 0\r\n"
            "a=control:*\r\n"
            "m=video 0 RTP/AVP 96\r\n"
            "a=rtpmap:96 H264/90000\r\n"
            "a=control:track0\r\n",
            time(NULL),
            localIp
    );

    sprintf(result,"RTSP/1.0 200 OK\r\n"
            "CSeq: %d\r\n"
            "Content-Base: %s\r\n"
            "Content-type: application/sdp\r\n"
            "Content-length: %d\r\n\r\n"
            "%s",
            cseq,
            url,
            (int)strlen(sdp),
            sdp
            );

    return 0;

}

static int handleCmd_SETUP(char* result,int cseq,int clientRtpPort)
{
    sprintf(result,"RTSP/1.0 200 OK\r\n"
            "CSeq: %d\r\n"
            "Transport: RTP/AVP;unicast;client_port=%d-%d;server_port=%d-%d\r\n"
            "Session: 66334873\r\n"
            "\r\n",
            cseq,
            clientRtpPort,
            clientRtpPort+1,
            SERVER_RTP_PORT,
            SERVER_RTCP_PORT
            );

    return 0;

}

static int handleCmd_PlAY(char* result,int cseq)
{
    sprintf(result,"RTSP/1.0 200 OK\r\n"
            "CSeq: %d\r\n"
            "Range: npt=0.000-\r\n"
            "Session: 66334873; timeout=60\r\n",
            cseq
    );

    return 0;
}

static int rtpSendH264Frame(int socket,const char* ip,int16_t port,struct RtpPacket* rtpPacket,uint8_t* frame,uint32_t frameSize)
{
    uint8_t naluType;
    int sendBytes = 0;
    int ret;

    naluType = frame[0];

    if(frameSize <= RTP_MAX_PKT_SIZE)
    {
        /*
         *   0 1 2 3 4 5 6 7 8 9
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |F|NRI|  Type   | a single NAL unit ... |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */

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
        /*
         *  0                   1                   2
         *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * | FU indicator  |   FU header   |   FU payload   ...  |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */

        /*
         *     FU Indicator
         *    0 1 2 3 4 5 6 7
         *   +-+-+-+-+-+-+-+-+
         *   |F|NRI|  Type   |
         *   +---------------+
         */

        /*
         *      FU Header
         *    0 1 2 3 4 5 6 7
         *   +-+-+-+-+-+-+-+-+
         *   |S|E|R|  Type   |
         *   +---------------+
         */

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

static void doClient(int clientSockfd, const char* clientIP,int clientPort,
                    int serverRtpSockfd,int serverRtcpSockfd,void* arg=nullptr)
{
    char method[40]={0};
    char url[100]={0};
    char version[40]={0};
    int cseq;
    int clientRtpPort,clientRtcpPort;
    char* bufPtr;
    char* rBuf = (char*)malloc(BUF_MAX_SIZE);
    char* wBuf = (char*)malloc(BUF_MAX_SIZE);
    std::string strLine;
    std::vector<std::string> vecline;
    bool bfind = false;

    while(1)
    {
        int recvLen;

        recvLen = recv(clientSockfd,rBuf,BUF_MAX_SIZE,0);
        if(recvLen <= 0)
        {
            goto out;
        }

        rBuf[recvLen] = '\0';
        printf("----------C->S-------------\n");
        printf("%s",rBuf);
        
        vecline.clear();
        bufPtr = rBuf;
        while(*bufPtr != '\0')
        {
            bufPtr = getLineFromBuf(bufPtr,&strLine);
            vecline.push_back(strLine);
        }


        std::vector<std::string>::iterator iter;
        for(iter=vecline.begin();iter!=vecline.end();iter++)
        {
            if(sscanf( iter->c_str(),"%s %s %s\r\n",method,url,version) == 3)
            {
                // printf("iter: %s\n",iter->c_str());
                bfind = true;
                break;
            }
        }
        if(!bfind)
        {
            printf("parse err\n");
            goto out;
        }

        bfind = false;
        for(iter = vecline.begin(); iter != vecline.end() ; iter++)
        {
            if(sscanf(iter->c_str(),"CSeq: %d\r\n",&cseq) == 1)
            {
                // printf("iter: %s\n",iter->c_str());
                bfind = true;
                break;
            }
        }
        if(!bfind)
        {
            printf("parse err\n");
            goto out;
        }

        /* 如果是SETUP，那么就再解析client_port */
        if(!strcmp(method, "SETUP"))
        {
            for(iter = vecline.begin(); iter != vecline.end() ; iter++)
            {
                int ret = 0;
                if(!strncmp(iter->c_str(), "Transport:", strlen("Transport:")))
                {
                    ret = sscanf(iter->c_str(), "Transport: RTP/AVP/UDP;unicast;client_port=%d-%d\r\n",&clientRtpPort, &clientRtcpPort);
                    if(ret != 2)
                    {
                        printf("sscanf Transport err\n");
                        goto out;
                    }
                    break;
                }
            }
        }



        if(!strcmp(method,"OPTIONS"))
        {
            if(handleCmd_OPTIONS(wBuf,cseq))
            {
                printf("fail to handle options\n");
                goto out;
            }
        }
        else if(!strcmp(method,"DESCRIBE"))
        {
            if(handleCmd_DESCRIBE(wBuf,cseq,url))
            {
                printf("fail to handle describe\n");
                goto out;
            }
        }
        else if(!strcmp(method,"SETUP"))
        {
            if(handleCmd_SETUP(wBuf,cseq,clientRtpPort))
            {
                printf("fail to handle setup\n");
                goto out;
            }
        }
        else if(!strcmp(method, "PLAY"))
        {
            if(handleCmd_PlAY(wBuf, cseq))
            {
                printf("failed to handle play\n");
                goto out;
            }
        }
        else
        {
            goto out;
        }


        printf("-----------S->C----------\n");
        printf("%s",wBuf);
        send(clientSockfd,wBuf,strlen(wBuf),0);

        if(!strcmp(method,"PLAY"))
        {
            int frameSize,startCode;
            // char* frame = (char*)malloc(500000);
            uint8_t* frame = (uint8_t*)malloc(500000);
            struct RtpPacket* rtpPacket = (struct RtpPacket*)malloc(500000);
            int fd = open((char*)arg,O_RDONLY);
            assert(fd>0);

            rtpHeaderInit(rtpPacket,0,0,0,RTP_VERSION,RTP_PAYLOAD_TYPE_H264,0,0,0, 0x88923423);
            printf("start play\n");
            printf("client ip:%s\n", clientIP);
            printf("client port:%d\n", clientPort);
            printf("RTP client port:%d\n", clientRtpPort);

            while(1)
            {
                frameSize = getFrameFromH264File(fd,(char*)frame,500000);
                if(frameSize < 0)
                {
                    break;
                }

                if(startCode3((char*)frame))
                    startCode = 3;
                if(startCode4((char*)frame))
                    startCode = 4;
                
                frameSize -= startCode;
                int sendBytes = rtpSendH264Frame(serverRtpSockfd,clientIP,clientRtpPort,rtpPacket,frame + startCode,frameSize);
                // int sendBytes = rtpSendH264Frame(serverRtpSockfd,"127.0.0.1",clientRtpPort,rtpPacket,frame + startCode,frameSize);
                rtpPacket->rtpheader.timestamp += 90000 / FPS;
                // printf("send %d rtp frame:%d\n", sendBytes, rtpPacket->rtpheader.seq);
                usleep(1000 * 1000 / FPS);


            }
            free(frame);
            free(rtpPacket);
            goto out;
        }

    }


out:
    printf("finish\n");
    close(clientSockfd);
    free(rBuf);
    free(wBuf);
}






int main(int argc,char* argv[])
{
    int serverSockfd;
    int serverRtpSockfd,serverRtcpSockfd;
    int ret = 0;

    serverSockfd = createTcpSocket();
    if(serverSockfd < 0 )
    {
        printf("failed to create tcp socket\n");
        return -1;
    }

    ret = bindSocketAddr(serverSockfd,"0.0.0.0",SERVER_PORT);
    if(ret < 0)
    {
        printf("failed to bind addr\n");
        return -1;

    }

    ret = listen(serverSockfd,10);
    if(ret < 0)
    {
        printf("failed to listen socket\n");
        return -1;
    }

    serverRtcpSockfd = createUdpSocket();
    serverRtpSockfd = createUdpSocket();
    if(serverRtcpSockfd < 0 || serverRtpSockfd < 0)
    {
        printf("failed to create udp socket\n");
        return -1;
    }


    if(bindSocketAddr(serverRtpSockfd,"0.0.0.0",SERVER_RTP_PORT) < 0
    || bindSocketAddr(serverRtcpSockfd,"0.0.0.0",SERVER_RTCP_PORT) < 0)
    {
        printf("failed to bind udp addr\n");
        return -1;
    }

    printf("rtsp://127.0.0.1:%d\n",SERVER_PORT);


    while(1)
    {
        int clientSockfd;
        char clientIP[40];
        int clientPort;

        clientSockfd = acceptClient(serverSockfd,clientIP,&clientPort);
        if(clientSockfd < 0 )
        {
            printf("failed to accept client\n");
            return -1;

        }
        printf("accept client;client ip: %s,client port: %d\n",clientIP,clientPort);

        doClient(clientSockfd,clientIP,clientPort,serverRtpSockfd,serverRtcpSockfd);
    }

    return 0;
}