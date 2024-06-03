# RTSP_SERVER
关于RTP和RTSP服务器的试写。这里主要是对h264和aac进行rtp和rtsp的传输接收

编译方式 ：
plan1、在build文件夹内执行（如没有该文件夹，请自行创建） cmake .. 生成makefile相关文件会在build内 make
plan2、直接运行autobuild.sh

需要的环境：ubuntu16.04及以上,g++ 6以上

文件夹说明：
avsource:一些音视频测试资源
bin:生成可执行文件存放位置
src:相关源文件
include:头文件
sdp:相关sdp文件，用于测试rtp传输

可用到的第三方工具：
ffmpeg

测试1：
  窗口1：
  ./h264_rtp_server [h264文件]
  窗口2：
  ffplay -protocol_whitelist "file,udp,rtp" -i h264.sdp 

