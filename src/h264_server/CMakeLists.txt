aux_source_directory(../transport TRANSPORT_LIST)
# include_directories(${PROJECT_SOURCE_DIR}/include)

add_executable(h264_rtp_server ${TRANSPORT_LIST} "rtp_h264.cpp")

add_executable(h264_rtsp_server ${TRANSPORT_LIST} "h264_rtsp_server.cpp")


add_executable(rtp_broadcast_h264 ${TRANSPORT_LIST} "rtp_broadcast_h264.cpp")

add_executable(h264_rtsp_broadcast_server ${TRANSPORT_LIST} "h264_rtsp_broadcast_server.cpp")
