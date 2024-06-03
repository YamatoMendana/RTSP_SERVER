aux_source_directory(../transport TRANSPORT_LIST)
# include_directories(${PROJECT_SOURCE_DIR}/include)

add_executable(aac_rtp ${TRANSPORT_LIST} "aac_rtp.cpp")

add_executable(aac_rtsp_server ${TRANSPORT_LIST} "aac_rtsp_server.cpp")


