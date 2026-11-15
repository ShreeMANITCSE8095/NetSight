cmake_minimum_required(VERSION 3.16)
project(NetSightEngine CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W3 /EHsc /utf-8)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -pthread -O2)
endif()

include_directories(include)

set(ENGINE_SOURCES
    src/types.cpp
    src/packet_parser.cpp
    src/pcap_reader.cpp
    src/live_capture.cpp
    src/tls_extractor.cpp
    src/dns_parser.cpp
    src/host_profiler.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
    src/tcp_server.cpp
    src/engine_core.cpp
)

add_executable(netsight-engine
    ${ENGINE_SOURCES}
    src/main.cpp
)

find_package(Threads REQUIRED)

if(WIN32)
    target_link_libraries(netsight-engine PRIVATE ws2_32 iphlpapi)
else()
    target_link_libraries(netsight-engine PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
endif()

# Unit tests target
enable_testing()
add_executable(engine-tests
    ${ENGINE_SOURCES}
    tests/test_main.cpp
)

if(WIN32)
    target_link_libraries(engine-tests PRIVATE ws2_32 iphlpapi)
else()
    target_link_libraries(engine-tests PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
endif()

add_test(NAME EngineUnitTests COMMAND engine-tests)

