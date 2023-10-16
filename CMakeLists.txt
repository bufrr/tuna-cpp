cmake_minimum_required(VERSION 3.17)
project(tuna-cpp C CXX)
enable_testing()
set(CMAKE_CXX_STANDARD 11)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -g -fno-omit-frame-pointer")
MESSAGE(STATUS "CMAKE_CXX_FLAGS: " ${CMAKE_CXX_FLAGS})
set(Boost_USE_MULTITHREADED FALSE)

include(CheckCXXSymbolExists)
check_cxx_symbol_exists(kqueue sys/event.h HAVE_KQUEUE)
if (NOT HAVE_KQUEUE)
    message(FATAL_ERROR "kqueue NOT found!")
else ()
    message(STATUS "kqueue found!")
endif ()
set(OPENSSL_ROOT_DIR /usr/local/opt/openssl /usr/local/Cellar/openssl@1.1/1.1.1h/)
#find_package(cpprestsdk REQUIRED)
#find_package(OpenSSL::SSL IMPORTED)


set(SOURCES
        entry.cpp
        nkn.cpp nkn_client_session.cpp nkn_local.cpp
        pb/tuna.pb.cc
        pb/transaction.pb.cc
        smux-cpp/utils.cpp
        smux-cpp/smux.cpp
        smux-cpp/local.cpp
        smux-cpp/client_session.cpp
        smux-cpp/encrypt.cpp
        nkn-sdk-cpp/json/NKNCodec.cpp
        nkn-sdk-cpp/config.cpp
        nkn-sdk-cpp/rpc.cpp
        nkn-sdk-cpp/wallet/account.cpp
        nkn-sdk-cpp/wallet/walletData.cpp
        nkn-sdk-cpp/wallet/wallet.cpp
        nkn-sdk-cpp/wallet/nanopay.cpp
        nkn-sdk-cpp/transaction/txBuilder.cpp
        nkn-sdk-cpp/pb/sigchain.pb.cc
        nkn-sdk-cpp/transaction/transaction.cpp tuna_exit.cpp tuna.cpp server_session.h server_session.cpp config.cpp
        entry_main.cpp encrypt.cpp)

# Headers
set(HEADERS
        tuna.h
        entry.h
        tuna_exit.h
        config.h
        base64.hpp
        nkn.h
        nkn_local.h
        nkn_client_session.h
        smux-cpp/smux.h
        smux-cpp/encoding.h
        smux-cpp/utils.h
        smux-cpp/frame.h
        smux-cpp/local.h
        smux-cpp/client_session.h
        smux-cpp/encoder.h
        smux-cpp/encrypt.h
        pb/tuna.pb.h
        pb/transaction.pb.h
        nkn-sdk-cpp/json/NKNCodec.h
        entry_main.h)

message(STATUS "Building static version...")


#include_directories(${tuna-cpp_SOURCE_DIR})
include_directories(/opt/homebrew/Cellar/boost/1.78.0_1/include/)
#include_directories(/usr/local/include/)
#link_directories(/usr/local/lib/)
include_directories(/opt/homebrew/Cellar/protobuf/3.19.4/include/)
include_directories(/opt/homebrew/Cellar/openssl@1.1/1.1.1n/include)
include_directories(/opt/homebrew/Cellar/cpprestsdk/2.10.18/include)
include_directories(/opt/homebrew/Cellar/libsodium/1.0.18_1/include)
include_directories(/opt/homebrew/Cellar/gmp/6.2.1_1/include)


include_directories(${CMAKE_SOURCE_DIR}/pb)
include_directories("${CMAKE_SOURCE_DIR}/gflags/include")
include_directories("${CMAKE_SOURCE_DIR}/rapidjson/include")
include_directories("${CMAKE_SOURCE_DIR}/smux")
include_directories(${CMAKE_SOURCE_DIR}/nkn-sdk-cpp)
include_directories(${CMAKE_SOURCE_DIR}/nkn-sdk-cpp/pb)
include_directories(${CMAKE_SOURCE_DIR}/nkn-sdk-cpp/include)


add_subdirectory("gflags")
add_subdirectory("smux-cpp")


#add_library(entry STATIC ${SOURCES})
add_executable(entry entry_main.cpp ${SOURCES})
target_link_libraries(entry /opt/homebrew/Cellar/cpprestsdk/2.10.18/lib/libcpprest.dylib)
target_link_libraries(entry /opt/homebrew/Cellar/boost/1.78.0_1/lib/libboost_program_options.a)
target_link_libraries(entry /opt/homebrew/Cellar/libsodium/1.0.18_1/lib/libsodium.a)
target_link_libraries(entry /opt/homebrew/Cellar/openssl@1.1/1.1.1n/lib/libcrypto.a)
target_link_libraries(entry /opt/homebrew/Cellar/gmp/6.2.1_1/lib/libgmp.a)
target_link_libraries(entry /opt/homebrew/Cellar/gmp/6.2.1_1/lib/libgmpxx.a)
target_link_libraries(entry /opt/homebrew/Cellar/protobuf/3.19.4/lib/libprotobuf.a)
target_link_libraries(entry /Users/bufrr/src/nkn-sdk-cpp-priv/libnkn_sdk.a)


#add_executable(entry entry_main.cpp ${SOURCES})
#target_link_libraries(entry /Users/bufrr/src/tuna-cpp/libentry.a)
