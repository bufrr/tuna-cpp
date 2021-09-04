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
        nkn-sdk-cpp/transaction/transaction.cpp tuna_exit.cpp tuna.cpp server_session.h server_session.cpp config.cpp
        entry_main.cpp)

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

#add_executable(exit exit_main.cpp ${SOURCES})
#target_link_libraries(exit /usr/local/Cellar/cpprestsdk/2.10.16/lib/libcpprest.dylib)
#target_link_libraries(exit ${CMAKE_SOURCE_DIR}/nkn-sdk-cpp/cmake-build-debug/nnn.a) #/usr/local/Cellar/openssl@1.1/1.1.1h/lib/libcrypto.a /usr/local/Cellar/gmp/6.2.1/lib/libgmp.a /usr/local/Cellar/gmp/6.2.1/lib/libgmpxx.a /usr/local/Cellar/cpprestsdk/2.10.16/lib/libcpprest.dylib /usr/local/Cellar/protobuf/3.14.0/lib/libprotobuf.a /usr/local/opt/libsodium/lib/libsodium.a)
#target_link_libraries(exit gflags)


#add_executable(entry entry_main.cpp ${SOURCES})
#target_link_libraries(entry /usr/local/Cellar/cpprestsdk/2.10.16/lib/libcpprest.dylib)
#target_link_libraries(entry ${CMAKE_SOURCE_DIR}/nkn-sdk-cpp/cmake-build-debug/newnnn.a) #/usr/local/Cellar/openssl@1.1/1.1.1h/lib/libcrypto.a /usr/local/Cellar/gmp/6.2.1/lib/libgmp.a /usr/local/Cellar/gmp/6.2.1/lib/libgmpxx.a /usr/local/Cellar/cpprestsdk/2.10.16/lib/libcpprest.dylib /usr/local/Cellar/protobuf/3.14.0/lib/libprotobuf.a /usr/local/opt/libsodium/lib/libsodium.a)
#target_link_libraries(entry gflags)

# Library
#if (BUILD_SHARED)
#add_library(entry STATIC ${SOURCES})
#else ()
#    add_library(entry STATIC ${SOURCES} ${HEADERS} /usr/local/opt/protobuf/lib/libprotobuf.a /usr/local/opt/libsodium/lib/libsodium.a /usr/local/Cellar/gmp/6.2.0/lib/libgmp.a /usr/local/Cellar/gmp/6.2.0/lib/libgmpxx.a /usr/local/Cellar/openssl@1.1/1.1.1h/lib/libcrypto.a /usr/local/Cellar/cpprestsdk/2.10.16/lib/libcpprest.dylib)
#    message(STATUS "Building static version...")
#endif ()

#include_directories(${tuna-cpp_SOURCE_DIR})
include_directories(/usr/local/Cellar/boost/1.74.0/include/)
#include_directories(/usr/local/include/)
#link_directories(/usr/local/lib/)
include_directories(/usr/local/opt/protobuf/include/)
include_directories(/usr/local/Cellar/openssl@1.1/1.1.1h/include)
include_directories(/usr/local/Cellar/cpprestsdk/2.10.16/include)
include_directories(/usr/local/Cellar/libsodium/1.0.18_1/include)
include_directories(/usr/local/Cellar/gmp/6.2.1/include)


include_directories(${CMAKE_SOURCE_DIR}/pb)
include_directories("${CMAKE_SOURCE_DIR}/gflags/include")
include_directories("${CMAKE_SOURCE_DIR}/rapidjson/include")
include_directories("${CMAKE_SOURCE_DIR}/smux")
include_directories(${CMAKE_SOURCE_DIR}/nkn-sdk-cpp)



add_subdirectory("gflags")
add_subdirectory("smux-cpp")

#link_directories(/usr/local/Cellar/boost/1.74.0/lib/)
#link_directories(/usr/local/opt/protobuf/lib/)
#link_directories(/Users/chow/test/casablanca/Build_iOS/Apple-Boost-BuildScript/src/boost_1_74_0/iphonesim-build/stage/lib)

#target_link_libraries(entry "-framework /Users/chow/test/casablanca/Build_iOS/boost.framework")
#set_target_properties(entry PROPERTIES LINK_FLAGS "-Wl,-F/Users/chow/test/casablanca/Build_iOS/boost.framework")
#find_library(BOOST_LIBRARY boost /Users/chow/test/casablanca/Build_iOS/boost.framework)

#target_link_libraries(entry "-framework CoreFoundation")
#target_link_libraries(entry "-framework Security")
#set_target_properties(entry PROPERTIES LINK_FLAGS "-Wl,-F/Library/Frameworks")

# x86_64
#target_link_libraries(entry
#        /Users/chow/test/c8d172709018780eb069/protobuf/platform/x86_64_ios/lib/libprotobuf.a
#        /Users/chow/test/libsodium-1.0.18/src/libsodium/.libs/libsodium.a
#        /Users/chow/test/gmp-6.1.0-20151019/ios/lib/libgmp.a
#        /Users/chow/test/gmp-6.1.0-20151019/ios/lib/libgmpxx.a
#        /Users/chow/test/casablanca/Build_iOS/OpenSSL-for-iPhone/bin/iPhoneSimulator14.3-x86_64.sdk/lib/libcrypto.a
#        /Users/chow/test/casablanca/Build_iOS/OpenSSL-for-iPhone/bin/iPhoneSimulator14.3-x86_64.sdk/lib/libssl.a
#        /Users/chow/test/casablanca/Build_iOS/build.Release.ios/lib/libcpprest.a
#        /Users/chow/test/casablanca/Build_iOS/Apple-Boost-BuildScript/build/boost/1.74.0/ios/release/build/x86_64/libboost.a
#        /Users/chow/test/zlib-1.2.11/build/Release-iphonesimulator/libz.a
#        )

# arm64

add_library(entry STATIC ${SOURCES})
target_link_libraries(entry
        /Users/chow/test/c8d172709018780eb069/protobuf/platform/arm64/lib/libprotobuf.a
        /Users/chow/test/libsodium_arm64.a
        /Users/chow/test/casablanca/Build_iOS/OpenSSL-for-iPhone/bin/iPhoneOS14.3-arm64.sdk/lib/libcrypto.a
        /Users/chow/test/casablanca/Build_iOS/OpenSSL-for-iPhone/bin/iPhoneOS14.3-arm64.sdk/lib/libssl.a
        /Users/chow/test/casablanca/Build_iOS/build.Release.ios/lib/libcpprest.a
        /Users/chow/test/casablanca/Build_iOS/Apple-Boost-BuildScript/build/boost/1.74.0/ios/release/build/arm64/libboost.a
        /Users/chow/gmp-6.2.1-20201222225403/ios/lib/libgmp.a
        )
# main
#target_link_libraries(entry /usr/local/Cellar/cpprestsdk/2.10.16/lib/libcpprest.dylib)
#target_link_libraries(entry ${CMAKE_SOURCE_DIR}/nkn-sdk-cpp/cmake-build-debug/nnn.a) #/usr/local/Cellar/openssl@1.1/1.1.1h/lib/libcrypto.a /usr/local/Cellar/gmp/6.2.1/lib/libgmp.a /usr/local/Cellar/gmp/6.2.1/lib/libgmpxx.a /usr/local/Cellar/cpprestsdk/2.10.16/lib/libcpprest.dylib /usr/local/Cellar/protobuf/3.14.0/lib/libprotobuf.a /usr/local/opt/libsodium/lib/libsodium.a)
#target_link_libraries(entry gflags)

#if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
#    set(CMAKE_INSTALL_PREFIX ${entry_SOURCE_DIR}/ CACHE PATH "Install path" FORCE)
#endif (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)


# Executable
#add_executable (helloworld main.cpp)

# Link the library with the executable
# target_link_libraries(entry entry)

# Debug symbols set in XCode project
# set_xcode_property(example GCC_GENERATE_DEBUGGING_SYMBOLS YES "All")


# Installation
#install(TARGETS entry DESTINATION lib)
#install(FILES ${HEADERS} DESTINATION include)
#
#set_target_properties(entry PROPERTIES
#        MACOSX_FRAMEWORK_IDENTIFIER com.example.entry
#        # MACOSX_FRAMEWORK_INFO_PLIST Info.plist
#        # "cu rrent version" in semantic format in Mach-O binary file
#        VERSION 1.0.0
#        # "compatibility version" in semantic format in Mach-O binary file
#        SOVERSION 1.0.0
#        PUBLIC_HEADER "${HEADERS}"
#        RESOURSE "${SOURCES}"
#        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "iPhone Developer"
#        )