#!/bin/bash

[ -d "build" ] && rm -R build/
mkdir build
cd build

cmake .. -G Xcode -DCMAKE_TOOLCHAIN_FILE=../ios.toolchain.cmake -DPLATFORM=OS64 -DCMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM=67P82ZQDAS

#cmake --build . --config Debug
cmake --build . --config Release

cd ..