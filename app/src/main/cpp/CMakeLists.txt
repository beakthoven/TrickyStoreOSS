# Copyright 2026 Dakkshesh <beakthoven@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.28)
project(TrickyStoreOSS)

find_package(cxx REQUIRED CONFIG)
link_libraries(cxx::cxx)

add_library(my_logging STATIC logging/logging.cpp)
target_include_directories(my_logging PUBLIC logging/include)
target_link_libraries(my_logging log)

# Maps parser (used by injector)
add_library(ts_maps STATIC maps/maps.cpp)
target_include_directories(ts_maps PUBLIC maps/include)

# PLTI (PLT hooking library)
add_subdirectory(external/PLTI)

# libutils stub
add_library(utils SHARED stub/stub_utils.cpp)
target_include_directories(utils PUBLIC external/AOSP/include)

# libbinder stub
add_library(binder SHARED stub/stub_binder.cpp)
target_include_directories(binder PUBLIC external/AOSP/include)
target_link_libraries(binder PRIVATE utils)

add_executable(libinject.so inject/main.cpp inject/utils.cpp)
target_link_libraries(libinject.so PRIVATE ts_maps my_logging)

add_library(${CMAKE_PROJECT_NAME} SHARED binder_interceptor.cpp)
target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC external/linux-kernel/include)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE log dl binder utils plti my_logging)
