cmake_minimum_required(VERSION 3.9)
project(ElfHook)

set(CMAKE_CXX_STANDARD 11)

add_executable(ElfHook
        hook_elf.cpp
        main.cpp HMELF.h HMELF.cpp)