cmake_minimum_required(VERSION 3.21)
project(AES)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 17)

add_executable(AES)

target_include_directories(AES PRIVATE .)

target_sources(AES
        PRIVATE
        main.c
        em_wb_aes_ctr.c)