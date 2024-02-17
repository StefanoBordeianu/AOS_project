cmake_minimum_required(VERSION 3.26)
project(aos C)

set(CMAKE_C_STANDARD 11)

add_executable(aos
        server.c)
