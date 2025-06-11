cmake_minimum_required(VERSION 3.22.1)
project(REDIRECTOR
        VERSION 1.0
        DESCRIPTION "BPF Chat"
        LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

add_subdirectory(redirector/)