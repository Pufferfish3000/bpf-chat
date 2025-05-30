set(BPFF "bpff_x86_64")

set (RELEASE_FLAGS -Wall -Werror -Wextra -Wpedantic -Wconversion -Wunreachable-code -Werror -Os)

add_executable(${BPFF})
target_include_directories(${BPFF} PUBLIC ${CMAKE_SOURCE_DIR}/bpff/include)

add_subdirectory(src/)
# add_subdirectory(core/)