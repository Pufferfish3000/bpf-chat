set(BPFC "bpfc_x86_64")

set (RELEASE_FLAGS -Wall -Werror -Wextra -Wpedantic -Wconversion -Wunreachable-code -Werror -Os)

add_executable(${BPFC})
target_include_directories(${BPFC} PUBLIC ${CMAKE_SOURCE_DIR}/bpfc/include)

add_subdirectory(src/)
# add_subdirectory(core/)