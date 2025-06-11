set(REDIRECTOR "redirector_x86_64")

set(RELEASE_FLAGS -Wall -Werror -Wextra -Wpedantic -Wconversion -Wunreachable-code -Werror -g)

add_executable(${REDIRECTOR})
target_compile_options(${REDIRECTOR} PUBLIC ${RELEASE_FLAGS})
target_include_directories(${REDIRECTOR} PUBLIC ${CMAKE_SOURCE_DIR}/redirector/include)

add_subdirectory(src/)
add_subdirectory(core/)