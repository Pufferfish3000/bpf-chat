#include <stdio.h>
#include <stdlib.h>

#include "bpff.h"

int main(int argc, char* argv[])
{
    int exit_code = EXIT_FAILURE;

    exit_code = StartBPFF();

    return exit_code;
}