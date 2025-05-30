#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "bpff.h"

static void DisplayUsage();
static int GetOptions(int argc, char* argv[]);

int main(int argc, char* argv[])
{
    int exit_code = EXIT_FAILURE;

    if (GetOptions(argc, argv))
    {
        DisplayUsage();
        goto end;
    }

    exit_code = StartBPFF();

end:
    return exit_code;
}

static void DisplayUsage()
{

    printf("USAGE");
}

static int GetOptions(int argc, char* argv[])
{
    int exit_code = EXIT_SUCCESS;
    int option = 0;

    if (NULL == argv)
    {
        (void)fprintf(stderr, "argc can not be NULL");
        goto end;
    }

    while (-1 != (option = getopt(argc, argv, "l:f:a:h")))
    {
        switch (option)
        {

            case 'l':
                break;

            case 'h':
                exit_code = EXIT_FAILURE;
                break;

            case '?':
                exit_code = EXIT_FAILURE;
                break;
        }
    }

end:
    return exit_code;
}