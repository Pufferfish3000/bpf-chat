#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "redirector.h"

static void DisplayUsage();
static int GetOptions(int argc, char* argv[], char** listen_port, char** forward_port,
                      char** forward_address);
int main(int argc, char* argv[])
{
    int exit_code = EXIT_FAILURE;
    (void)argc;
    (void)argv;
    long l_port = 5555;
    char* listen_port = NULL;
    char* forward_port = NULL;
    char* forward_address = NULL;

    if (GetOptions(argc, argv, &listen_port, &forward_port, &forward_address))
    {
        DisplayUsage();
    }

    if (l_port > UINT16_MAX || l_port < 0)
    {
        (void)fprintf(stderr, "Not a valid port number\n");
        goto end;
    }

    exit_code = StartREDIRECTOR((uint16_t)l_port);
end:
    return exit_code;
}

/**
 * @brief Displays server usage information
 * 
 */
static void DisplayUsage()
{

    printf(
        "usage: redirector [-h] -l LISTEN_PORT -f FORWARD_PORT -a FORWARD_ADDRESS\n\n"
        "Send a shell command to the configured agent.\n\n"
        "required flags:\n"
        "  -h                  show this help message and exit\n"
        "  -l LISTEN_PORT      Destination port redirector will filter for\n"
        "  -f FORWARD_PORT     Port redirector will forward traffic to\n"
        "  -a FORWARD_ADDRESS  Address redirector will forward traffic to\n");
}

/**
 * @brief Get Command line options.
 * 
 * @param argc argc from main
 * @param argv argc from main
 * @param listen_port Double pointer to dst port redirector will be filtering for
 * @param forward_port Double pointer to dst port redirector will be forwarding traffic to
 * @param forward_address Double pointer to address redirector will be forwarding traffic to
 * @return int 
 */
static int GetOptions(int argc, char* argv[], char** listen_port, char** forward_port,
                      char** forward_address)
{
    int exit_code = EXIT_SUCCESS;
    int help = 0;
    int option = 0;

    if (NULL == argv)
    {
        (void)fprintf(stderr, "argc can not be NULL\n");
        goto end;
    }

    if (NULL == listen_port || NULL != *listen_port)
    {
        (void)fprintf(stderr, "listen_port must be a NULL double pointer\n");
        goto end;
    }

    if (NULL == forward_port || NULL != *forward_port)
    {
        (void)fprintf(stderr, "forward_port must be a NULL double pointer\n");
        goto end;
    }

    if (NULL == forward_address || NULL != *forward_address)
    {
        (void)fprintf(stderr, "forward_address must be a NULL double pointer\n");
        goto end;
    }

    while (-1 != (option = getopt(argc, argv, "l:f:a:h")))
    {
        switch (option)
        {

            case 'l':
                *listen_port = optarg;
                break;

            case 'f':
                *forward_port = optarg;
                break;

            case 'a':
                *forward_address = optarg;
                break;

            case 'h':
                exit_code = EXIT_FAILURE;
                help = 1;  // was called
                break;

            case '?':
                exit_code = EXIT_FAILURE;
                break;
        }
    }

    if (NULL == *listen_port && !help)
    {
        (void)fprintf(stderr, "-l option is required\n");
        exit_code = EXIT_FAILURE;
    }

    if (NULL == *forward_port && !help)
    {
        (void)fprintf(stderr, "-f option is required\n");
        exit_code = EXIT_FAILURE;
    }

    if (NULL == *forward_address && !help)
    {
        (void)fprintf(stderr, "-a option is required\n");
        exit_code = EXIT_FAILURE;
    }

end:
    return exit_code;
}