#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "redirector.h"

static void DisplayUsage();
static int GetOptions(int argc, char* argv[], char** listen_port, char** forward_port,
                      char** forward_address, char** src_address);
int main(int argc, char* argv[])
{
    int exit_code = EXIT_FAILURE;
    int raw_send = 0;  // disabled
    const int base_10 = 10;
    long l_port = -1;
    long f_port = -1;
    char* listen_port = NULL;
    char* forward_port = NULL;
    char* forward_address = NULL;
    char* src_address = NULL;
    char* endptr = NULL;

    if (GetOptions(argc, argv, &listen_port, &forward_port, &forward_address, &src_address))
    {
        DisplayUsage();
        goto end;
    }

    l_port = strtol(listen_port, &endptr, base_10);
    if (*endptr != '\0')
    {
        fprintf(stderr, "Invalid listen port: %s\n", listen_port);
        goto end;
    }

    endptr = NULL;
    f_port = strtol(forward_port, &endptr, base_10);
    if (*endptr != '\0')
    {
        fprintf(stderr, "Invalid forward port: %s\n", forward_port);
        goto end;
    }

    if (l_port > UINT16_MAX || l_port < 0)
    {
        (void)fprintf(stderr, "Not a valid port number\n");
        goto end;
    }
    if (f_port > UINT16_MAX || f_port < 0)
    {
        (void)fprintf(stderr, "Not a valid port number\n");
        goto end;
    }

    exit_code = StartRedirector((uint16_t)l_port, (uint16_t)f_port, raw_send, forward_address, src_address);
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
        "usage: redirector [-h] -P FILTER_PORT -p FORWARD_PORT -a FORWARD_ADDRESS -A "
        "SOURCE_ADDRESS\n\n"
        "Send a shell command to the configured agent.\n\n"
        "required flags:\n"
        "  -h                  show this help message and exit\n"
        "  -r                  Send packets using raw sockets\n"
        "  -P FILTER_PORT      Destination port redirector will filter for\n"
        "  -p FORWARD_PORT     Port redirector will forward traffic to\n"
        "  -A SOURCE_ADDRESS   Source address that traffic will be forwarded from\n"
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
 * @return int EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
static int GetOptions(int argc, char* argv[], char** listen_port, char** forward_port,
                      char** forward_address, char** src_address, int* raw_send)
{
    int exit_code = EXIT_SUCCESS;
    const int enabled = 1;
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

    if (NULL == src_address || NULL != *src_address)
    {
        (void)fprintf(stderr, "forward_address must be a NULL double pointer\n");
        goto end;
    }

    while (-1 != (option = getopt(argc, argv, "p:P:a:A:h")))
    {
        switch (option)
        {

            case 'P':
                *listen_port = optarg;
                break;

            case 'p':
                *forward_port = optarg;
                break;

            case 'a':
                *forward_address = optarg;
                break;

            case 'A':
                *src_address = optarg;
                break;

            case 'h':
                exit_code = EXIT_FAILURE;
                help = enabled;  // was called
                break;

            case 'r':
                *raw_send = enabled;  // was called
                break;

            case '?':
                exit_code = EXIT_FAILURE;
                break;
        }
    }

    if (NULL == *listen_port && !help)
    {
        (void)fprintf(stderr, "-P option is required\n");
        exit_code = EXIT_FAILURE;
    }

    if (NULL == *forward_port && !help)
    {
        (void)fprintf(stderr, "-p option is required\n");
        exit_code = EXIT_FAILURE;
    }

    if (NULL == *forward_address && !help)
    {
        (void)fprintf(stderr, "-a option is required\n");
        exit_code = EXIT_FAILURE;
    }

    if (NULL == *src_address && !help)
    {
        (void)fprintf(stderr, "-A option is required\n");
        exit_code = EXIT_FAILURE;
    }

end:
    return exit_code;
}