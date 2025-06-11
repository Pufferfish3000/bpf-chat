#ifndef COMMON_H
#define COMMON_H

#define NFREE(ptr)  \
    do              \
    {               \
        free(ptr);  \
        ptr = NULL; \
    } while (0)

#endif /*COMMON_H*/