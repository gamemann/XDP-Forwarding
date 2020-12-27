#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <bpf.h>

#include "xdp_prog.h"

int bpf_map_get(const char *path)
{
    int fd = -1;

    fd = bpf_obj_get(path);

    return fd;
}

int main(int argc, char *argv[])
{
    int fwdmap = bpf_map_get(FORWARD_MAP);

    if (fwdmap < 0)
    {
        fprintf(stderr, "Coult not retrieve forward map FD. Exiting...\n");
        
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}