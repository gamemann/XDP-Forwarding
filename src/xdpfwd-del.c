#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <bpf.h>
#include <arpa/inet.h>

#include "xdpfwd.h"
#include "cmdline.h"
#include "utils.h"

int main(int argc, char *argv[])
{
    int fwdmap = bpf_map_get(FORWARD_MAP);

    if (fwdmap < 0)
    {
        fprintf(stderr, "Coult not retrieve forward map FD. Exiting...\n");
        
        return EXIT_FAILURE;
    }

    // Retrieve command line arguments.
    struct cmdline cmd = {0};

    parsecmdline(argc, argv, &cmd);

    // Check required arguments.
    if (cmd.baddr == NULL)
    {
        fprintf(stderr, "Missing bind address. Please specify bind address with -b <addr>.\n");

        return EXIT_FAILURE;
    }

    uint32_t bindaddr;

    // Retrieve 32-bit integers of bind and destination addresses in network byte order.
    struct in_addr baddr;
    inet_pton(AF_INET, cmd.baddr, &baddr);
    bindaddr = baddr.s_addr;

    // Construct key and values.
    struct forward_key fwdkey = {0};
    fwdkey.bindaddr = bindaddr;
    fwdkey.bindport = htons(cmd.bport);
    fwdkey.protocol = cmd.protocol;

    if (bpf_map_delete_elem(fwdmap, &fwdkey) != 0)
    {
        fprintf(stderr, "Error deleting forwarding rule :: %s\n", strerror(errno));

        return EXIT_FAILURE;
    }

    fprintf(stdout, "Deleted forwarding rule %s:%d over protocol %d\n", cmd.baddr, cmd.bport, cmd.protocol);

    return EXIT_SUCCESS;
}