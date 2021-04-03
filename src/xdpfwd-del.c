#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libconfig.h>

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
    uint8_t protocol;

    // Retrieve 32-bit integer of bind and destination addresses in network byte order.
    struct in_addr baddr;
    inet_pton(AF_INET, cmd.baddr, &baddr);
    bindaddr = baddr.s_addr;

    char *protocolstr = "ALL";

    // Check protocol.
    if (strcmp(lowerstr(cmd.protocol), "tcp") == 0)
    {
        protocolstr = "TCP";
        protocol = IPPROTO_TCP;
    }
    else if (strcmp(lowerstr(cmd.protocol), "udp") == 0)
    {
        protocolstr = "UDP";
        protocol = IPPROTO_UDP;
    }
    else if (strcmp(lowerstr(cmd.protocol), "icmp") == 0)
    {
        protocolstr = "ICMP";
        protocol = IPPROTO_ICMP;
    }

    // Construct key and values.
    struct forward_key fwdkey = {0};
    fwdkey.bindaddr = bindaddr;
    fwdkey.bindport = htons(cmd.bport);
    fwdkey.protocol = protocol;

    if (bpf_map_delete_elem(fwdmap, &fwdkey) != 0)
    {
        fprintf(stderr, "Error deleting forwarding rule :: %s\n", strerror(errno));

        return EXIT_FAILURE;
    }

    fprintf(stdout, "Deleted forwarding rule %s:%d over protocol %s.\n", cmd.baddr, cmd.bport, protocolstr);

    // Check if we're saving.
    if (cmd.save)
    {
        char *cfgfile = "/etc/xdpfwd/xdpfwd.conf";

        if (cmd.cfgfile != NULL)
        {
            cfgfile = cmd.cfgfile;
        }

        // Open file.
        FILE *fp = fopen(cfgfile, "rw");

        if (fp == NULL)
        {
            fprintf(stderr, "Could not save to config file :: %s\n", strerror(errno));

            return EXIT_FAILURE;
        }

        // Initialize libconfig.
        config_t conf;

        config_init(&conf);

        // Attempt to read config file through libconfig.
        if (config_read(&conf, fp) == CONFIG_FALSE)
        {
            fprintf(stderr, "Could not save to config file (could not load config) :: %s\n", config_error_text(&conf));

            config_destroy(&conf);

            return EXIT_FAILURE;
        }

        // We can close the file pointer now.
        fclose(fp);

        // Attempt to read forwarding rules.
        config_setting_t *fwd = config_lookup(&conf, "forwarding");

        // If it doesn't exist, create it.
        if (fwd == NULL)
        {
            fprintf(stderr, "Could not save to config file ('forwarding' list does not exist) :: %s\n", config_error_text(&conf));

            config_destroy(&conf);

            return EXIT_FAILURE;
        }

        // Loop through all rules.
        for (int i = 0; i < config_setting_length(fwd); i++)
        {
            // Retrieve element.
            config_setting_t *rule = config_setting_get_elem(fwd, i);

            if (rule == NULL)
            {
                continue;
            }

            const char *s_bindaddr;

            if (config_setting_lookup_string(rule, "bind", &s_bindaddr) == CONFIG_FALSE)
            {
                continue;
            }

            int s_bindport = 0;
            config_setting_lookup_int(rule, "bindport", &s_bindport);

            const char *s_destaddr;

            if (config_setting_lookup_string(rule, "dest", &s_destaddr) == CONFIG_FALSE)
            {
                continue;
            }

            int s_destport = 0;
            config_setting_lookup_int(rule, "destport", &s_destport);

            const char *s_protocol;

            if (config_setting_lookup_string(rule, "protocol", &s_protocol) == CONFIG_FALSE)
            {
                continue;
            }

            // Now compare.
            if (s_bindaddr == NULL || strcmp(lowerstr((char *)s_bindaddr), lowerstr(cmd.baddr)) != 0)
            {
                continue;
            }

            if (s_destaddr == NULL || strcmp(lowerstr((char *)s_destaddr), lowerstr(cmd.daddr)) != 0)
            {
                continue;
            }

            if (s_protocol == NULL || strcmp(lowerstr((char *)s_protocol), lowerstr(cmd.protocol)) != 0)
            {
                continue;
            }

            if (protocol != IPPROTO_ICMP && s_bindport != cmd.bport)
            {
                continue;
            }

            if (protocol != IPPROTO_ICMP && s_destport != cmd.dport)
            {
                continue;
            }

            // We found a match, remove this setting.
            config_setting_remove_elem(fwd, i);
        }

        // Save config.
        config_write_file(&conf, cfgfile);

        fprintf(stdout, "Attempted to remove rule from config.\n");

        // Cleanup.
        config_destroy(&conf);
    }

    return EXIT_SUCCESS;
}