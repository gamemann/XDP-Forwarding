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

    if (cmd.daddr == NULL)
    {
        fprintf(stderr, "Missing destination address. Please specify bind address with -b <addr>.\n");

        return EXIT_FAILURE;
    }

    uint32_t bindaddr;
    uint32_t destaddr;
    uint16_t destport = cmd.dport;
    uint8_t protocol = 0;

    // Retrieve 32-bit integers of bind and destination addresses in network byte order.
    struct in_addr baddr;
    inet_pton(AF_INET, cmd.baddr, &baddr);
    bindaddr = baddr.s_addr;

    struct in_addr daddr;
    inet_pton(AF_INET, cmd.daddr, &daddr);
    destaddr = daddr.s_addr;

    // Check destination port.
    if (destport < 1)
    {
        destport = cmd.bport;
    }

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

    struct forward_info fwdinfo = {0};
    fwdinfo.destaddr = destaddr;
    fwdinfo.destport = htons(destport);

    if (bpf_map_update_elem(fwdmap, &fwdkey, &fwdinfo, BPF_ANY) != 0)
    {
        fprintf(stderr, "Error adding forwarding rule :: %s\n", strerror(errno));

        return EXIT_FAILURE;
    }

    fprintf(stdout, "Added forwarding rule %s:%d => %s:%d over protocol %s.\n", cmd.baddr, cmd.bport, cmd.daddr, cmd.dport, protocolstr);

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
            fprintf(stderr, "Could not save rule to config file :: %s\n", strerror(errno));

            return EXIT_FAILURE;
        }

        // Initialize libconfig.
        config_t conf;

        config_init(&conf);

        // Attempt to read config file through libconfig.
        if (config_read(&conf, fp) == CONFIG_FALSE)
        {
            fprintf(stderr, "Could not save rule to config file (could not load config) :: %s\n", config_error_text(&conf));

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
            config_setting_t *root = config_root_setting(&conf);

            fwd = config_setting_add(root, "forwarding", CONFIG_TYPE_LIST);

            if (fwd == NULL)
            {
                fprintf(stderr, "Could not save rule to config file (could not insert 'forwarding' list) :: %s\n", config_error_text(&conf));

                config_destroy(&conf);

                return EXIT_FAILURE;
            }
        }

        // Add new group.
        config_setting_t *rule = config_setting_add(fwd, NULL, CONFIG_TYPE_GROUP);

        if (rule == NULL)
        {
            fprintf(stderr, "Could not save rule to config file (could not add rule group) :: %s\n", config_error_text(&conf));

            config_destroy(&conf);

            return EXIT_FAILURE;
        }

        // Add and set bind address.
        config_setting_t *s_bindaddr = config_setting_add(rule, "bind", CONFIG_TYPE_STRING);

        if (s_bindaddr != NULL)
        {
            config_setting_set_string(s_bindaddr, cmd.baddr);
        }

        // Add and set bind port.
        if (protocol != IPPROTO_ICMP)
        {
            config_setting_t *s_bindport = config_setting_add(rule, "bindport", CONFIG_TYPE_INT);

            if (s_bindport != NULL && protocol != IPPROTO_ICMP)
            {
                config_setting_set_int(s_bindport, cmd.bport);
            }
        }    

        // Add and set destination address.
        config_setting_t *s_destaddr = config_setting_add(rule, "dest", CONFIG_TYPE_STRING);

        if (s_destaddr != NULL)
        {
            config_setting_set_string(s_destaddr, cmd.daddr);
        }

        // Add and set destination port.
        if (protocol != IPPROTO_ICMP)
        {
            config_setting_t *s_destport = config_setting_add(rule, "destport", CONFIG_TYPE_INT);

            if (s_destport != NULL)
            {
                config_setting_set_int(s_destport, cmd.dport);
            }
        }

        // Add and set protocol
        config_setting_t *s_protocol = config_setting_add(rule, "protocol", CONFIG_TYPE_STRING);

        if (s_protocol != NULL)
        {
            config_setting_set_string(s_protocol, cmd.protocol);
        }

        // Save config.
        config_write_file(&conf, cfgfile);

        fprintf(stdout, "Attempted to save rule to config.\n");

        // Cleanup.
        config_destroy(&conf);
    }

    return EXIT_SUCCESS;
}