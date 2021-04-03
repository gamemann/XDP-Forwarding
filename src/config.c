#include <libconfig.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "config.h"
#include "utils.h"

int rcount;

/**
 * Parses our config with the libconfig package.
 * 
 * @param file A pointer to a string (const char) indicating the file name we're parsing with libconfig.
 * @param cfg A pointer to a config struct where we'll be storing the config information in.
 * 
 * @return Returns 0 on success (EXIT_SUCCESS) or 1 on failure (EXIT_FAILURE).
 */
int parseconfig(const char *file, struct config *cfg)
{
    // Open file.
    FILE *fp = fopen(file, "r");

    if (fp == NULL)
    {
        return EXIT_FAILURE;
    }

    // Initialize libconfig.
    config_t conf;
    config_setting_t *setting;

    config_init(&conf);

    // Attempt to read config file through libconfig.
    if (config_read(&conf, fp) == CONFIG_FALSE)
    {
        config_destroy(&conf);

        return EXIT_FAILURE;
    }

    // Read basic settings.
    const char *interface;

    if (config_lookup_string(&conf, "interface", &interface) == CONFIG_FALSE)
    {
        fprintf(stderr, "Config setting \"Interface\" not found. Aborting.\n");

        config_destroy(&conf);

        return EXIT_FAILURE;
    }

    cfg->interface = strdup(interface);

    // Read forwarding rules.
    config_setting_t *fwd;

    fwd = config_lookup(&conf, "forwarding");

    if (fwd == NULL)
    {
        fprintf(stderr, "Cannot find \"forwarding\" rules section. We won't be adding any forwarding rules until xdpfwd-add is used.\n");

        config_destroy(&conf);

        return EXIT_SUCCESS;
    }

    for (int i = 0; i < config_setting_length(fwd); i++)
    {
        config_setting_t *rule = config_setting_get_elem(fwd, i);

        const char *protocol = NULL;

        config_setting_lookup_string(rule, "protocol", &protocol);

        if (protocol != NULL)
        {
            cfg->rules[i].protocol = strdup(protocol);
        }

        const char *bindip;

        if (config_setting_lookup_string(rule, "bind", &bindip) == CONFIG_FALSE)
        {
            fprintf(stderr, "Could not find bind address on rule %d\n", i);

            continue;
        }

        cfg->rules[i].bindaddr = strdup(bindip);

        const char *destip;

        if (config_setting_lookup_string(rule, "dest", &destip) == CONFIG_FALSE)
        {
            fprintf(stderr, "Could not find destination address on rule %d\n", i);

            cfg->rules[i].bindaddr = NULL;

            continue;
        }

        cfg->rules[i].destaddr = strdup(destip);
        
        int bindport = 0;

        if (strcmp(lowerstr((char *)protocol), "icmp") != 0 && config_setting_lookup_int(rule, "bindport", &bindport) == CONFIG_FALSE)
        {
            fprintf(stderr, "Could not find bind port on rule %d\n", i);
        }

        cfg->rules[i].bindport = (uint16_t) bindport;

        int destport;

        if (strcmp(lowerstr((char *)protocol), "icmp") != 0 && config_setting_lookup_int(rule, "destport", &destport) == CONFIG_FALSE)
        {
            destport = bindport;
        }

        cfg->rules[i].destport = (uint16_t) destport;

        rcount++;
    }

    config_destroy(&conf);
    fclose(fp);

    return EXIT_SUCCESS;
}