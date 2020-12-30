#include <libconfig.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "config.h"

int rcount;

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
        fprintf(stderr, "Cannot find \"forwarding\" rules section.\n");

        config_destroy(&conf);

        return EXIT_FAILURE;
    }

    for (int i = 0; i < config_setting_length(fwd); i++)
    {
        config_setting_t *rule = config_setting_get_elem(fwd, i);

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
        
        int bindport;

        if (config_setting_lookup_int(rule, "bindport", &bindport) == CONFIG_FALSE)
        {
            fprintf(stderr, "Could not find bind port on rule %d\n", i);
        }

        cfg->rules[i].bindport = (uint16_t) bindport;

        int destport;

        if (config_setting_lookup_int(rule, "destport", &destport) == CONFIG_FALSE)
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