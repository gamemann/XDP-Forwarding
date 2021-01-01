#include <bpf.h>
#include <libbpf.h>

/**
 * Retrieves the FD of a BPF map pinned to the file system.
 * 
 * @param path Path to the BPF map on the file system (most likely in /sys/fs/bpf).
 * 
 * @return The FD (integer) of the BPF map.
 */
int bpf_map_get(const char *path)
{
    int fd = -1;

    fd = bpf_obj_get(path);

    return fd;
}

/**
 * Simply lower-cases a string.
 * 
 * @param str Pointer to the full string we want to lower-case (const char).
 * 
 * @return A character pointer to the lower-cased string.
 */
char *lowerstr(const char *str) 
{
    for (char *p = str; *p; p++) 
    {
        *p = tolower(*p);
    }

    return str;
}
