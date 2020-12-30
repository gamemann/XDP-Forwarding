#include <bpf.h>
#include <libbpf.h>

int bpf_map_get(const char *path)
{
    int fd = -1;

    fd = bpf_obj_get(path);

    return fd;
}