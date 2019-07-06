#ifndef VIRTUAL_DISK_H
#define VIRTUAL_DISK_H

#include <sys/types.h>

struct virtual_disk;
typedef struct virtual_disk* virtual_disk_t;

int libvd_init(int argc, char **argv);
void libvd_destroy();

virtual_disk_t vd_open(const char *file, const char *fmt, const int64_t offset, const int debug);
void vd_close(const virtual_disk_t vd);

int vd_write(const virtual_disk_t vd, const int64_t offset, const void *buf, const int size);
int vd_read(const virtual_disk_t vd, const int64_t offset, void *buf, int max);

void vd_sync(const virtual_disk_t vd);
#endif