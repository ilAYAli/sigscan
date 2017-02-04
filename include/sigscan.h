#ifndef SIGSCAN_H
#define SIGSCAN_H

#include <sys/types.h>


#define VERSION_MAJOR   1
#define VERSION_MINOR   13

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef short              s16;
typedef unsigned long long u64;
typedef long long          s64;

struct signature {
    char *name;
    char *ext;
    char *magic;
    uint32_t magic_len;
    int32_t magic_offset;
    uint32_t (*callback)(char *, uint32_t, uint32_t);
};

extern struct signature signatures[];

extern uint32_t _def_handler(char *data, uint32_t offset, uint32_t idx);
extern uint32_t _cramfs_handler(char *data, uint32_t offset, uint32_t idx);
extern uint32_t _squashfs_handler(char *data, uint32_t offset, uint32_t idx);
extern uint32_t _romfs_handler(char *data, uint32_t offset, uint32_t idx);
extern uint32_t _zip_central_handler(char *data, uint32_t offset, uint32_t idx);
extern uint32_t _zip_local_handler(char *data, uint32_t offset, uint32_t idx);
extern uint32_t _gzip_handler(char *data, uint32_t offset, uint32_t idx);
extern uint32_t _elf_handler(char *data, uint32_t offset, uint32_t idx);
extern uint32_t _vector_handler(char *data, uint32_t offset, uint32_t idx);
extern uint32_t _mtek(char *data, uint32_t offset, uint32_t idx);

#endif
