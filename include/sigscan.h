#ifndef SIGSCAN_H
#define SIGSCAN_H

#include <sys/types.h>


#define VERSION_MAJOR   1
#define VERSION_MINOR   13

typedef unsigned char      u8;
typedef char               s8;
typedef unsigned short     u16;
typedef short              s16;
typedef unsigned int       u32;
typedef int                s32;
typedef unsigned long long u64;
typedef long long          s64;

struct signature {
   s8 *name;
   s8 *ext;
   s8 *magic;
   u32 magic_len;
   s32 magic_offset;
   u32 (*callback)(s8 *, u32, u32);
};

extern struct signature signatures[];

extern u32 _def_handler(s8 *data, u32 offset, u32 idx);
extern u32 _cramfs_handler(s8 *data, u32 offset, u32 idx);
extern u32 _squashfs_handler(s8 *data, u32 offset, u32 idx);
extern u32 _romfs_handler(s8 *data, u32 offset, u32 idx);
extern u32 _zip_central_handler(s8 *data, u32 offset, u32 idx);
extern u32 _zip_local_handler(s8 *data, u32 offset, u32 idx);
extern u32 _gzip_handler(s8 *data, u32 offset, u32 idx);
extern u32 _elf_handler(s8 *data, u32 offset, u32 idx);
extern u32 _vector_handler(s8 *data, u32 offset, u32 idx);
extern u32 _mtek(s8 *data, u32 offset, u32 idx);

#endif
