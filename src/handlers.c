#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <libgen.h>
#include <sys/types.h>

#include <sigscan.h>
#ifndef __APPLE__
#include <elf.h>


//---[ ELF ] --------------------------------------------------------------------------------------
uint32_t _elf_handler(char *data, uint32_t offset, uint32_t idx)
{
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)&data[offset];
    char *class, *bits, *type, *machine;
    int ret;

    ret = 0;
    switch(ehdr->e_ident[EI_CLASS]) {
        case 0: bits = "invalid class"; break;
        case 1: bits = "32-bit"; break;
        case 2: bits = "64-bit"; break;
        default: goto out;
    }

    switch(ehdr->e_ident[EI_DATA]) {
        case 0: class = "Invalid data encoding"; break;
        case 1: class = "LSB"; break;
        case 2: class = "MSB"; break;
        default: goto out;
    }

    switch(ehdr->e_type) {
        case 1: type = "relocatable"; break;
        case 2: type = "executable"; break;
        case 3: type = "shared object"; break;
        case 4: type = "core"; break;
        default: goto out;
    }

    switch(ehdr->e_machine) {
        case 0: machine="No machine"; break;
        case 1: machine="AT&T WE 32100"; break;
        case 2: machine="SPARC"; break;
        case 3: machine="Intel"; break;
        case 4: machine="Motorola 68000"; break;
        case 5: machine="Motorola 88000"; break;
        case 7: machine="Intel 80860"; break;
        case 8: machine="MIPS I"; break;
        case 10:machine="MIPS RS3000 LE"; break;
        case 15:machine="Hewlett-Packard PA-RISC"; break;
        case 17:machine="Fujitsu VPP500"; break;
        case 18:machine="Enhanced instruction set SPARC"; break;
        case 19:machine="Intel 80960"; break;
        case 20:machine="Power PC"; break;
        case 36:machine="NEC V800"; break;
        case 37:machine="Fujitsu FR20"; break;
        case 38:machine="TRW RH-32"; break;
        case 39:machine="Motorola RCE"; break;
        case 40:machine="Advanced RISC Machines ARM"; break;
        case 41:machine="Digital Alpha"; break;
        case 42:machine="Hitachi SH"; break;
        case 43:machine="SPARC Version 9"; break;
        case 44:machine="Siemens Tricore embedded processor"; break;
        case 45:machine="Argonaut RISC Core, Argonaut Technologies Inc."; break;
        case 46:machine="Hitachi H8/300"; break;
        case 47:machine="Hitachi H8/300H"; break;
        case 48:machine="Hitachi H8S"; break;
        case 49:machine="Hitachi H8/500"; break;
        case 50:machine="Intel MercedTM Processor"; break;
        case 51:machine="Stanford MIPS-X"; break;
        case 52:machine="Motorola Coldfire"; break;
        case 53:machine="Motorola M68HC12"; break;
        case 62:machine="Intel x86-64"; break;
        case 89:machine="Matsushita MN10300"; break;
                //default: goto out;
        default: {
            printf("machine = %d\n", ehdr->e_machine); machine="unknown";
        }
    }

    printf("\n\t0x%08x: ELF {\n", offset);
    printf("\t   machine: %s\n", machine);
    printf("\t   class:   %s\n", class);
    printf("\t   bits:    %s\n", bits);
    printf("\t   type:    %s\n", type);
    printf("\t}\n");

    //printf("\t0x%08x:  ELF %s %s %s %s\n", offset, class, machine, bits, type);

    ret = signatures[idx].magic_len + sizeof(*ehdr);
out:
    return ret;
}

#endif

//---[ default handler ]---------------------------------------------------------------------------
uint32_t _def_handler(char *data, uint32_t offset, uint32_t idx)
{
    //printf("org offset: 0x%08x, magic offset: %d\n", offset, signatures[idx].magic_offset);
    printf("\n\t0x%08x: [type: data, len: %.4d]  %s\n",
           offset,
           signatures[idx].magic_len,
           signatures[idx].name);

    return signatures[idx].magic_len;
}


//---[ ROMFS ]-------------------------------------------------------------------------------------
struct romfs_super_block {
    uint32_t word0;
    uint32_t word1;
    uint32_t size;
    uint32_t checksum;
    char name[0]; /* volume name */
}__attribute__((packed));

uint32_t _romfs_handler(char *data, uint32_t offset, uint32_t idx)
{
    struct romfs_super_block *sb = (typeof(sb))&data[offset];
    uint32_t name_len;
    uint32_t rc;

    printf("\n\t0x%08x: ROMFS {\n", offset);
    printf("\t   0x%08lx: word0:     0x%08x\n", (unsigned long)&sb->word0 - (unsigned long)&sb, sb->word0);
    printf("\t   0x%08lx: word1:     0x%08x\n", (unsigned long)&sb->word1 - (unsigned long)&sb, sb->word1);
    printf("\t   0x%08lx: size:      0x%08x\n", (unsigned long)&sb->size  - (unsigned long)&sb, sb->size);
    printf("\t   0x%08lx: checksum:  0x%08x\n", (unsigned long)&sb->checksum - (unsigned long)&sb, sb->checksum);

    rc = 0;
    for (name_len = 0; sb->name[name_len]; name_len++)
        if (!isprint(sb->name[name_len]))
            return rc;

    printf("\t   0x%08lx: name:      %s\n", (unsigned long)&sb - (unsigned long)sb->name, sb->name);
    printf("\t};\n");

    rc = sizeof(*sb) - signatures[idx].magic_len + name_len;
    return rc;
}
//---[ SQUASH FS ]---------------------------------------------------------------------------------

struct squashfs_super_block {
    uint32_t s_magic;
    uint32_t inodes;
    uint32_t bytes_used_2;
    uint32_t uid_start_2;
    uint32_t guid_start_2;
    uint32_t inode_table_start_2;
    uint32_t directory_table_start_2;
    uint32_t s_major:16;
    uint32_t s_minor:16;
    uint32_t block_size_1:16;
    uint32_t block_log:16;
    uint32_t flags:8;
    uint32_t no_uids:8;
    uint32_t no_guids:8;
    uint32_t mkfs_time /* time of filesystem creation */;
    u64 root_inode;
    uint32_t block_size;
    uint32_t fragments;
    uint32_t fragment_table_start_2;
    s64 bytes_used;
    s64 uid_start;
    s64 guid_start;
    s64 inode_table_start;
    s64 directory_table_start;
    s64 fragment_table_start;
    s64 lookup_table_start;
} __attribute__ ((packed));

uint32_t _squashfs_handler(char *data, uint32_t offset, uint32_t idx)
{
    struct squashfs_super_block *sb = (typeof(sb)) &data[offset];

    printf("\n\t0x%08x: SQUASHFS {\n", offset);
    printf("\t   0x%08lx: magic:     0x%08x\n", (unsigned long)sb->s_magic - (unsigned long)sb, sb->s_magic);
    printf("\t   0x%08lx: inodes:    0x%08x\n", (unsigned long)sb->inodes - (unsigned long)sb, sb->inodes);
    printf("\t   0x%08lx: size:      0x%08x\n", (unsigned long)&sb->bytes_used_2 - (unsigned long)&sb, sb->bytes_used_2);
    printf("\t   0x%08lx: date:      %s\n", (unsigned long)&sb->mkfs_time - (unsigned long)&sb, ctime((time_t *)&sb->mkfs_time));
    //printf("\t   0x%08x: crc:       0x%08x\n", (uint32_t)&sb->fsid.crc - (uint32_t)&sb, sb->fsid.crc);

    printf("\t};\n");

    return sizeof(*sb) - signatures[idx].magic_len;
}
//---[ CRAMFS ]------------------------------------------------------------------------------------
struct cramfs_info {
    uint32_t crc;
    uint32_t edition;
    uint32_t blocks;
    uint32_t files;
}__attribute__((packed));

struct cramfs_super {
    uint32_t magic;         // 0x28cd3d45 - random number
    uint32_t size;          // length in bytes
    uint32_t flags;         // feature flags
    uint32_t future;        // reserved for future use
    uint8_t signature[16];  // "Compressed ROMFS"
    struct cramfs_info fsid;// unique filesystem info
    uint8_t name[16];
}__attribute__((packed));

uint32_t _cramfs_handler(char *data, uint32_t offset, uint32_t idx)
{
    struct cramfs_super *sb = (typeof(sb)) &data[offset];
    uint32_t i;
    uint32_t rc;

    printf("\n\t0x%08x: CRAMFS {\n", offset);
    printf("\t   0x%08lx: magic:     0x%08x\n", (unsigned long)sb->magic - (unsigned long)sb, sb->magic);
    printf("\t   0x%08lx: size:      0x%08x\n", (unsigned long)&sb->size - (unsigned long)&sb, sb->size);
    printf("\t   0x%08lx: crc:       0x%08x\n", (unsigned long)&sb->fsid.crc - (unsigned long)&sb, sb->fsid.crc);

    rc = sizeof(*sb) - signatures[idx].magic_len;
    for (i = 0; sb->name[i]; i++)
        if (!isprint(sb->name[i]))
            goto out;
    rc += i;
    printf("\t   0x%08lx: name:      \"%s\"\n", (unsigned long)&sb->name - (unsigned long)&sb, sb->name);
out:
    printf("\t};\n");

    return sizeof(*sb) - signatures[idx].magic_len;
}

//---[ ARM exception vector ]----------------------------------------------------------------------
uint32_t _vector_handler(char *data, uint32_t offset, uint32_t idx)
{
    printf("\n\t0x%08x: ARM exception vector table {\n", offset);
    printf("\t   0x%08x: 18f09fe5  ldr  pc, [pc, #0x18]; // reset vector\n", offset);
    printf("\t   0x%08x: 18f09fe5  ldr  pc, [pc, #0x18]; // undefined instruction vector\n", offset + 0x4);
    printf("\t   0x%08x: 18f09fe5  ldr  pc, [pc, #0x18]; // software interrupt vector (SWI)\n", offset + 0x8);
    printf("\t   0x%08x: 18f09fe5  ldr  pc, [pc, #0x18]; // abort prefetch vector\n", offset + 0xc);
    printf("\t   0x%08x: 18f09fe5  ldr  pc, [pc, #0x18]; // address exception trap\n", offset + 0x10);
    printf("\t   0x%08x: 18f09fe5  ldr  pc, [pc, #0x18]; // interrupt request vector (IRQ)\n", offset + 0x14);
    printf("\t   0x%08x: 18f09fe5  ldr  pc, [pc, #0x18]; // fast interrupt request vector (FIQ)\n", offset + 0x18);
    printf("\t};\n");

    return signatures[idx].magic_len;
}

//---[ Mediatek bootloader ]-----------------------------------------------------------------------
typedef struct _BOOTLHeader_ {
    char ID1[12];     // BOOTLOADER!\0
    char version[4];
    uint32_t length;
    uint32_t startAddr;
    uint32_t checksum;
    char ID2[8];      // NFIINFO\0
    uint8_t NFIinfo[6];
    uint16_t  pagesPerBlock;
    uint16_t  totalBlocks;
    uint16_t  blockShift;
    uint16_t  linkAddr[6];
    uint16_t  lastBlock;
} BOOTL_HEADER;

uint32_t _mtek(char *data, uint32_t offset, uint32_t idx)
{
    BOOTL_HEADER *bh;

    bh = (BOOTL_HEADER *)data;

    if (strncmp(bh->ID2, "NFIINFO", strlen("NFIINFO")))
        return 0;

    printf("\n\t0x%08x: Mediatek bootloader {\n", offset);
    printf("\t   0x%08lx   ID1:          \"%s\"\n", (unsigned long)&bh->ID1 - (unsigned long)&bh, bh->ID1);
    printf("\t   0x%08lx   version:      \"%s\"\n", (unsigned long)&bh->version - (unsigned long)&bh, bh->version);
    printf("\t   0x%08lx   length:       0x%08x\n", (unsigned long)&bh->length - (unsigned long)&bh, ntohl(bh->length));
    printf("\t   0x%08lx   start addr:   0x%08x\n", (unsigned long)&bh->startAddr - (unsigned long)&bh, ntohl(bh->startAddr));
    printf("\t   0x%08lx   checksum:     0x%08x\n", (unsigned long)&bh->checksum - (unsigned long)&bh, ntohl(bh->checksum));
    printf("\t   0x%08lx   ID2:          \"%s\"\n", (unsigned long)&bh->ID2 - (unsigned long)&bh, bh->ID2);
    printf("\t   0x%08lx   NFIinfo:      %02X%02x%02X%02X%02X%02X\n", (unsigned long)&bh->NFIinfo - (unsigned long)&bh,
           bh->NFIinfo[0], bh->NFIinfo[1], bh->NFIinfo[2], bh->NFIinfo[3], bh->NFIinfo[4], bh->NFIinfo[5]);
    printf("\t   0x%08lx   pages/block:  %d\n", (unsigned long)&bh->pagesPerBlock - (unsigned long)&bh, bh->pagesPerBlock);
    printf("\t   0x%08lx   total blocks: %d\n", (unsigned long)&bh->totalBlocks - (unsigned long)&bh, bh->totalBlocks);
    printf("\t   0x%08lx   link address: %02X%02x%02X%02X%02X%02X\n", (unsigned long)&bh->linkAddr - (unsigned long)&bh,
           bh->linkAddr[0], bh->linkAddr[1], bh->linkAddr[2], bh->linkAddr[3], bh->linkAddr[4], bh->linkAddr[5]);
    printf("\t   0x%08lx   last block:   %d\n\n", (unsigned long)&bh->lastBlock - (unsigned long)&bh, bh->lastBlock);
    printf("\t};\n");

    return sizeof(*bh)-signatures[idx].magic_len;
}

//---[ ZIP central header ]------------------------------------------------------------------------
typedef struct zip_central {
    uint32_t signature; //(0x02014b50)
    u16 version;
    u16 version_needed;
    u16 gps_flag;
    u16 compression;
    u16 last_mod;
    u16 last_date;
    uint32_t crc;
    uint32_t compr_size;
    uint32_t uncompr_size;
    u16 name_len;
    u16 extra_len;
    u16 comment_len;
    u16 disk_num;
    u16 attrib;
    uint32_t external_attrib;
    uint32_t rel_offset;
    char name[0];
} __attribute__((packed)) zip_central_t;

uint32_t _zip_central_handler(char *data, uint32_t offset, uint32_t idx)
{
    struct zip_central *zip = (struct zip_central *) &data[offset];
    char name[PATH_MAX];
    uint32_t i;

    // name verification:
    for (i = 0; i < zip->name_len && zip->name[i]; i++) {
        if (!isprint(zip->name[i]))
            break;
        name[i] = zip->name[i];
    }
    if (i != zip->name_len)
        return 0;
    name[i] = '\0';

    printf("\n\t0x%08x: ZIP central directory header {\n", offset);
    printf("\t   %-13s \"%s\"\n", "name:", name);
    printf("\t   %-14s 0x%08x\n", "crc:", zip->crc);
    printf("\t   %-14s 0x%08x\n", "compr. size:", zip->compr_size);
    printf("\t   %-14s 0x%08x\n", "uncompr. size:", zip->uncompr_size);
    printf("\t}\n");

    return zip->compr_size;
}

//---[ ZIP local header ]--------------------------------------------------------------------------
typedef struct zip_local {
    uint32_t signature; //(0x04034b50)
    u16 version_needed;
    u16 gps_flag;
    u16 compression;
    u16 last_mod;
    u16 last_date;
    uint32_t crc;
    uint32_t compr_size;
    uint32_t uncompr_size;
    u16 name_len;
    u16 extra_len;
    char name[0];
} __attribute__((packed)) zip_local_t;

uint32_t _zip_local_handler(char *data, uint32_t offset, uint32_t idx)
{
    struct zip_local *zip = (struct zip_local *) &data[offset];
    char name[PATH_MAX];
    uint32_t i;

    // name verification:
    for (i = 0; i < zip->name_len && zip->name[i]; i++) {
        if (!isprint(zip->name[i]))
            break;
        name[i] = zip->name[i];
    }
    if (i != zip->name_len)
        return 0;
    name[i] = '\0';

    printf("\n\t0x%08x: ZIP local file header {\n", offset);
    printf("\t   %-14s \"%s\"\n", "name:", name);
    printf("\t   %-14s 0x%08x\n", "crc:", zip->crc);
    printf("\t   %-14s 0x%08x\n", "compr. size:", zip->compr_size);
    printf("\t   %-14s 0x%08x\n", "uncompr. size:", zip->uncompr_size);
    printf("\t}\n");

    return zip->compr_size;
}

//---[ GZIP ]--------------------------------------------------------------------------------------
#define GZIP_FTEXT      0x01
#define GZIP_FHCRC      0x02
#define GZIP_FEXTRA     0x04
#define GZIP_FNAME      0x08
#define GZIP_FCOMMENT   0x10
#define GZIP_FRESERVED1 0x20
#define GZIP_FRESERVED2 0x40
#define GZIP_FRESERVED3 0x80

typedef struct gzip {
    uint8_t  id1; // 0x1f
    uint8_t  id2; // 0x8b
    uint8_t  cm;  // 0x08
    uint8_t  flg;
    uint32_t time;
    uint8_t  eflags;
    uint8_t  ostype;
    char name[0];
} __attribute__((__packed__)) gzip_t;

uint32_t _gzip_handler(char *data, uint32_t offset, uint32_t idx)
{
    struct gzip *gz = (struct gzip *) &data[offset];
    char timebuf[26];
    uint32_t name_len;
    uint32_t rc;

    rc = 0;
    // name validity check:
    name_len = 0;
    if (gz->flg & GZIP_FNAME) {
        for (name_len = 0; gz->name[name_len]; name_len++) {
            if (!isprint(gz->name[name_len]))
                return rc;
        }
    }

    printf("\n\t0x%08x GZIP compressed data {\n", offset);
    if (name_len)
        printf("\t   %-10s \"%s\"\n", "name:", gz->name);

    // compression method:
    printf("\t   %-10s ", "method:");
    switch(gz->cm) {
        case 8: printf("deflate%d\n", gz->cm); break;
        default: printf("%d\n", gz->cm);
    }

    printf("\t   %-10s ", "type:");
    if (gz->flg & GZIP_FTEXT)
        printf("ASCII\n");
    else
        printf("binary\n");

    printf("\t   %-10s ", "OS type:");
    switch(gz->ostype) {
        case 0: printf("FAT based\n"); break;
        case 1: printf("Amiga\n"); break;
        case 2: printf("VMS\n"); break;
        case 3: printf("Unix\n"); break;
        case 4: printf("VM/CMS\n"); break;
        case 5: printf("Atari TOS\n"); break;
        case 6: printf("HPFS based\n"); break;
        case 7: printf("Macintosh\n"); break;
        case 8: printf("Z-System\n"); break;
        case 9: printf("CP/M\n"); break;
        case 10:printf("TOPS-20\n"); break;
        case 11:printf("NTFS based\n"); break;
        case 12:printf("QDOS\n"); break;
        case 13:printf("Acorn RISCOS\n"); break;
        default: printf("[unknown: %d]\n", gz->ostype);
    }

    ctime_r((time_t *)&gz->time, timebuf);
    timebuf[strlen(timebuf)-1] = '\0';
    printf("\t   %-10s %s\n", "date:", timebuf);
    printf("\t}\n");

    rc = sizeof(*gz) - signatures[idx].magic_len;

    return rc;
}

