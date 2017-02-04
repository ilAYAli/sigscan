// sigscan
// by petter wahlman, petter@wahlman.no
// zlib magic (78 9c - 0x14 bytes after start)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <libgen.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <sigscan.h>

#include "../src/cryptoscan.c"

struct signature signatures[] = {
    { "ARM Interrupt vectors",       "vect",
        "\x18\xf0\x9f\xe5\x18\xf0\x9f\xe5\x18\xf0\x9f\xe5\x18\xf0\x9f\xe5\x18\xf0\x9f\xe5",       20,   0, _vector_handler },
    { "SHA1",                        "sha1",
        "\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10",                       16,   0, _def_handler },
    { "cpio archive",                "cpio",
        "\x30\x37\x30\x37\x30\x31\x30\x30\x30\x30\x30\x32\x44\x31\x30\x30",                       16,   0, _def_handler },
    { "Cram FS",                     "cfs",      "Compressed ROMFS",                             16, -16, _cramfs_handler },
    { "ROM FS",                      "romfs",    "-rom1fs-",                                     8,    0, _romfs_handler },
    { "Squash FS",                   "sqfs",     "hsqs",                                         4,    0, _squashfs_handler },
    { "BZIP header",                 "bz2",      "BZh91AY&SY",                                   10,   0, _def_handler },
#ifndef __APPLE__
    { "ELF",                         "elf",      "\x7f\x45\x4c\x46",                             4,    0, _elf_handler },
#endif
    { "7-Zip archive",               "7z",       "7z\xbc\xaf\x27\x1c\x00\x02",                   8,    0, _def_handler },
    { "RAR archive",                 "rar",      "Rar!\x1a\x07\x00",                             7,    0, _def_handler },
    { "ZIP central directory",       "zip",      "\x50\x4b\x01\x02",                             4,    0, _zip_central_handler },
    { "ZIP local header",            "zip",      "PK\x03\x04\x14\x00\x00\x00",                   8,    0, _zip_local_handler },
    { "ZIP local header",            "zip",      "PKLITE",                                       6,    0, _zip_local_handler },
    { "ZIP local header",            "zip",      "PKSpX",                                        5,    0, _zip_local_handler },
    { "ZIP local header",            "zip",      "PK\x03\x04",                                   4,    0, _zip_local_handler },
    { "u-boot/PPCBoot image",        "uboot",    "\x27\x05\x19\x56", /*Wolfgang's birthday*/     4,    0, _def_handler },
    { "ISO 9660",                    "iso",      "CD001",                                        5,    0, _def_handler },
    { "TAR archive",                 "tar",      "ustar",                                        5, -0x101, _def_handler },
    { "JFFS2",                       "jffs2",    "\x85\x19\x03\x20",                             4,    0, _def_handler },
    { "LZMA1",                       "lzma",     "\x5d\x00\x00\x80",                             4,    0, _def_handler },
    { "LZMA2",                       "lzma",     "\x80\x00\x00\x5d",                             4,    0, _def_handler },
    { "QEMI QCOW",                   "qcow",     "QFI\xfb",                                      4,    0, _def_handler },
    { "CAB archive",                 "cab",      "ISc(",                                         4,    0, _def_handler },
    { "CAB archive",                 "cab",      "MSCF",                                         4,    0, _def_handler },
    { "uClinux FLAT binary",         "bflt",     "bFLT",                                         4,    0, _def_handler },
    { "GZIP header",                 "gz",       "\x1f\x8b\x08",                                 3,    0, _gzip_handler },
    { "Mediatek bootloader",         "mtek",     "BOOTLOADER!",                                  11,   0, _mtek },
    { "Portable Network Graphics",   "png",      "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a",             8,    0, _def_handler },
    { "MP3 with ID3v2 container",    "mp3",      "\x49\x44\x33",                                 3,    0, _def_handler },
    //{ "ELF 32-bit",                "elf",      "\x7f\x45\x4c\x46\x01",                         5,    0, _def_handler },
    //{ "ELF 64-bit",                "elf",      "\x7f\x45\x4c\x46\x02",                         5,    0, _def_handler },
    //{ "FMA",                       "fma",      "FMA",                                          3,    0, _def_handler },
    //{ "TAR.Z",                     "tgz",      "\x1f\x9d\x90",                                 3,    0, _def_handler },
    //{ "LHA/LZA",                   "lha",      "\x2d\x6c\x68",                                 3,    0, _def_handler },
    //{ "ZLIB",                      "zlib"      "\x78\x9c",                                     2,    0, _def_handler },
};


static void print_signatures(void)
{
    int i;

    printf("\ncontainers (data):\n");
    for (i = 0; i < sizeof(signatures)/sizeof(signatures[0]); i++)  {
        if (i && !strcmp(signatures[i].name, signatures[i-1].name))
            continue;
        printf("\t[%4d bytes] %s\n", signatures[i].magic_len, signatures[i].name);
    }

    printf("\ncrypto algorithms (code):\n");
    for (i = 0; i < sizeof(crypto_signatures)/sizeof(crypto_signatures[0]); i++)  {
        if (i && !strcmp(crypto_signatures[i].algorithm, crypto_signatures[i-1].algorithm))
            continue;
        printf("\t[%4zd bytes] %s\n", crypto_signatures[i].size, crypto_signatures[i].algorithm);
    }
    exit(0);
}

static void print_usage(void)
{

    printf("sigscan v%d.%d by petter wahlman, badeip@binary-art.net\n"
           "usage: sigscan <options> filename\n"
           "    --help            this info\n"
           "    --nofs            don't scan for file systems\n"
           "    --nocrypto        don't scan for crypto signatures\n"
           "    --signatures      show supported signatures\n"
           //"    --bat           show 'bat' command used to extract data\n"
           "\n", VERSION_MAJOR, VERSION_MINOR);
    exit(0);
}

#define OPT_BAT         1
#define OPT_NO_FS       2
#define OPT_NO_CRYPTO   4
int main(int argc, char **argv)
{
    struct stat st;
    int fd;
    int i, j, ac;
    int opts = 0;
    if (argc < 2)
        print_usage();

    for (ac = 1; ac < argc; ac++) {
        if (!strcmp(argv[ac], "--help"))
            print_usage();
        else if (!strcmp(argv[ac], "--signatures"))
            print_signatures();
        else if (!strcmp(argv[ac], "--nofs"))
            opts |= OPT_NO_FS;
        else if (!strcmp(argv[ac], "--nocrypto"))
            opts |= OPT_NO_CRYPTO;
        else if (!strcmp(argv[ac], "--bat"))
            opts |= OPT_BAT;
    }

    for (ac = 1; ac < argc; ac++) {
        if (!strncmp(argv[ac], "--", 2))
            continue;

        //printf("%s: ", basename(argv[ac]));
        printf("\n%s: ", argv[ac]);

        lstat(argv[ac], &st);
        if (!st.st_size)
            continue;

        if (S_ISLNK(st.st_mode)) {
            char path[PATH_MAX+1];
            readlink(argv[ac], path, PATH_MAX+1);
            //printf("symbolic link to \"%s\"\n", path);
            continue;
        }

        if (!S_ISREG(st.st_mode)) {
            //printf("not a regular file.\n");
            continue;
        }

        fd = open(argv[ac], O_RDONLY);
        if (-1 == fd) {
            printf("error: \"%s\"\n", strerror(errno));
            continue;
        }

        //fstat(fd, &st);

        char *addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (-1 == (long)addr) {
            printf("error: %s\n", strerror(errno));
            continue;
        }

        for (i = 0; i < st.st_size; i++) {
            // FS:
            if (!(opts & OPT_NO_FS)) {
                for (j = 0; j < sizeof(signatures)/sizeof(signatures[0]); j++) {
                    if ((i + signatures[j].magic_len) >= st.st_size)
                        continue;
                    if (!memcmp(&addr[i], signatures[j].magic, signatures[j].magic_len)) {
                        uint32_t inc;
                        inc = signatures[j].callback(addr, i + signatures[j].magic_offset, j);
                        if (!inc)
                            continue;
                        //print_magic(signatures[j].magic, signatures[j].magic_len);
                        if (opts & OPT_BAT)
                            printf("\tbat -s 0x%08x %s %s.0x%08x.%s\n\n", i + signatures[j].magic_offset, argv[ac],
                                   basename(argv[ac]), i + signatures[j].magic_offset, signatures[j].ext);
                        //      printf("\n");
                        i += inc;
                    }
                }
            }
            // crypto:
            if (!(opts & OPT_NO_CRYPTO)) {
                for (j = 0; j < sizeof(crypto_signatures)/sizeof(crypto_signatures[0]); j++) {
                    if ((i + crypto_signatures[j].size) >= st.st_size)
                        continue;
                    if (!memcmp(&addr[i], crypto_signatures[j].array, crypto_signatures[j].size)) {
                        printf("\n\t0x%08x: [type: code, len: %.4zd]  %s\n",
                               i,
                               crypto_signatures[j].size,
                               crypto_signatures[j].algorithm);
                        i += crypto_signatures[j].size;
                    }
                }
            }
        }

        munmap(addr, st.st_size);
    }
    return 0;
}

