#ifdef __MINGW32__
#define __USE_MINGW_ANSI_STDIO 0
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#ifndef _WIN32
#include <sys/mman.h>
#else
#include "mman.h"
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#ifndef PATH_MAX
#if defined(_WIN32) || defined(__CYGWIN__)
#define PATH_MAX 256
#elif defined(__linux__)
#define PATH_MAX 4096
#else
#define PATH_MAX 1024
#endif
#endif

#define pk2bpk(pk) (((pk%0x1000000)<<8)+0x42)
#define bpk2pk(bpk) (((bpk>>24)+1)<<24)+(bpk>>8)

const uint8_t *xorCodeEOCD = (uint8_t *)"END_OF_CENTRAL_DIRECTORY_XOR_CODE_OF_BBK_APK_ENCRYPTION";
const uint8_t *xorCodeCD   = (uint8_t *)"CENTRAL_DIRECTORY_XOR_CODE_OF_BBK_APK_ENCRYPTION";
const uint8_t *xorCodeLOCAL= (uint8_t *)"LOCAL_FILE_HEADER_XOR_CODE_OF_BBK_APK_ENCRYPTION";
const uint8_t *xorCodeDD   = (uint8_t *)"DATA_DESCRIPTOR_XOR_CODE_OF_BBK_APK_ENCRYPTION";

#define local_file_magic 0x04034b50
#define bbk_local_file_magic pk2bpk(local_file_magic)

#pragma pack(push, 1)
struct local_file_header {
    uint32_t magic;
    uint16_t version;
    uint16_t flag;
    uint16_t method;
    uint16_t last_modified_time;
    uint16_t last_modified_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t file_name_length;
    uint16_t extra_field_length;
};
#pragma pack(pop)

#define data_descriptor_magic 0x08074b50
#define bbk_data_descriptor_magic pk2bpk(data_descriptor_magic)

#pragma pack(push, 1)
struct data_descriptor {
    uint32_t magic;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
};
#pragma pack(pop)

#define central_directory_file_header_magic 0x02014b50
#define bbk_central_directory_file_header_magic pk2bpk(central_directory_file_header_magic)

#pragma pack(push, 1)
struct directory_source {
    uint32_t magic;
    uint16_t cver;
    uint16_t dver;
    uint16_t flag;
    uint16_t compress_method;
    uint16_t last_modified_time;
    uint16_t last_modifiled_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t file_name_length;
    uint16_t extra_length;
    uint16_t annotation_length;
    uint16_t subsection;
    uint16_t attrib_inside;
    uint32_t attrib_outside;
    uint32_t offset;
};
#pragma pack(pop)

#define end_of_central_magic 0x06054b50
#define bbk_end_of_central_magic pk2bpk(end_of_central_magic)

#pragma pack(push, 1)
struct end_of_central_directory {
    uint32_t magic;
    uint16_t disk_num;
    uint16_t central_start_offset_disk_num;
    uint16_t record_central_num;
    uint16_t total_central_directory_num;
    uint32_t central_size;
    uint32_t central_start_offset;
    uint16_t extra_length;
};
#pragma pack(pop)

enum { CFG_ENCODE, CFG_DECODE };

static struct config {
    int verbose;
    int mode;
    char *input;
    char *output;
} cfg;

static int xor_range(uint8_t* val, uint32_t size, const uint8_t *xorCode, int startOffset) {
    if (size == 0) return -1;
    int xlen = strlen((const char*)xorCode);
    for (uint32_t i = 0; i < size; i++)
        val[i] ^= xorCode[(startOffset + i) % xlen];
    return 0;
}

static int xor_simple(uint8_t* val, uint32_t size, const uint8_t *xorCode) {
    return xor_range(val, size, xorCode, 0);
}

#ifdef _WIN32
static ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
    lseek(fd, offset, SEEK_SET);
    return write(fd, buf, count);
}
#endif

static inline off_t get_eocd_offset(uint8_t *mem, off_t size) {
    uint32_t magic;
    while (1) {
        if (size == 0) break;
        if (mem[size] == (uint8_t)(end_of_central_magic % 0x100) ||
            mem[size] == (uint8_t)(bbk_end_of_central_magic % 0x100)) {
            memcpy(&magic, mem + size, sizeof(magic));
            if (magic == end_of_central_magic || magic == bbk_end_of_central_magic)
                return size;
        }
        size--;
    }
    return 0;
}

static inline void parse_magic(uint32_t *magic) {
    *magic = (cfg.mode == CFG_ENCODE) ? pk2bpk(*magic) : bpk2pk(*magic);
}

static int parse_zip(char* input, char* output, int mode, int verbose) {
    int ret = 0;
    int fdi, fdo;
    struct local_file_header hl;
    struct data_descriptor hdd;
    struct end_of_central_directory heo;
    struct directory_source hds;
    off_t offset = 0, local_offset = 0, data_end = 0;
    uint8_t *buf;

    if (access(output, F_OK) == 0) {
        ret = remove(output);
        if (ret) {
            printf("Error: Cannot remove file %s\n", output);
            return ret;
        }
    }

    fdi = open(input, O_RDONLY | O_BINARY);
    fdo = open(output, O_CREAT | O_TRUNC | O_RDWR | O_BINARY, 0755);
    if (fdo < 0) {
        printf("Error: Failed to create new file.\n");
        return EIO;
    }

    lseek(fdi, 0, SEEK_SET);
    read(fdi, &hl, 28);
    if (hl.magic != local_file_magic && hl.magic != bbk_local_file_magic) {
        fprintf(stderr, "File does not seem like a apk or bpk file.\n");
        close(fdi); close(fdo);
        return 1;
    }
    if (hl.magic == bbk_local_file_magic && mode != CFG_DECODE) {
        fprintf(stderr, "File seems already encrypted.\n");
        close(fdi);
        return 1;
    }

    printf("Converting [%s] -> [%s] ...\n", input, output);

    struct stat st;
    stat(input, &st);
    uint8_t *mem = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fdi, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        close(fdi); close(fdo);
        return 1;
    }

    uint8_t *ptr;
    uint32_t data_len;
    uint16_t flag;

    // 定位 EOCD
    offset = get_eocd_offset(mem, st.st_size);
    if (verbose) printf("Find EOCD at              :\t%ld\n", offset);
    if (offset == 0) {
        printf("Error: Cannot find eocd magic.\n");
        munmap(mem, st.st_size);
        close(fdi); close(fdo);
        return EBADF;
    }
    ptr = mem + offset;
    memcpy(&heo, ptr, sizeof(heo));
    parse_magic(&heo.magic);
    xor_simple((uint8_t*)&heo + sizeof(heo.magic), sizeof(heo) - sizeof(heo.magic), xorCodeEOCD);
    pwrite(fdo, &heo, sizeof(heo), offset);
    if (mode == CFG_ENCODE) {
        xor_simple((uint8_t*)&heo + sizeof(heo.magic), sizeof(heo) - sizeof(heo.magic), xorCodeEOCD);
    }

    // EOCD 注释直接复制，不加密
    if (heo.extra_length != 0) {
        if (verbose) printf("Find End Extra at         :\t%ld\n", offset + sizeof(heo));
        pwrite(fdo, mem + offset + sizeof(heo), heo.extra_length, offset + sizeof(heo));
    }
    if (verbose) {
        printf("Find Central Directory Num: \t%u\n", heo.total_central_directory_num);
        printf("Find Central Total size   : \t%u\n", heo.central_size);
        printf("Find Central Offset at    : \t%u (0x%08x)\n", heo.central_start_offset, heo.central_start_offset);
    }

    // 解析中央目录
    offset = heo.central_start_offset;
    for (uint16_t i = 1; i <= heo.total_central_directory_num; i++) {
        if (verbose) {
            printf("[ %06u / %06u ] Parsing ... \r", i, heo.total_central_directory_num);
            fflush(stdout);
            if (i == heo.total_central_directory_num)
                printf("[ %06u / %06u ] Parsing ... Done!\n", i, heo.total_central_directory_num);
        }

        ptr = mem + offset;
        memcpy(&hds, ptr, sizeof(hds));
        if (mode == CFG_DECODE)
            xor_simple((uint8_t*)&hds + sizeof(hds.magic), sizeof(hds) - sizeof(hds.magic), xorCodeCD);

        flag = hds.flag;
        data_len = sizeof(hds) - sizeof(hds.magic) + hds.extra_length + hds.annotation_length + hds.file_name_length;
        lseek(fdo, offset, SEEK_SET);
        parse_magic(&hds.magic);
        write(fdo, &hds.magic, sizeof(hds.magic));
        offset += sizeof(hds.magic);

        buf = (uint8_t*)malloc(data_len);
        ptr += sizeof(hds);
        memcpy(buf, (uint8_t*)&hds + sizeof(hds.magic), sizeof(hds) - sizeof(hds.magic));
        memcpy(buf + sizeof(hds) - sizeof(hds.magic), ptr, hds.extra_length + hds.annotation_length + hds.file_name_length);
        if (mode == CFG_ENCODE) {
            xor_simple(buf, data_len, xorCodeCD);
        } else {
            xor_simple(buf, sizeof(hds) - sizeof(hds.magic), xorCodeCD);
            xor_simple(buf, data_len, xorCodeCD);
        }
        write(fdo, buf, data_len);
        free(buf);
        offset += data_len;

        // 解析本地文件头
        local_offset = hds.offset;
        ptr = mem + local_offset;
        memcpy(&hl, ptr, sizeof(hl));
        if (mode == CFG_DECODE)
            xor_range((uint8_t*)&hl + sizeof(hl.magic),
                      sizeof(hl) - sizeof(hl.magic) - sizeof(hl.extra_field_length),
                      xorCodeLOCAL, 0);

        uint16_t local_extra_len = hl.extra_field_length;
        uint32_t real_compressed_size = hds.compressed_size;

        // 从数据描述符获取真实压缩大小
        if (flag & 0x8) {
            uint8_t *dd_ptr = ptr + sizeof(hl) + hds.file_name_length + local_extra_len + hds.compressed_size;
            memcpy(&hdd, dd_ptr, sizeof(hdd));
            if (mode == CFG_DECODE) {
                parse_magic(&hdd.magic);
                xor_range((uint8_t*)&hdd + sizeof(hdd.magic), sizeof(hdd) - sizeof(hdd.magic), xorCodeDD, 0);
            }
            real_compressed_size = hdd.compressed_size;
        }

        // 写入压缩数据
        lseek(fdo, offset, SEEK_SET);
        parse_magic(&hl.magic);
        pwrite(fdo,
               ptr + sizeof(hl) + hds.file_name_length + local_extra_len,
               real_compressed_size,
               local_offset + sizeof(hl) + hds.file_name_length + local_extra_len);

        // 写入文件名（补 4 空字节后 XOR）
        buf = (uint8_t*)malloc(hds.file_name_length);
        memcpy(buf, ptr + sizeof(hl), hds.file_name_length);
        xor_range(buf, hds.file_name_length, xorCodeLOCAL, 4);
        pwrite(fdo, buf, hds.file_name_length, local_offset + sizeof(hl));
        free(buf);

        // 写入本地 extra field
        pwrite(fdo, ptr + sizeof(hl) + hds.file_name_length, local_extra_len,
               local_offset + sizeof(hl) + hds.file_name_length);

        // 写入数据描述符
        if (flag & 0x8) {
            if (mode == CFG_ENCODE) {
                xor_range((uint8_t*)&hdd + sizeof(hdd.magic), sizeof(hdd) - sizeof(hdd.magic), xorCodeDD, 0);
                parse_magic(&hdd.magic);
            }
            pwrite(fdo, &hdd, sizeof(hdd),
                   local_offset + sizeof(hl) + hds.file_name_length + local_extra_len + real_compressed_size);
        }

        // 计算物理结束位置
        off_t entry_end = local_offset + sizeof(hl) + hds.file_name_length + local_extra_len + real_compressed_size;
        if (flag & 0x8)
            entry_end += sizeof(hdd);
        if (entry_end > data_end)
            data_end = entry_end;

        // 写回本地文件头（修正 crc/size 字段）
        if (mode == CFG_ENCODE) {
            xor_range((uint8_t*)&hl + sizeof(hl.magic),
                      sizeof(hl) - sizeof(hl.magic) - sizeof(local_extra_len),
                      xorCodeLOCAL, 0);
        }
        if (!(flag & 0x8)) {
            hl.crc32 = (mode == CFG_ENCODE) ? (uint32_t)-1 : hds.crc32;
            hl.compressed_size = (mode == CFG_ENCODE) ? (uint32_t)-1 : hds.compressed_size;
            hl.uncompressed_size = (mode == CFG_ENCODE) ? (uint32_t)-1 : hds.uncompressed_size;
        } else {
            hl.crc32 = (mode == CFG_ENCODE) ? 0U : hds.crc32;
            hl.compressed_size = (mode == CFG_ENCODE) ? 0U : hds.compressed_size;
            hl.uncompressed_size = (mode == CFG_ENCODE) ? 0U : hds.uncompressed_size;
        }
        pwrite(fdo, &hl, sizeof(hl), local_offset);
    }

    // 复制签名块（包含填充）
    off_t copy_size = heo.central_start_offset - data_end;
    if (copy_size > 0) {
        pwrite(fdo, mem + data_end, copy_size, data_end);
        if (verbose)
            printf("Copied signature block + padding, size: %ld\n", copy_size);
    }

    munmap(mem, st.st_size);
    close(fdi);
    close(fdo);
    chmod(output, 0755);
    printf("Done!\n");
    return 0;
}

static void usage() {
    printf(
        "apk2bpk -i [file] -o [file] -d\n"
        "Usage:\n"
        "\t-i [file]   Input file\n"
        "\t-o [file]   Output file\n"
        "\t-d          Decode mode\n"
        "\t-v          Verbose\n"
        "\t-h          Print this help\n"
        "Convert apk <-> bpk\n"
    );
}

static void parse_arg(int argc, char** argv) {
    int opt;
    const char *optstr = "i:o:dvh";
    cfg.mode = CFG_ENCODE;
    cfg.verbose = 0;
    while ((opt = getopt(argc, argv, optstr)) != -1) {
        switch (opt) {
            case 'i': cfg.input = strdup(optarg); break;
            case 'o': cfg.output = strdup(optarg); break;
            case 'd': cfg.mode = CFG_DECODE; break;
            case 'v': cfg.verbose = 1; break;
            case 'h': usage(); exit(0);
            default: break;
        }
    }
}

int main(int argc, char** argv) {
    char output[PATH_MAX];
    if (argc < 2) {
        usage();
        return 1;
    }
    parse_arg(argc, argv);
    if (cfg.input == NULL) {
        fprintf(stderr, "Error: Input file not defined.\n");
        return 1;
    }
    if (access(cfg.input, F_OK) != 0) {
        fprintf(stderr, "Error: Input file [%s] does not exist.\n", cfg.input);
        return EEXIST;
    }
    if (cfg.output == NULL) {
        snprintf(output, sizeof(output), "%s%s", cfg.input,
                 (cfg.mode == CFG_ENCODE) ? ".bpk" : ".apk");
        cfg.output = output;
    }
    // 自动覆盖已存在的文件
    unlink(cfg.output);
    return parse_zip(cfg.input, cfg.output, cfg.mode, cfg.verbose);
}