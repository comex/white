#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <getopt.h>
#include <mach/mach_time.h>

#define prop(a, off, typ) *((typ *)(((char *) (a))+(off)))

struct regs {
    uint32_t cpsr;
    uint32_t ttbr0;
    uint32_t ttbr1;
    uint32_t ttbcr;
    uint32_t contextidr;
    uint32_t sctlr;
    uint32_t scr;
    uint32_t dbgdidr;
    uint32_t dbgdrar;
    uint32_t dbgdsar;
    uint32_t id_dfr0;
    uint32_t dbgdscr;
    uint32_t tpidrprw;
    uint32_t dacr;
};

int poke_mem(uint32_t kaddr, void *uaddr, uint32_t size, bool write, bool phys) {
    return syscall(8, 1, kaddr, uaddr, size, write, phys);
}

__attribute__((unused))
static uint32_t read32(uint32_t kaddr) {
    uint32_t result;
    assert(!poke_mem(kaddr, &result, sizeof(result), false, false));
    return result;
}

static const char *cacheable(uint32_t flags) {
    const char *descs[] = {
        "Non-cacheable",
        "Write-Back, Write-Allocate",
        "Write-Through, no Write-Allocate",
        "Write-Back, no Write-Allocate"
    };
    return descs[flags];
}

static const char *tex(uint32_t tex, uint32_t c, uint32_t b) {
    if(tex & 4) {
        static char buf[1024];
        sprintf(buf, "Cacheable, Outer:%s, Inner:%s", cacheable(tex & 3), cacheable(((c & 1) << 1) | (b & 1)));
        return buf;
    }

    const char *descs[] = {
        "Strongly-ordered",
        "Shareable Device",
        "Outer and Inner Write-Through, no Write-Allocate",
        "Outer and Inner Write-Back, no Write-Allocate",
        "Outer and Inner Non-cacheable",
        "Reserved! 00101",
        "Implementation defined! 00110",
        "Outer and Inner Write-Back, Write-Allocate",
        "Non-shareable Device",
        "Reserved! 01001",
        "Reserved! 01010",
        "Reserved! 01011",
    };
    uint32_t thing = ((tex & 7) << 2) |
                     ((c & 1) << 1) |
                     (b & 1);
    return descs[thing];
}

static const char *ap(uint32_t ap) {
    const char *descs[] = {
        "X/X",
        "RW/X",
        "RW/RO",
        "RW/RW",
        "100!",
        "RO/X",
        "RO/RO [deprec.]",
        "RO/RO",
    };
    return descs[ap & 3];
}

static void dump_pagetable(uint32_t ttbr, uint32_t baseaddr, uint32_t size) {
    unsigned int *data = malloc(size);
    assert(!poke_mem(ttbr & ~0x3f, data, size, false, true));
    for(uint32_t i = 0; i < (size / 4); i++) {
        unsigned int l1desc = data[i];
        if((l1desc & 3) == 0) continue; // fault
        printf("%08x: ", baseaddr + i * 0x100000);
        switch(l1desc & 3) {
        case 1: {
            printf("page table base=%x P=%d domain=%d\n", l1desc & ~0x3ff, (l1desc & (1 << 9)) & 1, (l1desc >> 5) & 0xf);
            unsigned int data2[256];
            memset(data2, 0xff, sizeof(data2));
            assert(!poke_mem(l1desc & ~0x3ff, &data2, sizeof(data2), false, true));
            for(int j = 0; j < 256; j++) {
                unsigned int l2desc = data2[j];
                if((l2desc & 3) == 0) continue; // fault
                printf("  %08x: ", baseaddr + (i * 0x100000) + (j * 0x1000));
                switch(l2desc & 3) {
                case 0:
                    printf("fault\n");
                    break;
                case 1:
                    printf("large base=%x [%s] XN=%x nG=%x S=%x AP=%s\n",
                        l2desc & 0xffff0000,
                        tex(l2desc >> 12, l2desc >> 3, l2desc >> 2),
                        (l2desc >> 15) & 1,
                        (l2desc >> 11) & 1,
                        (l2desc >> 10) & 1,
                        ap(((l2desc >> 7) & 4) | ((l2desc >> 4) & 3)));
                    break;
                case 2:
                case 3:
                    printf("small base=%x [%s] XN=%x nG=%x S=%x AP=%s\n",
                        l2desc & 0xfffff000,
                        tex(l2desc >> 6, l2desc >> 3, l2desc >> 2),
                        l2desc & 1,
                        (l2desc >> 11) & 1,
                        (l2desc >> 10) & 1,
                        ap(((l2desc >> 7) & 4) | ((l2desc >> 4) & 3)));
                    break;
                }
            }
            } break;
        case 2:
            if(l1desc & (1 << 18)) {
                printf("supersection base=%x extbase=%x NS=%d nG=%d [%s] AP=%s extbase2=%x XN=%x\n",
                    l1desc & 0xff000000,
                    (l1desc >> 20) & 0xf,
                    (l1desc >> 19) & 1,
                    (l1desc >> 17) & 1,
                    tex(l1desc >> 12, l1desc >> 3, l1desc >> 2),
                    ap(((l1desc >> 15) ? 4 : 0) | ((l1desc >> 10) & 3)),
                    (l1desc >> 5) & 0xf,
                    (l1desc >> 4) & 1);

            } else {
                printf("section!!\n");
            }
            break;
        case 3:
            printf("fine page table!!\n");
            break;
        }
    }
}

static void dump_creep() {
    struct rec {
        uint32_t address;
        uint32_t value;
    } __attribute__((packed));
    struct rec *buf = calloc(1048576, sizeof(struct rec));
    assert(!syscall(8, 11, buf, 1048576 * sizeof(struct rec)));
    for(int i = 0; i < 1048576; i++) {
        if(buf[i].address != 0 || buf[i].value != 0) {
            printf("[%d] %08x: %08x\n", i, buf[i].address, buf[i].value);
        }
    }
    free(buf);
}

struct trace_entry {
    uint32_t sp;
    uint32_t lr;
    uint32_t r[13];
    uint32_t pc;
} __attribute__((packed));

static void dump_protoss() {
    size_t size = 0x8000 * sizeof(struct trace_entry);
    struct trace_entry *buf = malloc(size);
    memset(buf, 0, size);
    int limit = syscall(8, 14, 0, buf, size);
    assert(limit != -1);
    for(int i = 1; i < 0x7fff; i++) {
        if(buf[i].pc) {
            printf("%.5d %08x", i, buf[i].pc);
            for(int r = 0; r < 12; r++)  {
                if(buf[i].r[r] != buf[i-1].r[r]) {
                    printf(" R%d=%08x", r, buf[i].r[r]);
                }
            }
            if(buf[i].sp != buf[i-1].sp) printf(" SP=%08x", buf[i].sp);
            if(buf[i].lr != buf[i-1].lr) printf(" LR=%08x", buf[i].lr);
            printf("\n");
        }
        if(i == limit - 1) {
            printf("--- ptr ---\n");
        }
    }
    free(buf);
}

struct watch_entry {
    uint32_t sp;
    uint32_t lr;
    uint32_t r[13];
    uint32_t pc;
    uint32_t accessed_address;
    uint32_t accessed_value;
    uint32_t was_store;
} __attribute__((packed));

static void dump_watch() {
    size_t size = 0x8000 * sizeof(struct watch_entry);
    struct watch_entry *buf = malloc(size);
    memset(buf, 0, size);
    int limit = syscall(8, 14, 1, buf, size);
    assert(limit != -1);
    for(int i = 0; i < 0x7fff; i++) {
        if(buf[i].accessed_address) {
            printf("%.5d %08x %s%08x] <- %08x", i, buf[i].accessed_address, buf[i].was_store ? "STORE [was " : "LOAD [", buf[i].accessed_value, buf[i].pc);
            for(int r = 0; r <= 12; r++)  {
                printf(" R%d=%08x", r, buf[i].r[r]);
            }
            printf(" SP=%08x LR=%08x\n", buf[i].sp, buf[i].lr);
            printf("\n");
        }
    }
    free(buf);
}

static void get_object_info(uint32_t object) {
    char buf[128];
    assert(!syscall(8, 25, object, buf, sizeof(buf)));
    printf("%s ", buf);
    int retain_count = syscall(8, 26, object);
    printf("retain=%d\n", retain_count);
}

static void list_iosurfaces() {
    uint32_t root = syscall(8, 13, 128, "IOService:/IOResources/IOCoreSurfaceRoot");
    assert(root);
    struct {
        uint32_t bufs;
        uint32_t count;
    } s;
    assert(!poke_mem(root + 0x80, &s, sizeof(s), false, false));
    for(uint32_t i = 0; i < s.count; i++) {
        uint32_t surface;
        char buf[0x100];
        assert(!poke_mem(s.bufs + 4*i, &surface, sizeof(surface), false, false));
        if(!surface) continue;
        assert(!poke_mem(surface, buf, sizeof(buf), false, false));
        uint32_t mysterious_88 = prop(buf, 0x88, uint32_t);
        uint32_t task = prop(buf, 0x44, uint32_t);

        printf("surface %u @ %x:\n", i, surface);
        printf("  global: %s\n", prop(buf, 0x15, bool) ? "YES" : "NO");
        if(mysterious_88) {
            int use_count;
            assert(!poke_mem(mysterious_88 + 0xc, &use_count, sizeof(use_count), false, false));
            printf("  use count: %d\n", use_count);
        }
        printf("  address: %x\n", prop(buf, 0x34, unsigned int));
        printf("  owning task: %x\n", task);
        printf("  size: %dx%d\n", prop(buf, 0x58, int), prop(buf, 0x5c, int));
        printf("  bytes per row: %d\n", prop(buf, 0x60, int));
        printf("  bytes per element: %d\n", (int) prop(buf, 0x64, short));
        printf("  element size: %dx%d\n", (int) prop(buf, 0x66, unsigned char), (int) prop(buf, 0x67, unsigned char));
        printf("  offset: %d\n", prop(buf, 0x68, int));
        printf("  pixel format: %x = %.4s\n", prop(buf, 0x6c, unsigned int), buf + 0x6c);
        printf("  alloc size: %d\n", prop(buf, 0x74, int));
        printf("  number of planes: %d\n", prop(buf, 0x78, int));
        printf("  ycbcr matrix: %x\n", prop(buf, 0x7c, unsigned int));
        printf("  cache mode: %x\n", prop(buf, 0x80, unsigned int));
        printf("  planes: %x\n", prop(buf, 0x8c, unsigned int));
        printf("  memory region?: %x, %x\n", prop(buf, 0x90, unsigned int), prop(buf, 0x94, unsigned int));
        printf("  a0: %x\n", prop(buf, 0xa0, unsigned int));
        printf("  a0 count: %x\n", prop(buf, 0xa4, unsigned int));
        printf("\n");
    }
}

uint32_t parse_hex(const char *optarg) {
    errno = 0;
    char *end;
    long long ret = strtoll(optarg, &end, 16);
    if(errno) {
        printf("Can't parse %s: %s\n", optarg, strerror(errno));
        abort();
    } else if(*end) {
        printf("Invalid hex string: %s\n", optarg);
        abort();
    } else {
        return (uint32_t) ret;
    }
}

int main(int argc, char **argv) {
    int c;
    bool did_something = false;
    int tracer_ticks = 0;
    int hook_force = 0;
    struct regs regs;
    
    struct option options[] = {
        {"ioreg", required_argument, 0, 128},
        {"ioreg-matching", required_argument, 0, 134},
        {"ioreg-name-matching", required_argument, 0, 135},
        {"metaclass", required_argument, 0, 135},
        {"crash-kernel", no_argument, 0, 129},
        {"test-protoss", no_argument, 0, 130},
        {"weird", required_argument, 0, 132},
        {"sysctl", no_argument, 0, 144},
        {"note", required_argument, 0, 142},
        {"read-debug-reg", required_argument, 0, 136},
        {"write-debug-reg", required_argument, 0, 137},
        {"do-something", no_argument, 0, 138},
        {"time", no_argument, 0, 139},
        {"ticks", required_argument, 0, 141},
        {"delay", required_argument, 0, 143},
        {0, 0, 0, 0}
    };
    int idx;
    while((c = getopt_long(argc, argv, "mMr012sl:w:L:W:uh:v:w:c:CPUdt:a:Ao:p:f", options, &idx)) != -1) {
        did_something = true;
        switch(c) {
        case 'r':
            assert(!syscall(8, 0, &regs));
            printf("cpsr=%x ttbr0=%x ttbr1=%x ttbcr=%x contextidr=%x sctlr=%x scr=%x\n", regs.cpsr, regs.ttbr0, regs.ttbr1, regs.ttbcr, regs.contextidr, regs.sctlr, regs.scr);
            printf("dbgdidr=%x dbgdrar=%x dbgdsar=%x id_dfr0=%x dbgdscr=%x\n", regs.dbgdidr, regs.dbgdrar, regs.dbgdsar, regs.id_dfr0, regs.dbgdscr);
            printf("tpidrprw=%x dacr=%x\n", regs.tpidrprw, regs.dacr);
            break;
        case '0':
            assert(!syscall(8, 0, &regs));
            dump_pagetable(regs.ttbr0, 0, 0x1000);
            break;
        case '1':
            assert(!syscall(8, 0, &regs));
            dump_pagetable(regs.ttbr1, 0, 0x4000);
            break;
        case '2':
            assert(!syscall(8, 0, &regs));
            dump_pagetable(regs.ttbr1 - 0x4000, 0, 0x4000);
            break;
        case 'p': {
            uint32_t pt = syscall(8, 28, atoi(optarg));
            assert(pt);
            printf("pt = %08x\n", pt);
            dump_pagetable(pt, 0, 0x1000);
            break;
        }
        case 's':
            list_iosurfaces();
            break;
        case 'l':
        case 'L': {
            uint32_t result;
            assert(!poke_mem(parse_hex(optarg), &result, sizeof(result), false, c == 'L'));
            printf("%08x\n", result);
            break;
        }
        case 'w':
        case 'W': {
            char *a = strsep(&optarg, "=");
            assert(a && optarg);
            
            uint32_t val = parse_hex(optarg);
            assert(!poke_mem(parse_hex(a), &val, sizeof(val), true, c == 'W'));
            break;
        }
        case 'u':
            assert(!syscall(8, 6));
            break;
        case 'h':
            assert(!syscall(8, 7, parse_hex(optarg), hook_force));
            break;
        case 142:
            assert(!syscall(8, 8, parse_hex(optarg), hook_force));
            break;
        case 143:
            assert(!syscall(8, 12, parse_hex(optarg), hook_force));
            break;
        case 144:
            assert(!syscall(8, 31));
        case 132:
            assert(!syscall(8, 9, parse_hex(optarg), hook_force));
            break;
        case 'c': {
            char *a = strsep(&optarg, "+");
            assert(a && optarg);
            assert(!syscall(8, 10, parse_hex(a), parse_hex(optarg)));
            break;
        }
        case 'C':
            dump_creep();
            break;
        case 'P':
            dump_protoss();
            break;
        case 'U':
            assert(!syscall(8, 12));
            break;
        case 128:
        case 134:
        case 135:
            printf("%p\n", (void *) syscall(8, 13, c, optarg));
            break;
        case 129:
            syscall(8, 4);
            break;
        case 130:
            assert(!syscall(8, 15));
            break;
        case 'd':
            assert(!syscall(8, 17));
            break;
        case 133:
            assert(!syscall(8, 19, parse_hex(optarg)));
            break;
        case 141:
            tracer_ticks = atoi(optarg);
            break;
        case 'f':
            hook_force = 1;
            break;
        case 't':
            assert(!syscall(8, 20, parse_hex(optarg), hook_force, tracer_ticks));
            break;
        case 'a': {
            char *a = strsep(&optarg, "+");
            assert(a && optarg);
            assert(!syscall(8, 22, parse_hex(a), parse_hex(optarg)));
            break;
        }
        case 'A':
            dump_watch();
            break;
        case 136:
            printf("%08x\n", syscall(8, 23, atoi(optarg)));
            break;
        case 137: {
            char *a = strsep(&optarg, "=");
            assert(a && optarg);
            assert(!syscall(8, 24, atoi(a), parse_hex(optarg)));
            break;
        }
        case 'o':
            get_object_info(parse_hex(optarg));
            break;
        case 138:
            // do_something
            printf("%08x\n", syscall(8, 27));
            break;
        case 139: {
            mach_timebase_info_data_t info;
            mach_timebase_info(&info);
            printf("mach_absolute_time: %llu * %d/%d\n", mach_absolute_time(), info.numer, info.denom);
            break;
        }
        case 'm':
            assert(!syscall(8, 29));
            break;
        case 'M': {
            static char buf[1048576];
            assert(!syscall(8, 30, buf, sizeof(buf)));
            printf("%s", buf);
            break;
        }
        case '?':
        default:
            goto usage;
        }
    }

    if(!did_something) goto usage;
    return 0;
usage:
    printf("Usage: %s ...\n"
           "    -r:                    print some regs\n"
           "    -0:                    dump memory map at ttbr0\n"
           "    -1:                    dump memory map at ttbr1\n"
           "    -2:                    dump memory map at ttbr1-0x4000\n"
           "    -p pid:                dump memory map of process\n"
           "    -s:                    dump some info about IOSurfaces\n"
           "    -l addr:               do a read32\n"
           "    -w addr=value:         do a write32\n"
           "    -L addr:               do a physical read32\n"
           "    -W addr=value:         do a physical write32\n"
           "    -u:                    unhook\n"
           "    -f:                    when hooking, force\n"
           "    -h addr:               hook for generic logging\n"
           "    --weird addr:          hook weird for logging\n"
           "    --sysctl:              hook sysctl for logging\n"
           "    --note addr:           hook roughly arbitrary address\n"
           "    -c addr+size:          hook range for creep\n"
           "    -C:                    dump creep results\n"
           "    -P:                    dump protoss results\n"
           "    -U:                    do something usb related\n"
           "    --ioreg path:          look up IORegistryEntry\n"
           "    --ioreg-matching:      service matching\n"
           "    --ioreg-name-matching: name matching\n"
           "    --metaclass name:      look up OSMetaClass\n"
           "    --crash-kernel:        crash the kernel\n"
           "    --test-protoss:        test protoss\n"
           "    -t addr:               hook for generic logging + trace (protoss)\n"
           "    --ticks n:             number of calls to skip before tracing\n"
           "    -a addr+mask:          watch range\n"
           "    -A:                    dump watch results\n"
           "    --read-debug-reg num:  dump debug reg\n"
           "    --write-debug-reg num=val: write debug reg\n"
           "    -o addr:               get object info\n"
           "    -d:                    Debugger()\n"
           "    -m:                    hook conslog_putc (like dmesg)\n"
           "    -M:                    see conslog_putc results\n"
           "    --do-something:        so transient I won't make it a real option\n"
           "    --time:                mach_absolute_time\n"
           , argv[0]);
    return 1;
}
