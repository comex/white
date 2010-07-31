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

int get_regs(uint32_t *ttbr0, uint32_t *ttbr1, uint32_t *ttbcr, uint32_t *contextidr) {
    return syscall(8, 0, ttbr0, ttbr1, ttbcr, contextidr);
}

int copy_phys(uint32_t paddr, uint32_t size, void *buf) {
    return syscall(8, 1, paddr, size, buf);
}

int kread(uint32_t addr, uint32_t size, void *buf) {
    return syscall(8, 2, addr, size, buf);
}

uint32_t read32(uint32_t addr) {
    return syscall(8, 3, addr);
}

int crash_kernel() {
    return syscall(8, 4);
}

int log_iosurfaces() {
    return syscall(8, 5);
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
        "RO/RO",
        "111!",
    };
    return descs[ap & 3];
}

static void dump_pagetable(uint32_t ttbr, uint32_t baseaddr, uint32_t size) {
    unsigned int *data = malloc(size);
    assert(!copy_phys(ttbr & ~0x3f, size, data));
    for(int i = 0; i < (size / 4); i++) {
        unsigned int l1desc = data[i];
        if((l1desc & 3) == 0) continue; // fault
        printf("%08x: ", baseaddr + i * 0x100000);
        switch(l1desc & 3) {
        case 1: {
            printf("page table base=%x P=%d domain=%d\n", l1desc & ~0x3ff, (l1desc & (1 << 9)) & 1, (l1desc >> 5) & 0xf);
            unsigned int data2[256];
            memset(data2, 0xff, sizeof(data2));
            assert(!copy_phys(l1desc & ~0x3ff, sizeof(data2), data2));
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

int main(int argc, char **argv) {
    int c;
    bool did_something = false;
    uint32_t ttbr0, ttbr1, ttbcr, contextidr;
    assert(!get_regs(&ttbr0, &ttbr1, &ttbcr, &contextidr));
    
    while((c = getopt(argc, argv, "r01s")) != -1)
    switch(c) {
    case 'r': {
        printf("ttbr0=%x ttbr1=%x ttbcr=%x contextidr=%x\n", ttbr0, ttbr1, ttbcr, contextidr);
        did_something = true;
        break;
    }
    case '0': {
        dump_pagetable(ttbr0, 0, 4096);
        did_something = true;
        break;
    }
    case '1': {
        dump_pagetable(ttbr1, 0, 16384);
        did_something = true;
        break;
    }
    case 's': {
        assert(!log_iosurfaces());
        did_something = true;
        break;
    }
    case '?':
    default:
        printf("Usage: %s [-r] [-0] [-1] [-s]\n", argv[0]);
        return 1;
    }

    if(!did_something) {
        printf("Usage: %s [-r] [-0] [-1] [-s]\n", argv[0]);
        return 1;
    }
    return 0;
}
