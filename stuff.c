#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

int get_regs(uint32_t *ttbr0, uint32_t *ttbr1, uint32_t *ttbcr) {
    return syscall(8, 0, ttbr0, ttbr1, ttbcr);
}

int copy_phys(uint32_t paddr, uint32_t size, void *buf) {
    return syscall(8, 1, paddr, size, buf);
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
            printf("coarse page table base=%x P=%d domain=%d\n", l1desc & ~0x3ff, (l1desc & (1 << 9)) ? 1 : 0, (l1desc >> 5) & 0xf);
            unsigned int data2[256];
            memset(data2, 0xff, sizeof(data2));
            assert(!copy_phys(l1desc & ~0x3ff, sizeof(data2), data2));
            for(int j = 0; j < 256; j++) {
                unsigned int l2desc = data2[i];
                if((l2desc & 3) == 0) continue; // fault
                printf("  %08x: ", baseaddr + (i * 0x100000) + (j * 0x1000));
                switch(l2desc & 3) {
                case 1:
                    printf("large base=%x TEX=%d AP0=%d AP1=%d AP2=%d AP3=%d C=%d B=%d\n", l2desc & 0xffff0000, (l2desc >> 12) & 7, (l2desc >> 4) & 3, (l2desc >> 6) & 3, (l2desc >> 8) & 3, (l2desc >> 10) & 3, (l2desc >> 3) & 1, (l2desc >> 2) & 1);
                    break;
                case 2:
                    printf("large base=%x AP0=%d AP1=%d AP2=%d AP3=%d C=%d B=%d\n", l2desc & 0xfffff000, (l2desc >> 4) & 3, (l2desc >> 6) & 3, (l2desc >> 8) & 3, (l2desc >> 10) & 3, (l2desc >> 3) & 1, (l2desc >> 2) & 1);
                    break;
                case 3:
                    printf("reserved (probably; extended small page)\n");
                    break;
                }
            }
            } break;
        case 2:
            if(l1desc & (1 << 18)) {
                printf("supersection base=%x extbase=%x NS=%d nG=%d TEX=%x AP=%x extbase2=%x XN=%x C=%x B=%x\n",
                    l1desc & 0xff000000,
                    (l1desc >> 20) & 0xf,
                    (l1desc >> 19) ? 1 : 0,
                    (l1desc >> 17) ? 1 : 0,
                    (l1desc >> 12) & 7,
                    ((l1desc >> 15) ? 4 : 0) | ((l1desc >> 10) & 3),
                    (l1desc >> 5) & 0xf,
                    (l1desc >> 4) ? 1 : 0,
                    (l1desc >> 3) ? 1 : 0,
                    (l1desc >> 2) ? 1 : 0);

            } else {
                printf("section!!\n");
            }
            break;
        case 3:
            printf("reserved\n");
            break;
        }
    }
}

int main() {
    uint32_t ttbr0, ttbr1, ttbcr;
    ttbr0 = ttbr1 = ttbcr = 0;
    printf("%x\n", get_regs(&ttbr0, &ttbr1, &ttbcr));
    printf("ttbr0=%x ttbr1=%x ttbcr=%x\n", ttbr0, ttbr1, ttbcr);

    //dump_pagetable(ttbr0, 0, 4096);
    dump_pagetable(ttbr1, 0, 16384);
}
