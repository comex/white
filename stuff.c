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
    for(int i = 0; i < 0x7fff; i++) {
        if(buf[i].pc) {
            printf("%.5d %08x", i, buf[i].pc);
            for(int r = 0; r < 12; r++)  {
                if(i == 0 || buf[i].r[r] != buf[i-1].r[r]) {
                    printf(" R%d=%08x", r, buf[i].r[r]);
                }
            }
            if(i == 0 || buf[i].sp != buf[i-1].sp) printf(" SP=%08x", buf[i].sp);
            if(i == 0 || buf[i].lr != buf[i-1].lr) printf(" LR=%08x", buf[i].lr);
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

struct cpuid_regs {
    uint32_t id_pfr0;
    uint32_t id_pfr1;
    uint32_t id_dfr0;
    uint32_t id_afr0;
    uint32_t id_mmfr0;
    uint32_t id_mmfr1;
    uint32_t id_mmfr2;
    uint32_t id_mmfr3;
    uint32_t id_isar0;
    uint32_t id_isar1;
    uint32_t id_isar2;
    uint32_t id_isar3;
    uint32_t id_isar4;
    uint32_t id_isar5;
};

static inline uint32_t bits(uint32_t a, uint32_t hi, uint32_t lo) {
    return (a >> lo) & ((1 << (hi - lo + 1)) - 1);
}

static void do_cpuid_regs() {
    struct cpuid_regs regs;
    assert(!syscall(8, 32, &regs));
    uint32_t a;

#define f(h, l, labels...) { uint32_t b = bits(a, h, l); char *labels_[] = {labels}; puts(b >= (sizeof(labels_)/sizeof(*labels_)) ? "RESERVED" : labels_[b]); }
#define sg(h, l, c, label) g(bits(a, h, l), c, label)
#define g(b, c, label) printf("%s %ssupported\n", label, (b) >= (c) ? "" : "NOT ")
#define s(h, l, label) sg(h, l, 1, label)
#define R4 "RESERVED", "RESERVED", "RESERVED", "RESERVED"
#define R13 R4, R4, R4, "RESERVED"
#define R14 R4, R4, R4, "RESERVED", "RESERVED"

    a = regs.id_pfr0;
    s(15, 12, "ThumbEE");
    f(11, 8, "Jazelle NOT supported", "Jazelle supported without clearing of JOSCR.CV", "Jazelle supported with clearing of JOSCR.CV");
    f(7, 4, "Thumb NOT supported", "Thumb supported", "RESERVED", "Thumb and Thumb-2 supported");
    s(3, 0, "ARM");
    printf("\n");

    a = regs.id_pfr1;
    f(11, 8, "Two-stack NOT supported", "RESERVED", "Two-stack supported");
    f(7, 4, "Security Extensions NOT supported", "Security Extensions supported", "Security Extensions + NSACR.RFR supported");
    s(3, 0, "Standard programmer's model");
    printf("\n");

    a = regs.id_dfr0;
    s(23, 20, "M profile Debug");
    s(19, 16, "ARM trace memory-mapped");
    s(15, 12, "ARM trace coprocessor-based");
    s(11, 8, "A/R profile debug memory-mapped");
    s(7, 4, "Secure debug coprocessor");
    s(3, 0, "A/R profile debug coprocessor");
    printf("\n");

    a = regs.id_mmfr0;
    f(31, 28, "Innermost shareability = Non-cacheable", "Innermost shareability with hardware coherency", R13, "Shareability ignored");
    s(27, 24, "FCSE");
    f(23, 20, "No Auxiliary registers supported", "Auxiliary Control Register supported", "Auxiliary Control Register and Auxiliary Fault Status Registers supported");
    f(19, 16, "TCMs NOT supported", "TCMs implementation defined", "TCM supported only (ARMv6)", "TCM and DMA supported (ARMv6)");
    f(15, 12, "One level of shareability implemented", "Two levels of shareability implemented");
    f(11, 8, "Outermost shareability = Non-cacheable", "Outermost shareability with hardware coherency", R13, "Shareability ignored");
    f(7, 4, "PMSA NOT supported", "PMSA implementation defined", "PMSAv6 supported", "PMSAv7 supported");
    f(3, 0, "VMSA NOT supported", "VMSA implementation defined", "VMSAv6 supported", "VMSAv7 supported");
    printf("\n");

    a = regs.id_mmfr1;
    f(31, 28, "No branch predictor", "Branch predictor requires flushing in many cases", "Branch predictor requires flushing in few cases", "Branch predictor never requires flushing");
    f(27, 24, "L1 cache test and clean NOT supported", "L1 cache test and clean supported", "L1 cache test, clean, and invalidate supported");
    f(23, 20, "L1 unified cache maintenance NOT supported", "L1 unified cache invalidate supported", "L1 unified cache invalidate and clean supported");
    f(19, 16, "L1 Harvard cache maintenance NOT supported", "L1 Harvard instruction cache invalidate supported", "L1 Harvard data and instruction cache invalidate supported", "L1 Harvard data and instruction cache invalidate and clean supported");
    f(15, 12, "L1 unified cache line maintenance by set/way NOT supported", "L1 unified cache line clean by set/way supported", "L1 unified cache line clean and clean+invalidate by set/way supported", "L1 unified cache line clean, clean+invalidate, and invalidate by set/way supported");
    f(11, 8, "L1 Harvard cache line maintenance by set/way NOT supported", "L1 Harvard data cache line clean and clean+invalidate by set/way supported", "L1 Harvard data cache line clean, clean+invalidate, and invalidate by set/way supported", "L1 Harvard data cache line clean, clean+invalidate, and invalidate, and instruction cache line invalidate, by set/way supported");
    f(7, 4, "L1 unified cache line maintenance by MVA NOT supported", "L1 unified cache line clean, invalidate, and clean+invalidate by MVA supported", "L1 unified cache line clean, invalidate, and clean+invalidate, and branch predictor invalidate, by MVA supported");
    f(3, 0, "L1 Harvard cache line maintenance by MVA NOT supported", "L1 Harvard data cache line clean, invalidate, and clean+invalidate, and instruction cache line invalidate, by MVA supported", "L1 Harvard data cache line clean, invalidate, and clean+invalidate, instruction cache line invalidate, and branch predictor invalidate, by MVA supported");
    printf("\n");

    a = regs.id_mmfr2;
    s(31, 28, "VMSAv7 access flag");
    s(27, 24, "WFI stalling");
    f(23, 20, "CP15 memory barrier operations NOT supported", "CP15 DSB supported", "CP15 DSB, ISB, and DMB supported");
    f(19, 16, "Unified TLB maintenance NOT supported", "Unified TLB invalidate all and by MVA supported", "Unified TLB invalidate all, by MVA, and by ASID supported", "Unified TLB invalidate all, by MVA, by ASID, and by MVA All ASID supported");
    f(15, 12, "Harvard TLB maintenance NOT supported", "Harvard TLB maintenance invalidate all and by MVA supported", "Harvard TLB maintenance invalidate all, by MVA, and by ASID supported");
    s(11, 8, "L1 Harvard cache maintenance by VA range");
    s(7, 4, "L1 Harvard cache prefetch by VA");
    s(3, 0, "L1 Harvard cache foreground prefetch by VA");
    printf("\n");

    a = regs.id_mmfr3;
    f(31, 28, "Supersections supported", R14, "Supersections NOT supported");
    s(23, 20, "Coherent walk");
    f(15, 12, "Cache, TLB, and branch predictor maintenance not broadcast", "Cache and branch predictor maintenance broadcast", "Cache, TLB, and branch predictor maintenance broadcast");
    f(11, 8, "Branch predictor maintenance NOT supported", "Branch predictor invalidate all supported", "Branch predictor invalidate all and by MVA supported");
    s(7, 4, "Cache maintain by set/way");
    s(3, 0, "Cache maintain by MVA");
    printf("\n");

    a = regs.id_isar0;
    s(27, 24, "SDIV, UDIV");
    s(23, 20, "BKPT");
    sg(19, 16, 1, "Generic CDP, LDC, MCR, MRC, STC");
    sg(19, 16, 2, "Generic CDP2, LDC2, MCR2, MRC2, STC2");
    sg(19, 16, 3, "Generic MCRR, MRRC");
    sg(19, 16, 4, "Generic MCRR2, MRRC2");
    s(15, 12, "CBNZ, CBZ");
    s(11, 8, "BFC, BFI, SBFX, UBFX");
    s(7, 4, "CLZ");
    s(3, 0, "SWP, SWPB");
    printf("\n");

    a = regs.id_isar1;
    s(31, 28, "Jazelle");
    f(27, 24, "Interworking NOT supported", "BX and T bit interworking supported", "BX, BLX, PC load, and T bit interworking supported", "BX, BLX, PC load, T bit, and ARM data processing interworking supported");
    s(23, 20, "MOVT, other long immediates");
    s(19, 16, "IT");
    sg(15, 12, 1, "SXTB, SXTH, UXTB, UXTH");
    sg(15, 12, 2, "SXTB16, SXTAB, SXTAB16, SXTAH, UXTB16, UXTAB, UXTAB16, UXTAG");
    s(11, 8, "SRS, RFE");
    s(7, 4, "LDM exception handling");
    s(3, 0, "SETEND");
    printf("\n");
    
    a = regs.id_isar2;
    sg(31, 28, 1, "REV, REV16, REVSH");
    sg(31, 28, 2, "RBIT");
    s(27, 24, "MRS, MSR, exception return SUBS PC, LR");
    sg(23, 20, 1, "UMLL, UMLAL");
    sg(23, 20, 2, "UMAAL");
    sg(19, 16, 1, "SMULL, SMLAL");
    sg(19, 16, 2, "SMLABB, SMLABT, SMLALBB, SMLALBT, SMLALTB, SMLALTT, SMLATB, SMLATT, SMLAWB, SMLAWT, SMULBB, SMULBT, SMULTB, SMULTT, SMULWB, SMULWT");
    sg(19, 16, 3, "SMLAD, SMLADX, SMLALD, SMLALDX, SMLSD, SMLSDX, SMLSLD, SMLSLDX, SMMLA, SMMLAR, SMMLS, SMMLSR, SMMUL, SMMULR, SMUAD, SMUADX, SMUSD, SMUSDX");
    sg(15, 12, 1, "MLA");
    sg(15, 12, 2, "MLS");
    f(11, 8, "LDM/STM not interruptible", "LDM/STM restartable", "LDM/STM continuable");
    sg(7, 4, 1, "PLD");
    sg(7, 4, 3, "PLI");
    sg(7, 4, 4, "PLDW");
    s(3, 0, "LDRD, STRD");
    printf("\n");

    a = regs.id_isar3;
    s(31, 28, "ENTERX, LEAVEX");
    s(27, 24, "True NOP");
    s(23, 20, "Thumb low-to-low MOV");
    s(19, 16, "TBB, TBH");
    uint32_t synch = (bits(a, 15, 12) << 4) | bits(regs.id_isar4, 23, 20);
    g(synch, 0x10000, "LDREX, STREX");
    g(synch, 0x10011, "CLREX, LDREXB, LDREXH, STREXB, STREXH");
    g(synch, 0x100000, "CLREX, LDREXB, LDREXH, STREXB, STREXH");
    s(11, 8, "SVC");
    sg(7, 4, 1, "SSAT, USAT, Q bit");
    sg(7, 4, 2, "Misc SIMD instructions, GE bits");
    s(3, 0, "QADD, QDADD, QDSUB, QSUB, Q bit");
    printf("\n");

    a = regs.id_isar4;
    s(31, 28, "SWP, SWPB (non-locking)");
    s(27, 24, "M profile CPS, MRS, MSR");
    s(19, 16, "DMB, DSB, ISB");
    s(15, 12, "SMC");
    s(11, 8, "Writeback (other than LDM, STM, PUSH, POP, SRS, RFE)");
    sg(7, 4, 1, "Shifts of LSL 0-3");
    sg(7, 4, 3, "Constant shifts");
    sg(7, 4, 4, "Register-controlled shifts shifts");
    sg(3, 0, 1, "LDRBT, LDRT, STRBT, STRT");
    sg(3, 0, 2, "LDRHT, LDRSBT, LDRSHT, STRHT");

#undef f
#undef sg
#undef g
#undef s
#undef R4
#undef R13
#undef R14
}

static uint32_t parse_hex(const char *optarg) {
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
    while((c = getopt_long(argc, argv, "mMri012sl:w:L:W:uh:v:w:c:CPUdt:a:Ao:p:f", options, &idx)) != -1) {
        did_something = true;
        switch(c) {
        case 'r':
            assert(!syscall(8, 0, &regs));
            printf("cpsr=%x ttbr0=%x ttbr1=%x ttbcr=%x contextidr=%x sctlr=%x scr=%x\n", regs.cpsr, regs.ttbr0, regs.ttbr1, regs.ttbcr, regs.contextidr, regs.sctlr, regs.scr);
            printf("dbgdidr=%x dbgdrar=%x dbgdsar=%x id_dfr0=%x dbgdscr=%x\n", regs.dbgdidr, regs.dbgdrar, regs.dbgdsar, regs.id_dfr0, regs.dbgdscr);
            printf("tpidrprw=%x dacr=%x\n", regs.tpidrprw, regs.dacr);
            break;
        case 'i':
            do_cpuid_regs();
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
           "    -i:                    print CPUID regs\n"
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
