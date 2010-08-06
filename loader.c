#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "elf.h"

struct proc;
// copied from xnu

typedef int32_t sy_call_t(struct proc *, void *, int *);
typedef void    sy_munge_t(const void *, void *);

struct sysent {     /* system call table */
    int16_t     sy_narg;    /* number of args */
    int8_t      sy_resv;    /* reserved  */
    int8_t      sy_flags;   /* flags */
    sy_call_t   *sy_call;   /* implementing function */
    sy_munge_t  *sy_arg_munge32; /* system call arguments munger for 32-bit process */
    sy_munge_t  *sy_arg_munge64; /* system call arguments munger for 64-bit process */
    int32_t     sy_return_type; /* system call return types */
    uint16_t    sy_arg_bytes;   /* Total size of arguments in bytes for
                     * 32-bit system calls
                     */
};
#define _SYSCALL_RET_INT_T      1   

// end copied

// search for 01 00 00 00 0c 00 00 00

struct sysent my_sysent = { 1, 0, 0, NULL, NULL, NULL, _SYSCALL_RET_INT_T, 5 * sizeof(uint32_t) };

void xread(int fd, void *buf, size_t nbyte) {
    errno = 0;
    int ret = read(fd, buf, nbyte);
    if(errno) perror("xread");
    assert(ret == nbyte);
}


int main() {
    assert(sizeof(struct sysent) == 0x18);
    int k = open("/dev/kmem", O_WRONLY);
    assert(k > 0);

    Elf32_Ehdr ehdr;
    Elf32_Shdr shdr;
    int fd = open("kcode.elf", O_RDONLY);
    assert(fd > 0);
    xread(fd, &ehdr, sizeof(ehdr));
    assert(ehdr.e_shentsize == sizeof(shdr));
    lseek(fd, ehdr.e_shoff, SEEK_SET);
    Elf32_Half shnum = ehdr.e_shnum;
    while(shnum--) {
        xread(fd, &shdr, sizeof(shdr));
        if(shdr.sh_type == SHT_PROGBITS) {
            if(!my_sysent.sy_call) my_sysent.sy_call = (void *) (shdr.sh_addr | 1);
            void *buf = malloc(shdr.sh_size);
            assert(pread(fd, buf, shdr.sh_size, shdr.sh_offset) == shdr.sh_size);
            assert(pwrite(k, buf, shdr.sh_size, shdr.sh_addr) == shdr.sh_size);
            free(buf);
        } else if(shdr.sh_type == SHT_NOBITS) {
            void *buf = calloc(1, shdr.sh_size);
            assert(pwrite(k, buf, shdr.sh_size, shdr.sh_addr) == shdr.sh_size);
            free(buf);
        }
    }

    assert(pwrite(k, &my_sysent, sizeof(struct sysent), SYSENT + 8 * sizeof(struct sysent)) == sizeof(struct sysent));
    close(k);
    
    return 0;
}
