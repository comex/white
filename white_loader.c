#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <data/common.h>
#include <data/binary.h>
#include <data/find.h>
#include <data/cc.h>
#include <data/running_kernel.h>
#include <data/loader.h>
#include <data/link.h>
#include <ctype.h>

static struct binary kern;

static addr_t find_hack_func(const struct binary *binary) {
    return b_sym(binary, "_IOFindBSDRoot", true, true); 
}


// gigantic hack
static uint32_t lookup_sym(const struct binary *binary, const char *sym) {
    if(!strcmp(sym, "_sysent")) {
        return find_int32(b_macho_segrange(binary, "__DATA"), 0x861000, true) + 4;
    }

    // $t_XX_XX -> find "+ XX XX" in TEXT
    if(sym[0] == '$' && ((sym[1] == 't' && sym[2] == '_') || sym[1] == '_')) {
        // lol...
        char *to_find = malloc(strlen(sym)+1);
        char *p = to_find;
        while(1) {
            char c = *sym++;
            switch(c) {
            case '$': if(*sym == 't') { c = '+'; sym++; } else { c = '-'; } break;
            case '_': c = ' '; break;
            case 'X': c = '.'; break;
            }
            *p++ = c;
            if(!c) break;
        }
        uint32_t result = find_data(b_macho_segrange(binary, "__TEXT"), to_find, 0, false);
        free(to_find);
        return result;
    }
    
    // $vt_<name> -> find offset to me from the corresponding vtable 
    // ex: __ZN11OSMetaClass20getMetaClassWithNameEPK8OSSymbol
    if(!strncmp(sym, "$vt_", 4)) {
        sym += 4;
        uint32_t the_func = lookup_sym(binary, sym);
        if(!the_func) return 0;

        // find the class, and construct its vtable name
        while(*sym && !isnumber(*sym)) sym++;
        char *class;
        unsigned int len = (unsigned int) strtol(sym, &class, 10) + (class - sym);
        assert(len > 0 && len <= strlen(sym));
        char *vt_name = malloc(len + 6);
        memcpy(vt_name, "__ZTV", 5);
        memcpy(vt_name + 5, sym, len);
        vt_name[len + 5] = 0;
        
        uint32_t vtable = b_sym(binary, vt_name, true, false);
        if(!vtable) return 0;
        uint32_t loc_in_vtable = find_int32((range_t) {binary, vtable, 0x1000}, the_func, true);

        uint32_t diff = loc_in_vtable - (vtable + 8);

        fprintf(stderr, "b_lookup_sym: vtable index %d for %s = %x - %x\n", diff/4, sym, loc_in_vtable, vtable + 8);
        return diff;
    }

    return b_sym(binary, sym, true, false);
}

int main(int argc, char **argv) {
    b_init(&kern);
    (void) argc;
    argv++;
    while(1) {
        char *arg = *argv++;
        if(!arg) goto usage;
        if(arg[0] != '-' || arg[1] == '\0' || arg[2] != '\0') goto usage;
        switch(arg[1]) {
        case 'k': {
            char *kern_fn;
            if(!(kern_fn = *argv++)) goto usage;
            b_load_macho(&kern, kern_fn, false);
            break;
        }
#ifdef IMG3_SUPPORT
        case 'i': {
            uint32_t key_bits;
            prange_t data = parse_img3_file(*argv++, &key_bits);
            prange_t key = parse_hex_string(*argv++);
            prange_t iv = parse_hex_string(*argv++);
            prange_t decompressed = decrypt_and_decompress(key_bits, key, iv, data);
            b_prange_load_macho(&kern, decompressed, false);
            break;
        }
#endif
#ifdef __APPLE__
        case 'l': {
            if(!kern.valid) goto usage;
            b_prepare_running_kernel(&kern);
            uint32_t sysent = lookup_sym(&kern, "_sysent");
            if(!*argv) goto usage;
            char *to_load_fn;
            while(to_load_fn = *argv++) {
                struct binary to_load;
                b_init(&to_load);
                b_load_macho(&to_load, to_load_fn, true);
                uint32_t slide = b_allocate_from_running_kernel(&to_load);
                if(!(to_load.mach_hdr->flags & MH_PREBOUND)) {
                    b_relocate(&to_load, &kern, lookup_sym, slide);
                }
                b_inject_into_running_kernel(&to_load, sysent);
            }
            return 0;
        }
#endif
        case 'p': {
            if(!kern.valid) goto usage;
            if(!*argv) goto usage;
            char *to_load_fn, *output_fn;
            uint32_t slide = 0xf0000000;
            while(to_load_fn = *argv++) {
                if(!(output_fn = *argv++)) goto usage;
                struct binary to_load;
                b_init(&to_load);
                b_load_macho(&to_load, to_load_fn, true);
                if(!(to_load.mach_hdr->flags & MH_PREBOUND)) {
                    b_relocate(&to_load, &kern, lookup_sym, slide);
                    slide += 0x10000;
                }
                to_load.mach_hdr->flags |= MH_PREBOUND;
                b_macho_store(&to_load, output_fn);
            }
            return 0;
        }
        case 'q': {
            if(!kern.valid) goto usage;
            char *out_kern = *argv++;
            if(!out_kern) goto usage;
            b_macho_store(&kern, out_kern);

            int fd = open(out_kern, O_RDWR);
            if(fd == -1) {
                edie("couldn't re-open output kc"); 
            }

            if(!*argv) goto usage;
            char *to_load_fn;
            while(to_load_fn = *argv++) {
                struct binary to_load;
                b_init(&to_load);
                b_load_macho(&to_load, to_load_fn, true);
                if(!(to_load.mach_hdr->flags & MH_PREBOUND)) {
                    b_relocate(&to_load, &kern, lookup_sym, b_allocate_from_macho_fd(fd));
                }
                b_inject_into_macho_fd(&to_load, fd, find_hack_func);
            }
            close(fd);

            return 0;
        }
#ifdef __APPLE__
        case 'u': {
            char *baseaddr_hex;
            if(!(baseaddr_hex = *argv++)) goto usage;
            unload_from_running_kernel(parse_hex_uint32(baseaddr_hex));
            return 0;
        }
#endif
        }
    }

    usage:
    printf("Usage: loader -k kern "
#ifdef __APPLE__
                                 "-l kcode.dylib                load\n"
           "                      "
#endif
                                 "-p kcode.dylib out.dylib      prelink\n"
           "                      -q out_kern kcode.dylib       insert into kc\n"
#ifdef __APPLE__
           "              -u f0000000                           unload\n"
#endif
           );
}

