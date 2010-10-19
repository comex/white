#!/usr/bin/env python
from fabricate import *
sources = ['kcode.c', 'black.c', 'creep.c', 'creepasm.S']
whole = True

def build():
    GCC = ['/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2', '-arch', 'armv7', '-gstabs', '-Os', '-isysroot', '/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.1.sdk/']
    run(GCC, '-std=gnu99', '-o', 'loader_', 'loader.c')
    run('bash', '-c', 'cp loader_ loader; ldid -Sent.plist loader')
    run(GCC, '-std=gnu99', '-o', 'stuff', 'stuff.c')
    # the read_only_relocs thing is so I can do ".long records" (the read-only-ness doesn't matter here)
    run(GCC, '-dynamiclib', '-o', 'kcode.dylib', sources, '-std=gnu99', '-fwhole-program', '-combine', '-nostdlib', '-nodefaultlibs', '-lgcc', '-undefined', 'dynamic_lookup', '-read_only_relocs', 'suppress')
    # Not actually i386... obviously.
    run(GCC, '-dynamiclib', '-o', 'mem.dylib', 'mem.c', '-fwhole-program', '-combine', '-nostdinc', '-nodefaultlibs', '-lgcc', '-Wimplicit', '-Ixnu', '-Ixnu/bsd', '-Ixnu/libkern', '-Ixnu/osfmk', '-Ixnu/bsd/i386', '-Ixnu/bsd/sys', '-Ixnu/EXTERNAL_HEADERS', '-Ixnu/osfmk/libsa', '-D__i386__', '-DKERNEL', '-DKERNEL_PRIVATE', '-DBSD_KERNEL_PRIVATE', '-D__APPLE_API_PRIVATE', '-DXNU_KERNEL_PRIVATE', '-flat_namespace', '-undefined', 'dynamic_lookup', '-fno-builtin-printf')


def clean():
    autoclean()

main()
