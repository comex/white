#!/usr/bin/env python
from fabricate import *
sources = ['kcode.c', 'kasm.S']
#scratch = 0xc06ed000
#sysent = 0xc0255924
#kern = '/Users/comex/star/bs/iPad1,1_3.2.1/kern'

#scratch = 0xc076c000
#sysent = 0xc021c678
#kern = '/Users/comex/star/bs/iPhone1,x_3.1.3/kern'

#scratch = 0x8075d000
#sysent = 0x80256aac
#kern = '/Users/comex/star/bs/iPhone3,1_4.0.1/kern'

scratch = 0x806b4000
sysent = 0x80256aac
kern = '/Users/comex/star/bs/iPod3,1_4.0/kern'

def build():
    run('gcc-4.2', '-o', 'loader', 'loader.c', '-arch', 'armv7', '-isysroot', '/var/sdk', '-DSCRATCH=0x%08x' % scratch, '-DSYSENT=0x%08x' % sysent)
    run('gcc-4.2', '-std=gnu99', '-o', 'stuff', 'stuff.c', '-arch', 'armv7', '-isysroot', '/var/sdk')
    #run('ldid', '-S', 'loader')
    #run('ldid', '-S', 'stuff')

    run('python', 'nm.py', kern, '0x%08x' % scratch)

    GCC = ['arm-none-eabi-gcc', '-mthumb', '-march=armv7', '-Os']
    OBJCOPY = 'arm-none-eabi-objcopy'
    for source in sources:
        run(GCC, '-std=gnu99', '-c', source)

    run(GCC, '-o', 'kcode.elf', [source[:source.find('.')]+'.o' for source in sources], '-nostdlib', '-nodefaultlibs', '-lgcc', '-T', 'nm.ld')

    run(OBJCOPY, '-O', 'binary', 'kcode.elf', 'kcode.bin')

def clean():
    autoclean()

main()
