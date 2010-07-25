#!/usr/bin/env python
from fabricate import *
sources = ['kcode.c', 'kasm.S']
def build():
    run('gcc-4.2', '-o', 'loader', 'loader.c', '-arch', 'armv6', '-isysroot', '/var/sdk')
    #run('ldid', '-S', 'loader')

    run('python', 'nm.py')

    GCC = ['arm-none-eabi-gcc', '-mthumb', '-march=armv7', '-Os']
    OBJCOPY = 'arm-none-eabi-objcopy'
    for source in sources:
        run(GCC, '-c', source)

    run(GCC, '-o', 'kcode.elf', [source[:source.find('.')]+'.o' for source in sources], '-nostdlib', '-nodefaultlibs', '-lgcc', '-T', 'nm.ld')

def clean():
    autoclean()

main()
