import mmap, os, struct, re
# ripped from config.py

class macho:
    def __init__(self, name, stuff):
        self.name = name
        self.stuff = stuff
        xbase = stuff.tell()
        magic, cputype, cpusubtype, \
        filetype, filetype, ncmds, sizeofcmds, \
        flags = struct.unpack('IHHIIIII', stuff.read(0x1c))
        self.sects = sects = []
        self.nsyms = None
        self.syms = None
        while True:
            xoff = stuff.tell()
            if xoff >= xbase + sizeofcmds: break
            cmd, clen = struct.unpack('II', stuff.read(8))
            if cmd == 1: # LC_SEGMENT
                name = stuff.read(16).rstrip('\0')
                vmaddr, vmsize, foff, fsiz = struct.unpack('IIII', stuff.read(16))
                sects.append((vmaddr, foff, fsiz))
            elif cmd == 2: # LC_SYMTAB
                self.symoff, self.nsyms, self.stroff, self.strsize = struct.unpack('IIII', stuff.read(16))
            elif cmd == 11: # LC_DYSYMTAB
                self.ilocalsym, self.nlocalsym = struct.unpack('II', stuff.read(8))
                self.iextdefsym, self.nextdefsym = struct.unpack('II', stuff.read(8))
                self.iundefsym, self.nundefsym = struct.unpack('II', stuff.read(8))
            stuff.seek(xoff + clen)

    def get_syms(self):
        syms = {}
        for off in xrange(self.symoff, self.symoff + 12*self.nsyms, 12):
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack('IBBhI', self.stuff[off:off+12])
            if n_value == 0: continue
            n_strx += self.stroff
            psym = self.stuff[n_strx:self.stuff.find('\0', n_strx)]
            if n_desc & 8:
                # thumb
                n_value |= 1
            yield psym, n_value

filename = '/Users/comex/star/bs/iPad1,1_3.2.1/kern'
fp = open(filename, 'rb')
stuff = mmap.mmap(fp.fileno(), os.path.getsize(filename), prot=mmap.PROT_READ)
m = macho(filename, stuff)

out = open('nm.ld', 'w')

out.write(open('base.ld').read())

for a, b in m.get_syms():
    if a.startswith('_') and re.match('^[a-zA-Z0-9_@\$]{2,}$', a):
        print >> out, '%s = 0x%08x;' % (a[1:], b)
