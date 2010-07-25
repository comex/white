SECTIONS {
    . = 0xc06ed000;
    .init : { *(.init) }
    /DISCARD/ : { *(.comment); *(.ARM.attributes) }
}
