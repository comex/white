SECTIONS {
    . = 0xc076c000;
    .init : { *(.init) }
    /DISCARD/ : { *(.comment); *(.ARM.attributes) }
}
