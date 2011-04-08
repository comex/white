__attribute__((long_call)) extern int switch_to_serial_console() asm("$t_02_4a_00_23_10_68_13_60_70_47");
__attribute__((long_call)) extern int serial_init();
// may not be necessary
__attribute__((long_call)) extern void conslog_putc(char);
__attribute__((long_call)) extern void printf(const char *msg, ...);

__attribute__((constructor))
static void init() {
    switch_to_serial_console();
    int *disableConsoleOutput = *((int **) (((char *) conslog_putc) - 1 + 0x3c));
    printf("disableConsoleOutput address:%p old value: %d\n", disableConsoleOutput, *disableConsoleOutput);
    *disableConsoleOutput = 0;
    serial_init();
    conslog_putc('h'); conslog_putc('i'); conslog_putc('\n');
    printf("You should get this on serial.\n");
}
