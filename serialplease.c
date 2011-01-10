__attribute__((long_call)) extern int switch_to_serial_console() asm("$t_02_4a_00_23_10_68_13_60_70_47");
__attribute__((long_call)) extern int serial_init();
// may not be necessary
extern char conslog[] asm("$_05_4b_1b_68_00_2b_f5_d1_20_46_XX_XX_XX_XX_f1_e7");

__attribute__((long_call)) extern void printf(const char *msg, ...);

__attribute__((constructor))
static void init() {
    switch_to_serial_console();
    int *disableConsoleOutput = *((int **) (conslog + 0x18));
    printf("disableConsoleOutput address:%p old value: %d\n", disableConsoleOutput, *disableConsoleOutput);
    *disableConsoleOutput = 0;
    serial_init();
    printf("You should get this on serial.\n");
}
