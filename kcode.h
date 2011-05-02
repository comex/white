#define unused __attribute__((unused))
// black.c
void *hook(void *addr, void *replacement, int mode, void *tag);
void *unhook(void *stub);
// creep.c
int creep_go(void *start, int size);
void creep_get_records(user_addr_t buf, uint32_t bufsize);
void creep_stop();
// protoss.c
int protoss_go();
int protoss_go_watch(uint32_t address, uint32_t mask);
int protoss_get_records(int type, user_addr_t buf, uint32_t bufsize);
void protoss_stop();
void protoss_unload();
uint32_t protoss_dump_debug_reg(uint32_t reg);
int protoss_write_debug_reg(uint32_t reg, uint32_t val);
// failsafe.S
int run_failsafe(void *result, void *func, uint32_t arg1, uint32_t arg2);
