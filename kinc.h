#include <stdint.h>
// This is stupid and generates wasteful code, but is necessary.  The BL instruction generated otherwise treats it as ARM and ignores the least-significant bit.
// A proper solution is apparently making the generated symbol have the right attribute, but I can't do that without... manually generating an ELF file?
#define LC __attribute__((long_call))

LC void IOLog(const char *msg, ...) __attribute__((format (printf, 1, 2)));
