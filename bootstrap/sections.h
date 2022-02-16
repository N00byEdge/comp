#define MAX_SECTION_BYTES 0x100000

#define SECTION_TEXT 0
#define SECTION_DATA 1
#define SECTION_RODATA 2
#define SECTION_BSS 3
#define LAST_SECTION SECTION_BSS

u64 section_base_addr[4] = {};
u64 current_section_bytes[4] = {};
u8 current_section_buf[3][MAX_SECTION_BYTES] = {};
