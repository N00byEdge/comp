u64 write_generic(u64 value, int section, int len) {
    u64 section_offset = current_section_bytes[section];

    if(section != SECTION_BSS) {
        *(u64*)&current_section_buf[section][section_offset] = value;
    }

    current_section_bytes[section] += len;

    return section_base_addr[section] + section_offset;
}

u64 write8(u8 value, int section) {
    return write_generic(value, section, 1);
}

u64 write16(u16 value, int section) {
    return write_generic(value, section, 2);
}

u64 write32(u32 value, int section) {
    return write_generic(value, section, 4);
}

u64 write64(u64 value, int section) {
    return write_generic(value, section, 8);
}

int current_reading_file = 0;

char buffer_chr;
char next_chr;

int has_buffer = 0;
int has_next_buffer = 0;

int switch_file(char const *filename) {
    assert(!has_buffer);
    
    int f = current_reading_file;
    current_reading_file = open(filename, O_RDONLY);
    if(current_reading_file < 0) {
        printf("Cannot open imported filename '%s': %d!", filename, current_reading_file);
        exit(1);
    }
    return f;
}

void restore_file(int old_value) {
    current_reading_file = old_value;
    if(has_buffer) {
        assert(buffer_chr == 0);
        has_buffer = 0;
    }
}

u8 peek() {
    if(!has_buffer) {
        if(!has_next_buffer) {
            if(read(current_reading_file, &buffer_chr, 1) != 1)
                buffer_chr = 0;
        } else {
            buffer_chr = next_chr;
            has_next_buffer = 0;
            has_buffer = 1;
        }
        
        has_buffer = 1;
    }
    //printf("peek() = '%c'\n", buffer_chr);
    return buffer_chr;
}

u8 peek_next() {
    peek();
    if(!has_next_buffer) {
        if(read(current_reading_file, &next_chr, 1) != 1)
            next_chr = 0;
        has_next_buffer = 1;
    }
    //printf("peek_next() = '%c'\n", next_chr);
    return next_chr;
}

u8 consume() {
    u8 result = peek();
    has_buffer = 0;
    printf("consume() = '%c'\n", result);
    return result;
}
