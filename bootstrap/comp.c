#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

#define i8 int8_t
#define i16 int16_t
#define i32 int32_t
#define i64 int64_t

#define TODO assert(!"TODO");

#include "sections.h"
#include "io.h"
#include "trie.h"

// Nop sequences
// bytes  sequence                encoding
// 
// 1      90H                            NOP
// 2      66 90H                         66 NOP
// 3      0F 1F 00H                      NOP DWORD ptr [EAX]
// 4      0F 1F 40 00H                   NOP DWORD ptr [EAX + 00H]
// 5      0F 1F 44 00 00H                NOP DWORD ptr [EAX + EAX*1 + 00H]
// 6      66 0F 1F 44 00 00H             NOP DWORD ptr [AX + AX*1 + 00H]
// 7      0F 1F 80 00 00 00 00H          NOP DWORD ptr [EAX + 00000000H]
// 8      0F 1F 84 00 00 00 00 00H       NOP DWORD ptr [AX + AX*1 + 00000000H]
// 9      66 0F 1F 84 00 00 00 00 00H    NOP DWORD ptr [AX + AX*1 + 00000000H]

u64 instr_load_imm(unsigned regnum, u64 value) {
    assert(regnum < 0x10);

    if(regnum >= 8) {
        regnum -= 8;
        write8(0x49, SECTION_TEXT);
    } else {
        write8(0x48, SECTION_TEXT);
    }

    write8(0xB8 | regnum, SECTION_TEXT);
    write64(value, SECTION_TEXT);

    return 0;
}

void skip_whitespace() {
    int is_comment = 0;
    while(1) {
        if(is_comment) {
            if(consume() == '\n')
                is_comment = 0;
        } else {
            switch(peek()) {
                case '\n':
                    // Track line numbers?
                case ' ':
                case '\t':
                case '\r':
                    consume();
                    continue;

                case '/':
                    if(peek_next() == '/') {
                        consume();
                        consume();
                        is_comment = 1;
                        continue;
                    }
                    return;

                default:
                    return;
            }
        }
    }
}

int builtin_root;
int root_root;

void parse_file();

char filename_buf[0x100] = {};

void read_filename() {
    skip_whitespace();
    char c, *curr = filename_buf;

    while(1) {
        switch(c = consume()) {
            case '"':
                *curr++ = 0;
                return;

            default:
                *curr++ = c;
                continue;
        }
    }
}

u64 from_hex(char val) {
    switch(val) {
    default: TODO
    case '0'...'9':
        return val - '0' + 0x0;
    case 'A'...'F':
        return val - 'A' + 0xA;
    case 'a'...'f':
        return val - 'f' + 0xa;
    }
}

u64 read_string_literal() {
    assert(peek() == '"');
    consume();
    u64 result = current_section_bytes[SECTION_RODATA] + section_base_addr[SECTION_RODATA];
    while(1) {
        char chr = consume();
        switch(chr) {
        default:
            write_generic((unsigned char)chr, SECTION_RODATA, 1);
            break;
        case '\\':
            chr = consume();
            switch(chr) {
            default:
                write_generic((unsigned char)chr, SECTION_RODATA, 1);
                break;
            case 'n':
                write_generic('\n', SECTION_RODATA, 1);
                break;
            case 't':
                write_generic('\t', SECTION_RODATA, 1);
                break;
            case 'r':
                write_generic('\r', SECTION_RODATA, 1);
                break;
            case 'x':
                chr = from_hex(consume()) << 4;
                chr |= from_hex(consume());
                write_generic(chr, SECTION_RODATA, 1);
                break;
            }
            break;
        case '"':
            write_generic(0, SECTION_RODATA, 1);
            return result;
        }
    }
}

int is_starting_ident_chr() {
    switch(peek()) {
        case 'a'...'z':
        case 'A'...'Z':
        case '@':
        case '_':
            return 1;

        default:
            return 0;
    }
}

int is_ident_chr() {
    switch(peek()) {
        case 'a'...'z':
        case 'A'...'Z':
        case '0'...'9':
        case '@':
        case '_':
            return 1;

        default:
            return 0;
    }
}

struct trie_node_value *read_node_name_in_root(int current) {
    char buf[2];
    buf[1] = 0;

    skip_whitespace();

    if(!is_starting_ident_chr()) {
        assert(!"Not an identifier!");
    }

    while(1) {
        if(is_ident_chr()) {
            buf[0] = consume();
            current = lookup_node(buf, current);
            if(current == 0) return 0;
        } else {
            return get_or_create_node_value("", current);
        }
    }
}

struct trie_node_value *read_node_name() {
    return read_node_name_in_root(current_file_root);
}

u64 read_int_literal_hex() {
    u64 result = 0;
    while(1) {
        switch(peek()) {
            case '0'...'9':
                result <<= 4;
                result += consume() - '0';
                continue;
            case 'a'...'f':
                result <<= 4;
                result += 0xa + consume() - 'a';
                continue;
            case 'A'...'F':
                result <<= 4;
                result += 0xA + consume() - 'A';
                continue;
            default:
                return result;
        }
    }
}

u64 read_int_literal_decimal() {
    u64 result = 0;
    while(1) {
        switch(peek()) {
            case '0'...'9':
                result *= 10;
                result += consume() - '0';
                continue;
            default:
                return result;
        }
    }
}

u64 read_int_literal() {
    if(peek() == '0') {
        consume();
        if(peek() == 'x') {
            consume();
            return read_int_literal_hex();
        }
    }
    return read_int_literal_decimal();
}

u64 read_char_literal() {
    u64 result;
    if(peek() == '\\') {
        consume();
        switch(peek()) {
        default:
            result = consume();
            break;
        case 'x': consume();
            result = read_int_literal_hex();
            break;
        case 'n': consume();
            result = '\n';
            break;
        case 't': consume();
            result = '\t';
            break;
        case 'r': consume();
            result = '\r';
            break;
        }
    } else {
        result = consume();
    }
    assert(consume() == '\'');
    return result;
}

void collapse_var_name_eval(struct trie_node_value **var_name_node) {
    while(var_name_node[0]->type == TRIE_TYPE_FILE_DUP) {
        skip_whitespace();

        // This is hopefully something in the form of like
        // my_module.thing;
        assert(consume() == '.');

        // Just read the node and use that one instead
        var_name_node[0] = read_node_name_in_root(var_name_node[0]->file_scope_trie);
        assert(var_name_node[0]);
    }
}

#define PARSE_EVERYTHING 0

u64 eval_comptime_with_precedence(int precedence) {
    skip_whitespace();

    u64 lhs;
    struct trie_node_value *tmp;

    // Evaluate the lhs, we don't care much about the precedence here
    switch(peek()) {
        case '0'...'9':
            lhs = read_int_literal();
            break;

        case '\'': consume();
            // Char literal
            lhs = read_char_literal();
            break;

        case '(': consume();
            // Parens in expression 
            lhs = eval_comptime_with_precedence(PARSE_EVERYTHING);
            assert(consume() == ')');
            break;

        case ')':
            printf("Error: Expected primary expression before ')'!\n");
            exit(1);
            break;

        case '-': consume();
            // Unary minus
            // Assoc: Left-to-Right
            // Prec: 2
            lhs = -eval_comptime_with_precedence(2);
            break;

        case '~': consume();
            // Unary bitwise not
            // Assoc: Left-to-Right
            // Prec: 2
            lhs = ~eval_comptime_with_precedence(2);
            break;

        case 'a' ... 'z':
        case 'A' ... 'Z':
        case '@':
        case '_':
            tmp = read_node_name(0);
            if(!tmp) {
                assert(!"Unknown identifier!");
            }
            collapse_var_name_eval(&tmp);
            switch(tmp->type) {
                default:
                    printf("Identifier type: %d\n", tmp->type);
                    assert(!"Bad identifier type!");

                case TRIE_TYPE_BUILTIN_FUNCTION:
                    skip_whitespace();
                    assert(consume() == '(');
                    lhs = ((u64 (*)(int))tmp->value)(0);
                    break;

                case TRIE_TYPE_COMPTIME:
                    lhs = tmp->value;
                    break;

                case TRIE_TYPE_FUNCTION_OFFSET:
                    lhs = tmp->value + section_base_addr[SECTION_TEXT];
                    break;
            }
            break;

        default:
            printf("eval_comptime_with_precedence: %c\n", peek());
            TODO
    }

    // When we're checking precedence, it's very important to keep the associativity in mind.
    // If something is Left-to-Right associative, equal precedence means we can keep iterating
    // while Right-to-Left means we need to recurse

    while(1) {
        skip_whitespace();
        // Check if we have anything else in the expression
        switch(peek()) {
            case '.':
            case ')':
            case ':':
            case ']':
            case ';':
            case ',':
                // Nothing else left to evaluate at this level
                return lhs;

            case '+': consume();
                // Binary addition
                // Assoc: Left-to-Right
                // Prec: 4
                if(4 >= precedence) {
                    lhs += eval_comptime_with_precedence(4);
                }
                else {
                    return lhs;
                }
                break;

            case '-': consume();
                // Binary subtraction
                // Assoc: Left-to-Right
                // Prec: 4
                if(4 >= precedence) {
                    lhs -= eval_comptime_with_precedence(4);
                }
                else {
                    return lhs;
                }
                break;

            case '*':
                // Binary multiplication
                // Assoc: Left-to-Right
                // Prec: 3
                if(3 >= precedence) {
                    consume();
                    lhs *= eval_comptime_with_precedence(3);
                }
                else {
                    return lhs;
                }
                break;

            case '&':
                // Binary bitwise and
                // Assoc: Left-to-Right
                // Prec: 8
                if(8 >= precedence) {
                    consume();
                    lhs &= eval_comptime_with_precedence(8);
                }
                else {
                    return lhs;
                }
                break;

            case '^':
                // Binary bitwise xor
                // Assoc: Left-to-Right
                // Prec: 9
                if(9 >= precedence) {
                    consume();
                    lhs ^= eval_comptime_with_precedence(9);
                }
                else {
                    return lhs;
                }
                break;

            case '|':
                // Binary bitwise or
                // Assoc: Left-to-Right
                // Prec: 10
                if(10 >= precedence) {
                    consume();
                    lhs |= eval_comptime_with_precedence(10);
                }
                else {
                    return lhs;
                }
                break;

            case '<': consume();
                assert(consume() == '<');
                // Bit shift left
                // Assoc: Left-to-Right
                // Prec: 5
                if(5 >= precedence) {
                    consume();
                    lhs <<= eval_comptime_with_precedence(5);
                }
                else TODO
                break;

            case '>': consume();
                assert(consume() == '>');
                // Bit shift right
                // Assoc: Left-to-Right
                // Prec: 5
                if(5 >= precedence) {
                    consume();
                    lhs >>= eval_comptime_with_precedence(5);
                }
                else TODO
                break;

            default:
                printf("eval_comptime_with_precedence(): peek(): %02x (%c)\n", peek(), peek());
                TODO
        }
    }
}

u64 eval_compiletime() {
    return eval_comptime_with_precedence(PARSE_EVERYTHING);
}

#define REG_IDX_RAX 0
#define REG_IDX_RCX 1
#define REG_IDX_RDX 2
#define REG_IDX_RBX 3
#define REG_IDX_RSP 4
#define REG_IDX_RBP 5
#define REG_IDX_RSI 6
#define REG_IDX_RDI 7
#define REG_IDX_R8 8
#define REG_IDX_R9 9
#define REG_IDX_R10 10
#define REG_IDX_R11 11
#define REG_IDX_R12 12
#define REG_IDX_R13 13
#define REG_IDX_R14 14
#define REG_IDX_R15 15

u32 arg_regs[] = {
    REG_IDX_RDI,
    REG_IDX_RSI,
    REG_IDX_RDX,
    REG_IDX_RCX,
    REG_IDX_R8,
    REG_IDX_R9,
};

void remove_nodes_of_type_at(int type, int node) {
    if(!node) return;

    struct trie_node *curr = &trie_node_storage[node];

    int i;
    for(i = 0; i < 0x100; ++i) {
        remove_nodes_of_type_at(type, curr->next[i]);
    }

    if(curr->value.type == type)
        curr->value.type = TRIE_TYPE_NONE;
}

void remove_nodes_of_type(int type) {
    remove_nodes_of_type_at(type, current_file_root);
}

void riprel_text_off_32(u64 text_offset) {
    u64 rip_text_offset = current_section_bytes[SECTION_TEXT] + 4;
    write32(text_offset - rip_text_offset, SECTION_TEXT);
}

// Emit a jump to the given text offset
void jmp_text_offset(u64 text_offset) {
    write8(0xE9, SECTION_TEXT);
    riprel_text_off_32(text_offset);
}

void riprel_addr_32(u64 addr) {
    u64 rip_value = section_base_addr[SECTION_TEXT] + current_section_bytes[SECTION_TEXT] + 4;
    write32(addr - rip_value, SECTION_TEXT);
}

void fixup32_to_here(u64 text_offset, u64 write_offset) {
    text_offset += write_offset;
    u64 rip_text_offset_at_offset = text_offset + 4;
    u64 target_offset = current_section_bytes[SECTION_TEXT];
    *(u32*)&current_section_buf[SECTION_TEXT][text_offset] = target_offset - rip_text_offset_at_offset;
}

// Basically emits
// ```
// +00: jmp 1f
// +02: jmp imm32
// +07: 1f:
// ```
// To get the addr to write the address to, call
//   `fixup_addr_loc`
// To set the address of the jump, call
//   `fixup_set_jump_dest`
u64 emit_jmp_fixup() {
    // We use the .text offset as the handle
    u64 fixup_handle = current_section_bytes[SECTION_TEXT];

    // jmp rip + 0x05 (+0x07)
    write8(0xEB, SECTION_TEXT);
    write8(0x05, SECTION_TEXT);

    // jmp imm32
    write8(0xE9, SECTION_TEXT);
    write32(0x41414141, SECTION_TEXT);

    return fixup_handle;
}

// Returns the number of args loaded into registers
int put_fargs_in_regs(u32 *reg_list) {
    int arg_idx = 0;

    // Possible value in a function call:
    //   * comptime values (including literals)
    //   * local variables & arguments
    //   * global buffer addrs
    skip_whitespace();
    if(peek() != ')') {
        while(1) {
            skip_whitespace();
            int arg_reg = reg_list[arg_idx];

            switch(peek()) {
            case '0'...'9':
                // Integer literal
                // mov arg_reg, val
                if(arg_reg >= 8) {
                    arg_reg -= 8;
                    write8(0x49, SECTION_TEXT);
                } else {
                    write8(0x48, SECTION_TEXT);
                }

                write8(0xB8 | arg_reg, SECTION_TEXT);
                write64(read_int_literal(), SECTION_TEXT);
                break;

            case '\'': consume();
                // Char literal
                if(arg_reg >= 8) {
                    arg_reg -= 8;
                    write8(0x49, SECTION_TEXT);
                } else {
                    write8(0x48, SECTION_TEXT);
                }

                write8(0xB8 | arg_reg, SECTION_TEXT);
                write64(read_char_literal(), SECTION_TEXT);
                break;

            case '"':
                if(arg_reg >= 8) {
                    arg_reg -= 8;
                    write8(0x4C, SECTION_TEXT);
                } else {
                    write8(0x48, SECTION_TEXT);
                }

                // lea arg_reg, [rel str_buf]
                write8(0x8D, SECTION_TEXT);
                write8(0x05 | (arg_reg << 3), SECTION_TEXT);
                riprel_addr_32(read_string_literal());
                break;

            case 'a'...'z':
            case 'A'...'Z':
            case '@':
            case '_':
                // Identifier, check type!
                struct trie_node_value *var_name_node = read_node_name(1);
                collapse_var_name_eval(&var_name_node);
                switch(var_name_node->type) {
                case TRIE_TYPE_FUNCTION_LOCAL:
                    if(arg_reg >= 8) {
                        arg_reg -= 8;
                        write8(0x4C, SECTION_TEXT);
                    } else {
                        write8(0x48, SECTION_TEXT);
                    }

                    // mov arg_reg, [rbp + rbp_offset]
                    write8(0x8B, SECTION_TEXT);
                    write8(0x85 | (arg_reg << 3), SECTION_TEXT);
                    write32(-var_name_node->value, SECTION_TEXT);
                    break;

                case TRIE_TYPE_FUNCTION_LOCAL_BUFFER:
                    if(arg_reg >= 8) {
                        arg_reg -= 8;
                        write8(0x4C, SECTION_TEXT);
                    } else {
                        write8(0x48, SECTION_TEXT);
                    }

                    // mov arg_reg, [rbp + rbp_offset]
                    write8(0x8D, SECTION_TEXT);
                    write8(0x85 | (arg_reg << 3), SECTION_TEXT);
                    write32(-var_name_node->value, SECTION_TEXT);
                    break;

                case TRIE_TYPE_GLOBAL_BUFFER:
                    if(arg_reg >= 8) {
                        arg_reg -= 8;
                        write8(0x4C, SECTION_TEXT);
                    } else {
                        write8(0x48, SECTION_TEXT);
                    }

                    // lea arg_reg, [rel glob_buf]
                    write8(0x8D, SECTION_TEXT);
                    write8(0x05 | (arg_reg << 3), SECTION_TEXT);
                    riprel_addr_32(var_name_node->value);
                    break;

                case TRIE_TYPE_BUILTIN_FUNCTION:
                    if(arg_reg >= 8) {
                        arg_reg -= 8;
                        write8(0x49, SECTION_TEXT);
                    } else {
                        write8(0x48, SECTION_TEXT);
                    }

                    // mov arg_reg, val
                    assert(consume() == '(');
                    write8(0xB8 | arg_reg, SECTION_TEXT);
                    write64(((u64(*)(int))var_name_node->value)(0), SECTION_TEXT);
                    break;

                case TRIE_TYPE_COMPTIME:
                    if(arg_reg >= 8) {
                        arg_reg -= 8;
                        write8(0x49, SECTION_TEXT);
                    } else {
                        write8(0x48, SECTION_TEXT);
                    }

                    // mov arg_reg, val
                    write8(0xB8 | arg_reg, SECTION_TEXT);
                    write64(var_name_node->value, SECTION_TEXT);
                    break;

                case TRIE_TYPE_FUNCTION_OFFSET:
                    if(arg_reg >= 8) {
                        arg_reg -= 8;
                        write8(0x4C, SECTION_TEXT);
                    } else {
                        write8(0x48, SECTION_TEXT);
                    }

                    // lea arg_reg, [rel fn]
                    write8(0x8D, SECTION_TEXT);
                    write8(0x05 | (arg_reg << 3), SECTION_TEXT);
                    riprel_text_off_32(var_name_node->value);
                    break;

                case TRIE_TYPE_NONE:
                    assert(!"Unknown identifier!");

                default:
                    assert(!"Invalid function call parameter identifier");
                }
                break;

            default: assert(!"Invalid function parameter start char");
            }

            skip_whitespace();
            if(peek() == ')') {
                break;
            }

            // Make sure we have a comma after our literal or identifier,
            // more complex expressions than that are not allowed.
            assert(consume() == ',');
            arg_idx += 1;
        }
    }

    assert(consume() == ')');
    return arg_idx;
}

void parse_eval_with_precedence(int precedence, struct trie_node_value *var_name_node) {
    skip_whitespace();

    if(var_name_node) {
        collapse_var_name_eval(&var_name_node);
    } else {
        // Primary expressions
        switch(peek()) {
            case '0'...'9':
                // mov rax, imm64
                write8(0x48, SECTION_TEXT);
                write8(0xB8, SECTION_TEXT);
                write64(read_int_literal(), SECTION_TEXT);
                break;

            case '\'': consume();
                // Char literal
                write8(0x48, SECTION_TEXT);
                write8(0xB8, SECTION_TEXT);
                write64(read_char_literal(), SECTION_TEXT);
                break;

            case '(': consume();
                parse_eval_with_precedence(PARSE_EVERYTHING, 0);
                assert(consume() == ')');
                break;

            case ')':
                printf("Error: Expected primary expression before ')'!\n");
                exit(1);
                break;

            case '-': consume();
                // Unary minus
                // Assoc: Left-to-Right
                // Prec: 2
                parse_eval_with_precedence(2, 0);

                // neg rax
                write8(0x48, SECTION_TEXT);
                write8(0xF7, SECTION_TEXT);
                write8(0xD8, SECTION_TEXT);
                break;

            case '~': consume();
                // Unary bitwise not
                // Assoc: Left-to-Right
                // Prec: 2
                parse_eval_with_precedence(2, 0);

                // not rax
                write8(0x48, SECTION_TEXT);
                write8(0xF7, SECTION_TEXT);
                write8(0xD0, SECTION_TEXT);
                break;

            case 'a'...'z':
            case 'A'...'Z':
            case '@':
            case '_':
                var_name_node = read_node_name(1);
                collapse_var_name_eval(&var_name_node);

                switch(var_name_node->type) {
                    case TRIE_TYPE_FUNCTION_LOCAL:
                        u64 rbp_offset = -var_name_node->value;
                        // lea rax, [rbp + rbp_offset]
                        write8(0x48, SECTION_TEXT);
                        write8(0x8D, SECTION_TEXT);
                        write8(0x85, SECTION_TEXT);
                        write32(rbp_offset, SECTION_TEXT);
                        break;

                    case TRIE_TYPE_GLOBAL_BUFFER:
                    case TRIE_TYPE_COMPTIME:
                        // mov rax, value
                        write8(0x48, SECTION_TEXT);
                        write8(0xB8, SECTION_TEXT);
                        write64(var_name_node->value, SECTION_TEXT);
                        break;

                    case TRIE_TYPE_FUNCTION_OFFSET:
                    case TRIE_TYPE_BUILTIN_FUNCTION:
                        // Handled in the function call postfix operator
                        break;

                    case TRIE_TYPE_NONE:
                        printf("Unknown identifier!\n");
                        exit(1);

                    default:
                        TODO
                }
                break;

            default: TODO
        }
    }

    skip_whitespace();

    // Postfix operators
    switch(peek()) {
        default:
            if(var_name_node) {
                switch(var_name_node->type) {
                    default: break;
                    case TRIE_TYPE_FUNCTION_OFFSET:
                        // lea rax, [rel foff]
                        write8(0x48, SECTION_TEXT);
                        write8(0x8D, SECTION_TEXT);
                        write8(0x05, SECTION_TEXT);
                        riprel_text_off_32(var_name_node->value);
                        break;

                    case TRIE_TYPE_FUNCTION_LOCAL:
                        // Dereference this pointer before evaluating everything else
                        // mov rax, [rax]
                        write8(0x48, SECTION_TEXT);
                        write8(0x8B, SECTION_TEXT);
                        write8(0x00, SECTION_TEXT);
                        break;
                }
            }
            break;

        case '[': consume();
            assert(var_name_node);

            // push rax
            write8(0x50, SECTION_TEXT);

            parse_eval_with_precedence(PARSE_EVERYTHING, 0);

            // pop rdx
            write8(0x5A, SECTION_TEXT);

            switch(var_name_node->type) {
                case TRIE_TYPE_FUNCTION_LOCAL:
                    // This is a pointer to an address, dereference it first
                    // mov rdx, [rdx]
                    write8(0x48, SECTION_TEXT);
                    write8(0x8B, SECTION_TEXT);
                    write8(0x12, SECTION_TEXT);

                    // Fall through to next case, we have to do the same thing anyways

                case TRIE_TYPE_GLOBAL_BUFFER:
                    // This is a straight up address

                    // Add evaluated offset to local variable pointer
                    // add rax, rdx
                    write8(0x48, SECTION_TEXT);
                    write8(0x01, SECTION_TEXT);
                    write8(0xD0, SECTION_TEXT);

                    // Dereference the pointer
                    // mov rax, [rax]
                    write8(0x48, SECTION_TEXT);
                    write8(0x8B, SECTION_TEXT);
                    write8(0x00, SECTION_TEXT);
                    break;
            }

            assert(consume() == ']');
            break;

        case '(': consume();
            assert(var_name_node);

            switch(var_name_node->type) {
            default: TODO

            case TRIE_TYPE_FUNCTION_OFFSET:
                u64 foffset = var_name_node->value;

                put_fargs_in_regs(arg_regs);

                // We need to store the lhs pointer in case
                // the function we're calling wants to overwrite it

                // push rbx
                write8(0x53, SECTION_TEXT);

                // Woop, call the function!
                write8(0xE8, SECTION_TEXT);
                riprel_text_off_32(foffset);

                // pop rbx
                write8(0x5B, SECTION_TEXT);
                break;

            case TRIE_TYPE_BUILTIN_FUNCTION:
                void (*fptr)(int) = (void(*)(int))var_name_node->value;
                fptr(1);
                break;
            }
            break;
    }

    while(1) {
        skip_whitespace();
        switch(peek()) {
            default:
                printf("parse_eval_with_precedence(): %c (%02X)\n", peek(), peek());
                TODO

            case '[':
                assert(!"Subscript operator on non-lvalue is not allowed!");

            // End of expression
            case ']':
            case ')':
            case ';':
            case ',':
                return;

            // Binary operators
            case '+':
                // Binary addition
                // Assoc: Left-to-Right
                // Prec: 4
                if(4 >= precedence) {
                    consume();
                    // push rax
                    write8(0x50, SECTION_TEXT);
                    parse_eval_with_precedence(4, 0);

                    // pop rdx
                    write8(0x5A, SECTION_TEXT);

                    // add rax, rdx
                    write8(0x48, SECTION_TEXT);
                    write8(0x01, SECTION_TEXT);
                    write8(0xD0, SECTION_TEXT);
                    break;
                }
                return;

            case '-':
                // Binary subtraction
                // Assoc: Left-to-Right
                // Prec: 4
                if(4 >= precedence) {
                    consume();
                    // push rax
                    write8(0x50, SECTION_TEXT);
                    parse_eval_with_precedence(4, 0);

                    // pop rdx
                    write8(0x5A, SECTION_TEXT);

                    // sub rdx, rax
                    write8(0x48, SECTION_TEXT);
                    write8(0x29, SECTION_TEXT);
                    write8(0xC2, SECTION_TEXT);

                    // mov rax, rdx
                    write8(0x48, SECTION_TEXT);
                    write8(0x89, SECTION_TEXT);
                    write8(0xD0, SECTION_TEXT);
                    break;
                }
                return;

            case '*':
                // Binary multiplication
                // Assoc: Left-to-Right
                // Prec: 3
                if(3 >= precedence) {
                    consume();
                    // push rax
                    write8(0x50, SECTION_TEXT);
                    parse_eval_with_precedence(3, 0);

                    // pop rdx
                    write8(0x5A, SECTION_TEXT);

                    // imul rax, rdx
                    write8(0x48, SECTION_TEXT);
                    write8(0x0F, SECTION_TEXT);
                    write8(0xAF, SECTION_TEXT);
                    write8(0xC2, SECTION_TEXT);
                    break;
                }
                return;

            case '%':
                // Binary modulus
                // Assoc: Left-to-Right
                // Prec: 3
                if(3 >= precedence) {
                    consume();
                    // push rax
                    write8(0x50, SECTION_TEXT);
                    parse_eval_with_precedence(3, 0);

                    // pop rcx
                    write8(0x59, SECTION_TEXT);

                    // xchg rax, rcx
                    write8(0x48, SECTION_TEXT);
                    write8(0x91, SECTION_TEXT);

                    // div rcx (rax /= rcx, rdx = rax % rcx)
                    write8(0x48, SECTION_TEXT);
                    write8(0x0F, SECTION_TEXT);
                    write8(0xAF, SECTION_TEXT);
                    write8(0xC2, SECTION_TEXT);

                    // push rdx
                    write8(0x52, SECTION_TEXT);

                    // pop rax
                    write8(0x58, SECTION_TEXT);
                    break;
                }
                return;

            case '/':
                // Binary modulus
                // Assoc: Left-to-Right
                // Prec: 3
                if(3 >= precedence) {
                    consume();
                    // push rax
                    write8(0x50, SECTION_TEXT);
                    parse_eval_with_precedence(3, 0);

                    // pop rcx
                    write8(0x59, SECTION_TEXT);

                    // xchg rax, rcx
                    write8(0x48, SECTION_TEXT);
                    write8(0x91, SECTION_TEXT);

                    // div rcx (rax /= rcx, rdx = rax % rcx)
                    write8(0x48, SECTION_TEXT);
                    write8(0x0F, SECTION_TEXT);
                    write8(0xAF, SECTION_TEXT);
                    write8(0xC2, SECTION_TEXT);
                    break;
                }
                return;

            case '&':
                // Binary bitwise and
                // Assoc: Left-to-Right
                // Prec: 8
                if(8 >= precedence) {
                    consume();
                    // push rax
                    write8(0x50, SECTION_TEXT);
                    parse_eval_with_precedence(8, 0);

                    // pop rdx
                    write8(0x5A, SECTION_TEXT);

                    // and rax, rdx
                    write8(0x48, SECTION_TEXT);
                    write8(0x21, SECTION_TEXT);
                    write8(0xD0, SECTION_TEXT);
                    break;
                }
                return;

            case '^':
                // Binary bitwise xor
                // Assoc: Left-to-Right
                // Prec: 9
                if(9 >= precedence) {
                    consume();
                    // push rax
                    write8(0x50, SECTION_TEXT);
                    parse_eval_with_precedence(9, 0);

                    // pop rdx
                    write8(0x5A, SECTION_TEXT);

                    // xor rax, rdx
                    write8(0x48, SECTION_TEXT);
                    write8(0x31, SECTION_TEXT);
                    write8(0xD0, SECTION_TEXT);
                    break;
                }
                return;

            case '|':
                // Binary bitwise or
                // Assoc: Left-to-Right
                // Prec: 10
                if(10 >= precedence) {
                    consume();
                    // push rax
                    write8(0x50, SECTION_TEXT);
                    parse_eval_with_precedence(10, 0);

                    // pop rdx
                    write8(0x5A, SECTION_TEXT);

                    // or rax, rdx
                    write8(0x48, SECTION_TEXT);
                    write8(0x09, SECTION_TEXT);
                    write8(0xD0, SECTION_TEXT);
                    break;
                }
                return;

            case '=': consume();
                assert(consume() == '=');
                // Equals comparison
                // Assoc: Left-to-Right
                // Prec: 7
                if(7 >= precedence) {
                    // push rax
                    write8(0x50, SECTION_TEXT);
                    parse_eval_with_precedence(7, 0);

                    // pop rdx
                    write8(0x5A, SECTION_TEXT);

                    // cmp rax, rdx
                    write8(0x48, SECTION_TEXT);
                    write8(0x39, SECTION_TEXT);
                    write8(0xD0, SECTION_TEXT);

                    // sete al
                    write8(0x0F, SECTION_TEXT);
                    write8(0x94, SECTION_TEXT);
                    write8(0xC0, SECTION_TEXT);

                    // movzx rax, al
                    write8(0x48, SECTION_TEXT);
                    write8(0x0F, SECTION_TEXT);
                    write8(0xB6, SECTION_TEXT);
                    write8(0xC0, SECTION_TEXT);
                    break;
                }
                TODO // Multi-char token can't be put back!

            case '!': consume();
                assert(consume() == '=');
                // Not-equals comparison
                // Assoc: Left-to-Right
                // Prec: 7
                if(7 >= precedence) {
                    // push rax
                    write8(0x50, SECTION_TEXT);
                    parse_eval_with_precedence(7, 0);

                    // pop rdx
                    write8(0x5A, SECTION_TEXT);

                    // cmp rax, rdx
                    write8(0x48, SECTION_TEXT);
                    write8(0x39, SECTION_TEXT);
                    write8(0xD0, SECTION_TEXT);

                    // setne al
                    write8(0x0F, SECTION_TEXT);
                    write8(0x95, SECTION_TEXT);
                    write8(0xC0, SECTION_TEXT);

                    // movzx rax, al
                    write8(0x48, SECTION_TEXT);
                    write8(0x0F, SECTION_TEXT);
                    write8(0xB6, SECTION_TEXT);
                    write8(0xC0, SECTION_TEXT);
                    break;
                }
                TODO // Multi-char token can't be put back!

            case '<': consume();
                switch(peek()) {
                    default:
                        // Less than
                        // Assoc: Left-to-Right
                        // Prec: 6
                        if(6 > precedence) {
                            // push rax
                            write8(0x50, SECTION_TEXT);
                            parse_eval_with_precedence(6, 0);

                            // pop rdx
                            write8(0x5A, SECTION_TEXT);

                            // cmp rdx, rax
                            write8(0x48, SECTION_TEXT);
                            write8(0x39, SECTION_TEXT);
                            write8(0xC2, SECTION_TEXT);

                            // setb al
                            write8(0x0F, SECTION_TEXT);
                            write8(0x92, SECTION_TEXT);
                            write8(0xC0, SECTION_TEXT);

                            // movzx rax, al
                            write8(0x48, SECTION_TEXT);
                            write8(0x0F, SECTION_TEXT);
                            write8(0xB6, SECTION_TEXT);
                            write8(0xC0, SECTION_TEXT);
                            break;
                        }
                        TODO // Multi-char token can't be put back!

                    case '=': consume();
                        // Less than or equal
                        // Assoc: Left-to-Right
                        // Prec: 6
                        if(6 > precedence) {
                            // push rax
                            write8(0x50, SECTION_TEXT);
                            parse_eval_with_precedence(6, 0);

                            // pop rdx
                            write8(0x5A, SECTION_TEXT);

                            // cmp rdx, rax
                            write8(0x48, SECTION_TEXT);
                            write8(0x39, SECTION_TEXT);
                            write8(0xC2, SECTION_TEXT);

                            // setbe al
                            write8(0x0F, SECTION_TEXT);
                            write8(0x96, SECTION_TEXT);
                            write8(0xC0, SECTION_TEXT);

                            // movzx rax, al
                            write8(0x48, SECTION_TEXT);
                            write8(0x0F, SECTION_TEXT);
                            write8(0xB6, SECTION_TEXT);
                            write8(0xC0, SECTION_TEXT);
                            break;
                        }
                        TODO // Multi-char token can't be put back!

                    case '<': consume();
                        // Shift left
                        // Assoc: Left-to-Right
                        // Prec: 5
                        if(5 > precedence) {
                            // push rax
                            write8(0x50, SECTION_TEXT);
                            parse_eval_with_precedence(10, 0);

                            // pop rcx
                            write8(0x59, SECTION_TEXT);

                            // shlx rax, rcx, rax
                            write8(0xC4, SECTION_TEXT);
                            write8(0xE2, SECTION_TEXT);
                            write8(0xF9, SECTION_TEXT);
                            write8(0xF7, SECTION_TEXT);
                            write8(0xC1, SECTION_TEXT);
                            break;
                        }
                        TODO // Multi-char token can't be put back!
                }
                break;

            case '>': consume();
                switch(peek()) {
                    default:
                        // Greater than
                        // Assoc: Left-to-Right
                        // Prec: 6
                        if(6 > precedence) {
                            // push rax
                            write8(0x50, SECTION_TEXT);
                            parse_eval_with_precedence(6, 0);

                            // pop rdx
                            write8(0x5A, SECTION_TEXT);

                            // cmp rdx, rax
                            write8(0x48, SECTION_TEXT);
                            write8(0x39, SECTION_TEXT);
                            write8(0xC2, SECTION_TEXT);

                            // seta al
                            write8(0x0F, SECTION_TEXT);
                            write8(0x97, SECTION_TEXT);
                            write8(0xC0, SECTION_TEXT);

                            // movzx rax, al
                            write8(0x48, SECTION_TEXT);
                            write8(0x0F, SECTION_TEXT);
                            write8(0xB6, SECTION_TEXT);
                            write8(0xC0, SECTION_TEXT);
                            break;
                        }
                        TODO // Multi-char token can't be put back!

                    case '=': consume();
                        // Greater than or equal
                        // Assoc: Left-to-Right
                        // Prec: 6
                        if(6 > precedence) {
                            // push rax
                            write8(0x50, SECTION_TEXT);
                            parse_eval_with_precedence(6, 0);

                            // pop rdx
                            write8(0x5A, SECTION_TEXT);

                            // cmp rdx, rax
                            write8(0x48, SECTION_TEXT);
                            write8(0x39, SECTION_TEXT);
                            write8(0xC2, SECTION_TEXT);

                            // setae al
                            write8(0x0F, SECTION_TEXT);
                            write8(0x93, SECTION_TEXT);
                            write8(0xC0, SECTION_TEXT);

                            // movzx rax, al
                            write8(0x48, SECTION_TEXT);
                            write8(0x0F, SECTION_TEXT);
                            write8(0xB6, SECTION_TEXT);
                            write8(0xC0, SECTION_TEXT);
                            break;
                        }
                        TODO // Multi-char token can't be put back!

                    case '>': consume();
                        // Shift right
                        // Assoc: Left-to-Right
                        // Prec: 5
                        if(5 > precedence) {
                            // push rax
                            write8(0x50, SECTION_TEXT);
                            parse_eval_with_precedence(10, 0);

                            // pop rcx
                            write8(0x59, SECTION_TEXT);

                            // shrx rax, rcx, rax
                            write8(0xC4, SECTION_TEXT);
                            write8(0xE2, SECTION_TEXT);
                            write8(0xFB, SECTION_TEXT);
                            write8(0xF7, SECTION_TEXT);
                            write8(0xC1, SECTION_TEXT);
                            break;
                        }
                        TODO // Multi-char token can't be put back!
                }
                break;
        }
    }
}

void parse_eval() {
    parse_eval_with_precedence(PARSE_EVERYTHING, 0);
}

// Read operator and value, target address is already stored in `rbx`
void do_op_qword(int is_pointer) {
    skip_whitespace();
    if(peek() == '[') {
        consume();
        if(is_pointer) {
            // We have to dereference the pointer to get its value
            // mov rbx, [rbx]
            write8(0x48, SECTION_TEXT);
            write8(0x8B, SECTION_TEXT);
            write8(0x1B, SECTION_TEXT);
        }

        parse_eval();

        // add rbx, rax
        write8(0x48, SECTION_TEXT);
        write8(0x01, SECTION_TEXT);
        write8(0xC3, SECTION_TEXT);

        assert(consume() == ']');
    }

    skip_whitespace();

    switch(peek()) {
    case '=': consume();
        // Assignment
        parse_eval();

        // mov [rbx], rax
        write8(0x48, SECTION_TEXT);
        write8(0x89, SECTION_TEXT);
        write8(0x03, SECTION_TEXT);
        return;

    case '+': consume();
        assert(consume() == '=');
        // In-place addition
        parse_eval();

        // add [rbx], rax
        write8(0x48, SECTION_TEXT);
        write8(0x01, SECTION_TEXT);
        write8(0x03, SECTION_TEXT);
        return;

    case '-': consume();
        assert(consume() == '=');

        // In-place subtraction
        parse_eval();

        // sub [rbx], rax
        write8(0x48, SECTION_TEXT);
        write8(0x29, SECTION_TEXT);
        write8(0x03, SECTION_TEXT);
        return;

    case '&': consume();
        assert(consume() == '=');

        // In-place bitwise and
        parse_eval();

        // and [rbx], rax
        write8(0x48, SECTION_TEXT);
        write8(0x21, SECTION_TEXT);
        write8(0x03, SECTION_TEXT);
        return;

    case '|': consume();
        assert(consume() == '=');

        // In-place bitwise or
        parse_eval();

        // and [rbx], rax
        write8(0x48, SECTION_TEXT);
        write8(0x09, SECTION_TEXT);
        write8(0x03, SECTION_TEXT);
        return;

    case '^': consume();
        assert(consume() == '=');

        // In-place bitwise xor
        parse_eval();

        // and [rbx], rax
        write8(0x48, SECTION_TEXT);
        write8(0x31, SECTION_TEXT);
        write8(0x03, SECTION_TEXT);
        return;

    case '*': consume();
        assert(consume() == '=');
        
        // In-place multiply
        parse_eval();

        // mul qword ptr [rbx]
        write8(0x48, SECTION_TEXT);
        write8(0xF7, SECTION_TEXT);
        write8(0x23, SECTION_TEXT);

        // mov [rbx], rax
        write8(0x48, SECTION_TEXT);
        write8(0x89, SECTION_TEXT);
        write8(0x03, SECTION_TEXT);
        return;

    case '/': consume();
        assert(consume() == '=');

        // In-place divide
        parse_eval();

        // xor rdx, rdx
        write8(0x48, SECTION_TEXT);
        write8(0x31, SECTION_TEXT);
        write8(0xD2, SECTION_TEXT);

        // xchg [rbx], rax
        write8(0x48, SECTION_TEXT);
        write8(0x87, SECTION_TEXT);
        write8(0x03, SECTION_TEXT);

        // div qword ptr [rbx]
        write8(0x48, SECTION_TEXT);
        write8(0xF7, SECTION_TEXT);
        write8(0x33, SECTION_TEXT);

        // mov [rbx], rax
        write8(0x48, SECTION_TEXT);
        write8(0x89, SECTION_TEXT);
        write8(0x03, SECTION_TEXT);
        return;

    case '%': consume();
        assert(consume() == '=');

        // In-place modulus
        parse_eval();

        // xor rdx, rdx
        write8(0x48, SECTION_TEXT);
        write8(0x31, SECTION_TEXT);
        write8(0xD2, SECTION_TEXT);

        // xchg [rbx], rax
        write8(0x48, SECTION_TEXT);
        write8(0x87, SECTION_TEXT);
        write8(0x03, SECTION_TEXT);

        // div qword ptr [rbx]
        write8(0x48, SECTION_TEXT);
        write8(0xF7, SECTION_TEXT);
        write8(0x33, SECTION_TEXT);

        // mov [rbx], rdx
        write8(0x48, SECTION_TEXT);
        write8(0x89, SECTION_TEXT);
        write8(0x13, SECTION_TEXT);
        return;

    case '>': consume();
        assert(consume() == '>');
        assert(consume() == '=');

        // In-place bitshift right
        parse_eval();

        // shrx rax, [rbx], rax
        write8(0xC4, SECTION_TEXT);
        write8(0xE2, SECTION_TEXT);
        write8(0xFB, SECTION_TEXT);
        write8(0xF7, SECTION_TEXT);
        write8(0x03, SECTION_TEXT);

        // mov [rbx], rax
        write8(0x48, SECTION_TEXT);
        write8(0x89, SECTION_TEXT);
        write8(0x03, SECTION_TEXT);
        return;

    case '<': consume();
        assert(consume() == '<');
        assert(consume() == '=');

        // In-place bitshift left
        parse_eval();
        
        // shrx rax, [rbx], rax
        write8(0xC4, SECTION_TEXT);
        write8(0xE2, SECTION_TEXT);
        write8(0xF9, SECTION_TEXT);
        write8(0xF7, SECTION_TEXT);
        write8(0x03, SECTION_TEXT);

        // mov [rbx], rax
        write8(0x48, SECTION_TEXT);
        write8(0x89, SECTION_TEXT);
        write8(0x03, SECTION_TEXT);
        return;

    default:
        printf("do_op_qword(): peek() = %02x (%c)\n", peek(), peek());
        TODO
    }
}

void parse_primary_expression_with_node(struct trie_node_value *lhs) {
    collapse_var_name_eval(&lhs);

    skip_whitespace();

    assert(lhs);
    switch(lhs->type) {
        case TRIE_TYPE_FUNCTION_LOCAL:
            // Load variable into `rbx`
            u64 rbp_offset = -lhs->value;
            // lea rbx, [rbp + rbp_offset]
            write8(0x48, SECTION_TEXT);
            write8(0x8D, SECTION_TEXT);
            write8(0x9D, SECTION_TEXT);
            write32(rbp_offset, SECTION_TEXT);

            do_op_qword(1);
            break;

        case TRIE_TYPE_GLOBAL_BUFFER:
            // Load global addr into `rbx`

            // lea rbx, [global_var]
            write8(0x48, SECTION_TEXT);
            write8(0x8D, SECTION_TEXT);
            write8(0x1D, SECTION_TEXT);
            riprel_addr_32(lhs->value);
            
            do_op_qword(0);
            break;

        case TRIE_TYPE_NONE:
            printf("Unknown identifier!\n");
            exit(1);

        default:
            parse_eval_with_precedence(PARSE_EVERYTHING, lhs);
    }

    assert(consume() == ';');
}

void parse_primary_expression() {
    struct trie_node_value *var_name_node = read_node_name(1);
    parse_primary_expression_with_node(var_name_node);
}

void recover_primary_expression(char const *recover_text) {
    int current = current_file_root;
    char buf[2];
    buf[1] = 0;

    while(*recover_text) {
        buf[0] = *recover_text++;
        current = lookup_node(buf, current);
    }

    while(1) {
        // No reason to call this with recover_text = "" so we can call
        //   `is_ident_chr` without bothering with `is_starting_ident_chr`
        if(is_ident_chr()) {
            buf[0] = consume();
            current = lookup_node(buf, current);
        } else {
            struct trie_node_value *lhs_node = get_or_create_node_value("", current);
            return parse_primary_expression_with_node(lhs_node);
        }
    }
}

int parse_block(u64 break_offset, u64 continue_offset, u64 endcase_offset, u64 *switch_table_base, u64 switch_default_label_text_offset) {
    while(1) {
        skip_whitespace();
        switch(peek()) {
            case '}': return 1;

            case 'b': consume();
                if(peek() != 'r') { recover_primary_expression("b"); break; } consume();
                if(peek() != 'e') { recover_primary_expression("br"); break; } consume();
                if(peek() != 'a') { recover_primary_expression("bre"); break; } consume();
                if(peek() != 'k') { recover_primary_expression("brea"); break; } consume();
                if(is_ident_chr()) { recover_primary_expression("break"); break; }

                assert(break_offset);
                jmp_text_offset(break_offset);

                skip_whitespace();
                assert(consume() == ';');

                if(switch_table_base == 0)
                    return 1;
                break;

            case 'c': consume();
                switch(peek()) {
                    case 'a': consume();
                        if(peek() != 's') { recover_primary_expression("ca"); break; } consume();
                        if(peek() != 'e') { recover_primary_expression("cas"); break; } consume();
                        if(is_ident_chr()) { recover_primary_expression("case"); break; }

                        assert(switch_table_base);

                        u64 start_table_index = eval_compiletime();
                        u64 end_table_index;
                        switch(consume()) {
                            case ':': switch_table_base[start_table_index] = current_section_bytes[SECTION_TEXT] - switch_default_label_text_offset; break;
                            case '.':
                                assert(consume() == '.');
                                assert(consume() == '.');
                                end_table_index = eval_compiletime();
                                assert(consume() == ':');
                                for(int i = start_table_index; i <= end_table_index; ++ i) {
                                    switch_table_base[i] = current_section_bytes[SECTION_TEXT] - switch_default_label_text_offset;
                                }
                        }

                        break;

                    case 'o': consume();
                        if(peek() != 'n') { recover_primary_expression("co"); break; } consume();
                        if(peek() != 't') { recover_primary_expression("con"); break; } consume();
                        if(peek() != 'i') { recover_primary_expression("cont"); break; } consume();
                        if(peek() != 'n') { recover_primary_expression("conti"); break; } consume();
                        if(peek() != 'u') { recover_primary_expression("contin"); break; } consume();
                        if(peek() != 'e') { recover_primary_expression("continu"); break; } consume();
                        if(is_ident_chr()) { recover_primary_expression("continue"); break; }

                        assert(continue_offset);
                        jmp_text_offset(continue_offset);

                        skip_whitespace();
                        assert(consume() == ';');

                        if(switch_table_base == 0)
                            // This is not a valid route of the block
                            return 0;
                        break;

                    default:
                        recover_primary_expression("c");
                        break;
                }
                break;

            case 'e': consume();
                if(peek() != 'n') { recover_primary_expression("e"); break; } consume();
                if(peek() != 'd') { recover_primary_expression("en"); break; } consume();
                if(peek() != 'c') { recover_primary_expression("end"); break; } consume();
                if(peek() != 'a') { recover_primary_expression("endc"); break; } consume();
                if(peek() != 's') { recover_primary_expression("endca"); break; } consume();
                if(peek() != 'e') { recover_primary_expression("endcas"); break; } consume();
                if(is_ident_chr()) { recover_primary_expression("endcase"); break; }


                skip_whitespace();
                assert(consume() == ';');

                assert(switch_table_base);

                jmp_text_offset(endcase_offset);

                break;

            case 'i': consume();
                if(peek() != 'f') { recover_primary_expression("i"); break; } consume();
                if(is_ident_chr()) { recover_primary_expression("if"); break; }

                skip_whitespace();
                assert(consume() == '(');

                parse_eval();

                // test rax, rax
                write8(0x48, SECTION_TEXT);
                write8(0x85, SECTION_TEXT);
                write8(0xC0, SECTION_TEXT);

                u64 else_fixup = current_section_bytes[SECTION_TEXT];
                // jz else_case
                write8(0x0F, SECTION_TEXT);
                write8(0x84, SECTION_TEXT);
                write32(0x41414141, SECTION_TEXT);

                skip_whitespace();
                assert(consume() == ')');

                skip_whitespace();
                assert(consume() == '{');
                int taken_can_exit = parse_block(break_offset, continue_offset, endcase_offset, switch_table_base, switch_default_label_text_offset);
                skip_whitespace();
                assert(consume() == '}');

                u64 endif_fixup = current_section_bytes[SECTION_TEXT];
                if(taken_can_exit) {
                    // jmp endif_label
                    write8(0xE9, SECTION_TEXT);
                    write32(0x41414141, SECTION_TEXT);
                }

                skip_whitespace();
                assert(consume() == 'e');
                assert(consume() == 'l');
                assert(consume() == 's');
                assert(consume() == 'e');
                assert(!is_ident_chr());

                fixup32_to_here(else_fixup, 2);

                // Parse else block
                skip_whitespace();
                assert(consume() == '{');
                int else_can_exit = parse_block(break_offset, continue_offset, endcase_offset, switch_table_base, switch_default_label_text_offset);
                skip_whitespace();
                assert(consume() == '}');

                // The else block falls through to the following code

                if(taken_can_exit) {
                    fixup32_to_here(endif_fixup, 1);
                }

                if(switch_table_base == 0 && (!taken_can_exit && !else_can_exit)) {
                    // We can exit if either path can
                    return 0;
                }

                break;

            case 'l': consume();
                if(peek() != 'o') { recover_primary_expression("l"); break; } consume();
                if(peek() != 'o') { recover_primary_expression("lo"); break; } consume();
                if(peek() != 'p') { recover_primary_expression("loo"); break; } consume();
                if(is_ident_chr()) { recover_primary_expression("loop"); break; }
                skip_whitespace();

                // Jump past the next jump
                // jmp continue_label
                write8(0xEB, SECTION_TEXT);
                write8(0x05, SECTION_TEXT); // continue_label - rip

                // We also need a fixup for switch `break;`s
                u64 new_break_offset = current_section_bytes[SECTION_TEXT];
                // jmp imm32
                write8(0xE9, SECTION_TEXT);
                write32(0x41414141, SECTION_TEXT);

                // continue_label:
                u64 new_continue_offset = current_section_bytes[SECTION_TEXT];
                assert(consume() == '{');
                // Loops can always exit through `break;`, can't do anything about that until
                // we can track it.
                parse_block(new_break_offset, new_continue_offset, endcase_offset, switch_table_base, switch_default_label_text_offset);
                skip_whitespace();
                assert(consume() == '}');
                fixup32_to_here(new_break_offset, 1);

                break;

            case 'r': consume();
                if(peek() != 'e') { recover_primary_expression("r"); break; } consume();
                if(peek() != 't') { recover_primary_expression("re"); break; } consume();
                if(peek() != 'u') { recover_primary_expression("ret"); break; } consume();
                if(peek() != 'r') { recover_primary_expression("retu"); break; } consume();
                if(peek() != 'n') { recover_primary_expression("retur"); break; } consume();
                if(is_ident_chr()) { recover_primary_expression("return"); break; }

                skip_whitespace();
                if(peek() != ';') {
                    parse_eval();
                }
                // Function epilogue
                // mov rsp, rbp
                write8(0x48, SECTION_TEXT);
                write8(0x89, SECTION_TEXT);
                write8(0xEC, SECTION_TEXT);

                // pop rbp
                write8(0x5D, SECTION_TEXT);

                // ret
                write8(0xC3, SECTION_TEXT);
                assert(consume() == ';');

                if(!switch_table_base)
                    return 0;
                break;

            case 's': consume();
                if(peek() != 'w') { recover_primary_expression("s"); break; } consume();
                if(peek() != 'i') { recover_primary_expression("sw"); break; } consume();
                if(peek() != 't') { recover_primary_expression("swi"); break; } consume();
                if(peek() != 'c') { recover_primary_expression("swit"); break; } consume();
                if(peek() != 'h') { recover_primary_expression("switc"); break; } consume();
                if(is_ident_chr()) { recover_primary_expression("switch"); break; }

                skip_whitespace();
                assert(consume() == '(');

                // Align pointer in .rodata, there could be strings and stuff in there!
                section_base_addr[SECTION_RODATA] += 7;
                section_base_addr[SECTION_RODATA] &= ~7;

                // Create a switch table in .rodata, it's already zero initialized
                u64 switch_table_addr = section_base_addr[SECTION_RODATA] + current_section_bytes[SECTION_RODATA];
                u64 *new_switch_table = (u64 *)&current_section_buf[SECTION_RODATA][current_section_bytes[SECTION_RODATA]];

                // Only switch cases 0..0x7F are valid
                write_generic(0, SECTION_RODATA, 8 * 0x80);

                parse_eval();

                // Get the switch table address
                // lea rbx, [rel switch_table_addr]
                write8(0x48, SECTION_TEXT);
                write8(0x8D, SECTION_TEXT);
                write8(0x1D, SECTION_TEXT);
                riprel_addr_32(switch_table_addr);

                // Index into the offset table with the result
                // mov rax, [rbx + rax * 8]
                write8(0x48, SECTION_TEXT);
                write8(0x8B, SECTION_TEXT);
                write8(0x04, SECTION_TEXT);
                write8(0xC3, SECTION_TEXT);

                // lea rbx, [rel default_case]
                write8(0x48, SECTION_TEXT);
                write8(0x8D, SECTION_TEXT);
                write8(0x1D, SECTION_TEXT);
                write32(0x0A, SECTION_TEXT); // default_case - rip

                // Add offset to the default case label
                // add rbx, rax
                write8(0x48, SECTION_TEXT);
                write8(0x01, SECTION_TEXT);
                write8(0xC3, SECTION_TEXT);

                // jmp rbx
                write8(0xFF, SECTION_TEXT);
                write8(0xE3, SECTION_TEXT);

                // We also need a fixup for switch `endcase;`s
                u64 new_endcase_offset = current_section_bytes[SECTION_TEXT];
                // jmp imm32
                write8(0xE9, SECTION_TEXT);
                write32(0x41414141, SECTION_TEXT);

                // default_case:
                u64 new_switch_default_label_text_offset = current_section_bytes[SECTION_TEXT];
                assert(consume() == ')');
                skip_whitespace();
                assert(consume() == '{');

                parse_block(break_offset, continue_offset, new_endcase_offset, new_switch_table, new_switch_default_label_text_offset);

                assert(consume() == '}');

                // Fix the imm32 in the jump hidden in the switchpoline
                fixup32_to_here(new_endcase_offset, 1);
                break;

            case 'u': consume();
                if(peek() != 'n') { recover_primary_expression("u"); break; } consume();
                if(peek() != 'r') { recover_primary_expression("un"); break; } consume();
                if(peek() != 'e') { recover_primary_expression("unr"); break; } consume();
                if(peek() != 'a') { recover_primary_expression("unre"); break; } consume();
                if(peek() != 'c') { recover_primary_expression("unrea"); break; } consume();
                if(peek() != 'h') { recover_primary_expression("unreac"); break; } consume();
                if(peek() != 'a') { recover_primary_expression("unreach"); break; } consume();
                if(peek() != 'b') { recover_primary_expression("unreacha"); break; } consume();
                if(peek() != 'l') { recover_primary_expression("unreachab"); break; } consume();
                if(peek() != 'e') { recover_primary_expression("unreachabl"); break; } consume();
                if(is_ident_chr()) { recover_primary_expression("unreachable"); break; }

                skip_whitespace();
                assert(consume() == ';');

                if(!switch_table_base)
                    return 0;
                break;

            default:
                if(is_starting_ident_chr()) {
                    parse_primary_expression();
                    break;
                } else {
                    printf("parse_block: %c (0x%02X)\n", peek(), peek());
                    TODO;
                }
        }
    }
}

void parse_function_decl() {
    // First, let's emit the function prologue
    // push rbp
    write8(0x55, SECTION_TEXT);

    // mov rbp, rsp
    write8(0x48, SECTION_TEXT);
    write8(0x89, SECTION_TEXT);
    write8(0xE5, SECTION_TEXT);

    u64 stack_offset = 0;
    u64 arg_idx = 0;

    // Read argument list, storing each ones stack offset and storing it to the stack
    assert(consume() == '(');
    while(1) {
        skip_whitespace();

        if(peek() == ')') {
            consume();
            break;
        }

        // Store the variable at `rbp - stack_offset`
        u32 arg_reg = arg_regs[arg_idx++];

        struct trie_node_value *var_name_node = read_node_name(1);
        assert(var_name_node->type == TRIE_TYPE_NONE);

        // Store the variable to our stack
        // push arg_reg
        if(arg_reg >= 8) {
            arg_reg -= 8;
            write8(0x41, SECTION_TEXT);
        }

        write8(0x50 | arg_reg, SECTION_TEXT);

        stack_offset += 8;

        var_name_node->type = TRIE_TYPE_FUNCTION_LOCAL;
        var_name_node->value = stack_offset;

        skip_whitespace();
        if(peek() == ',') {
            consume();
        }
    }
    skip_whitespace();

    u64 local_var_bytes = 0;

    // Local variable list
    if(peek() == '[') {
        consume();

        while(1) {
            skip_whitespace();

            if(peek() == ']') {
                consume();
                break;
            }

            struct trie_node_value *var_name_node = read_node_name(1);
            assert(var_name_node->type == TRIE_TYPE_NONE);

            // We don't initialize the variable, that's up to the user,
            // so no code is generated for local variables

            skip_whitespace();
            if(peek() == '[') {
                consume();
                // This is a buffer instead
                var_name_node->attribute = eval_compiletime();

                // Align size up
                var_name_node->attribute += 0xF;
                var_name_node->attribute &= ~0xF;

                skip_whitespace();
                assert(consume() == ']');

                var_name_node->type = TRIE_TYPE_FUNCTION_LOCAL_BUFFER;
                local_var_bytes += var_name_node->attribute;
                stack_offset    += var_name_node->attribute;
            } else {
                var_name_node->type = TRIE_TYPE_FUNCTION_LOCAL;
                local_var_bytes += 8;
                stack_offset    += 8;
            }
            var_name_node->value = stack_offset;

            skip_whitespace();
            if(peek() == ',') {
                consume();
            }
        }
    }

    if(!(stack_offset & 0x8)) {
        // If we add another variable it will be aligned.
        // That means we're not at this moment, we need to
        // add another one to remain aligned.
        local_var_bytes += 8;
    }

    if(local_var_bytes) {
        // sub rsp, imm32
        write8(0x48, SECTION_TEXT);
        write8(0x81, SECTION_TEXT);
        write8(0xEC, SECTION_TEXT);
        write32(local_var_bytes, SECTION_TEXT);
    }

    skip_whitespace(); assert(consume() == '{');
    int can_fall_through_block = parse_block(0, 0, 0, 0, 0);
    skip_whitespace(); assert(consume() == '}');

    if(can_fall_through_block) {
        // Function epilogue
        // mov rsp, rbp
        write8(0x48, SECTION_TEXT);
        write8(0x89, SECTION_TEXT);
        write8(0xEC, SECTION_TEXT);

        // pop rbp
        write8(0x5D, SECTION_TEXT);

        // ret
        write8(0xC3, SECTION_TEXT);
    }

    remove_nodes_of_type(TRIE_TYPE_FUNCTION_LOCAL);
}

void create_builtins_for_current_file() {
    // Add "@" shorthand for "builtin."
    add_shorthand(current_file_root, '@', builtin_root);

    // Prepare "builtin"
    struct trie_node_value *builtin_node = get_or_create_node_value("builtin", current_file_root);
    assert(builtin_node->type == TRIE_TYPE_NONE);

    builtin_node->type = TRIE_TYPE_FILE_DUP;
    builtin_node->file_scope_trie = builtin_root;
}

void parse_file() {
    while(1) {
        skip_whitespace();
        switch(peek()) {
        case 'e': consume();
            assert(consume() == 'n');
            assert(consume() == 'u');
            assert(consume() == 'm');

            // Enum decl
            skip_whitespace();
            assert(consume() == '{');
            u64 current_value = 0;

            while(1) {
                skip_whitespace();
                if(peek() == '}') {
                    consume();
                    break;
                }

                struct trie_node_value *name_node = read_node_name(1);
                assert(name_node->type == TRIE_TYPE_NONE);

                name_node->type = TRIE_TYPE_COMPTIME;
                name_node->value = current_value;
                skip_whitespace();
                switch(peek()) {
                case ',':
                    current_value += 1;
                    break;

                case '0'...'9':
                    current_value += read_int_literal();
                    break;

                case '=': consume();
                    name_node->value = eval_compiletime();
                    current_value = name_node->value + 1;
                    break;

                default: TODO
                }
                assert(consume() == ',');
            }
            skip_whitespace();
            assert(consume() == ';');
            break;

        case 'f': consume();
            assert(consume() == 'n');
            // Function decl

            skip_whitespace();
            struct trie_node_value *fn_name_node = read_node_name(1);
            assert(fn_name_node->type == TRIE_TYPE_NONE);

            fn_name_node->type = TRIE_TYPE_FUNCTION_OFFSET;
            fn_name_node->value = current_section_bytes[SECTION_TEXT];
            parse_function_decl();

            break;

        case 'i': consume();
            assert(consume() == 'm');
            assert(consume() == 'p');
            assert(consume() == 'o');
            assert(consume() == 'r');
            assert(consume() == 't');

            skip_whitespace();

            assert(consume() == '"');

            read_filename();

            skip_whitespace();

            // Make a new file node
            struct trie_node_value *filename_node = get_or_create_node_value(filename_buf, 0);
            struct trie_node_value *alias_node = read_node_name(1);
            assert(alias_node->type == TRIE_TYPE_NONE);
            skip_whitespace();
            assert(consume() == ';');
            alias_node->type = TRIE_TYPE_FILE_DUP;

            switch(filename_node->type) {
            case TRIE_TYPE_NONE:
                // Filename unknown!
                filename_node->type = TRIE_TYPE_FILE_UNANALYZED;
                alias_node->file_scope_trie = filename_node->file_scope_trie = alloc_trie_node();

                // Read and parse the file
                int old_fd = switch_file(filename_buf);
                int old_file_root = current_file_root;
                current_file_root = filename_node->file_scope_trie;
                create_builtins_for_current_file();
                parse_file();
                current_file_root = old_file_root;
                restore_file(old_fd);

                // File has finished parsing, update its status
                filename_node->type = TRIE_TYPE_FILE_SCOPE;
                break;

            case TRIE_TYPE_FILE_SCOPE:
                // File is already parsed, copy this into a an alias node
                alias_node->type = TRIE_TYPE_FILE_DUP;
                alias_node->file_scope_trie = filename_node->file_scope_trie;
                break;

            case TRIE_TYPE_FILE_UNANALYZED: // File is being parsed, circular import
                printf("File '%s' cirularly imported!\n", filename_buf);
                exit(1);

            default:
                assert(!"Unexpected filename type!");
            }
            break;

        case 'z': consume();
            assert(consume() == 'e');
            assert(consume() == 'r');
            assert(consume() == 'o');
            assert(consume() == 'e');
            assert(consume() == 's');

            struct trie_node_value *var_addr = read_node_name(1);
            assert(var_addr->type == TRIE_TYPE_NONE);

            skip_whitespace(); assert(consume() == '[');

            var_addr->attribute = eval_compiletime();

            var_addr->type = TRIE_TYPE_GLOBAL_BUFFER;
            var_addr->value = write_generic(0, SECTION_BSS, var_addr->attribute);
            skip_whitespace(); assert(consume() == ']');
            skip_whitespace(); assert(consume() == ';');

            // 8-byte align
            current_section_bytes[SECTION_BSS] += 8 - 1;
            current_section_bytes[SECTION_BSS] &= ~(8 - 1);

            break;

        case 'c': consume();
            assert(consume() == 'o');
            assert(consume() == 'm');
            assert(consume() == 'p');
            assert(consume() == 't');
            assert(consume() == 'i');
            assert(consume() == 'm');
            assert(consume() == 'e');

            skip_whitespace();
            struct trie_node_value *decl_name_node = read_node_name(1);
            assert(decl_name_node->type == TRIE_TYPE_NONE);

            // Please use the syntax `comptime my_identifier = <comptime expr>;`
            skip_whitespace(); assert(consume() == '=');

            decl_name_node->value = eval_compiletime();
            decl_name_node->type = TRIE_TYPE_COMPTIME;
            assert(consume() == ';');
            break;

        case 0:
            // End of file
            return;

        default:
            printf("parse_file: 0x%02x ('%c')\n", peek(), peek());
            TODO
        }
    }
}

void store_comptime_value(char const *name, long long value, int root) {
    struct trie_node_value *node_value = get_or_create_node_value(name, root);
    node_value->type = TRIE_TYPE_COMPTIME;
    node_value->value = value;
}

u64 write_entry_point() {
    u64 entry_point = current_section_bytes[SECTION_TEXT] + section_base_addr[SECTION_TEXT];

    // argc = [rsp]
    // mov rdi, qword ptr [rsp]
    write8(0x48, SECTION_TEXT);
    write8(0x8B, SECTION_TEXT);
    write8(0x3C, SECTION_TEXT);
    write8(0x24, SECTION_TEXT);

    // argv = rsp + 8
    // lea rsi, [rsp + 8]
    write8(0x48, SECTION_TEXT);
    write8(0x8D, SECTION_TEXT);
    write8(0x74, SECTION_TEXT);
    write8(0x24, SECTION_TEXT);
    write8(0x08, SECTION_TEXT);
    
    // envp = rsp + argc * 8 + 0x10 (there are argc+1 pointers, one null at the end)
    // lea rdx, [rsp + rdi * 8 + 0x10]
    write8(0x48, SECTION_TEXT);
    write8(0x8D, SECTION_TEXT);
    write8(0x54, SECTION_TEXT);
    write8(0xFC, SECTION_TEXT);
    write8(0x10, SECTION_TEXT);

    // Jump to main
    struct trie_node_value *node = get_or_create_node_value("main", current_file_root); // addr of main
    assert(node);
    assert(node->type == TRIE_TYPE_FUNCTION_OFFSET);

    write8(0xE9, SECTION_TEXT);
    riprel_text_off_32(node->value);

    return entry_point;
}

void write_output_file(int fd) {
    u64 entry_point = write_entry_point();

    u64 tmp;
    
    // Write the elf header
    assert(16 == write(fd, "\x7F\x45LF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16)); // hdr
    assert(2 == write(fd, "\x02\x00", 2)); // type
    assert(2 == write(fd, "\x3E\x00", 2)); // machine
    assert(4 == write(fd, "\x01\x00\x00\x00", 4)); // version

    assert(8 == write(fd, &entry_point, 8)); // entry

    assert(8 == write(fd, "\x40\x00\x00\x00\x00\x00\x00\x00", 8)); // phoff
    assert(8 == write(fd, "\x00\x00\x00\x00\x00\x00\x00\x00", 8)); // shoff
    assert(4 == write(fd, "\x00\x00\x00\x00", 4)); // flags
    assert(2 == write(fd, "\x00\x00", 2)); // ehsize
    assert(2 == write(fd, "\x38\x00", 2)); // phentsize
    assert(2 == write(fd, "\x04\x00", 2)); // phnum
    assert(2 == write(fd, "\x40\x00", 2)); // shentsize
    assert(2 == write(fd, "\x00\x00", 2)); // shnum
    assert(2 == write(fd, "\x00\x00", 2)); // shstrndx

    // phdrs
    u64 current_phdr_contents_file_offset = 0x1000;
    for(int i = 0; i < 4; ++ i) {
        assert(4 == write(fd, "\x01\x00\x00\x00", 4));
        switch(i) {
            case SECTION_TEXT:
                // WX
                assert(4 == write(fd, "\x05\x00\x00\x00", 4));
                break;

            case SECTION_RODATA:
                // R
                assert(4 == write(fd, "\x04\x00\x00\x00", 4));
                break;

            case SECTION_BSS:
            case SECTION_DATA:
                // RW
                assert(4 == write(fd, "\x06\x00\x00\x00", 4));
                break;
        }

        u64 aligned_file_size = (0xFFF + current_section_bytes[i]) & ~0xFFF;

        // file offset
        if(i == SECTION_BSS) {
            tmp = 0;
            assert(8 == write(fd, &tmp, 8));
        } else {
            assert(8 == write(fd, &current_phdr_contents_file_offset, 8));
        }

        tmp = section_base_addr[i];
        assert(8 == write(fd, &tmp, 8)); // vaddr
        assert(8 == write(fd, &tmp, 8)); // paddr

        // file size
        if(i == SECTION_BSS || current_section_bytes[i] == 0) {
            tmp = 0;
            assert(8 == write(fd, &tmp, 8));
        } else {
            assert(8 == write(fd, &current_section_bytes[i], 8));
            current_phdr_contents_file_offset += aligned_file_size;
        }

        // We pad every section with 7 additional zero bytes so that we can access
        // every byte as a 64 bit int
        tmp = current_section_bytes[i] + 7;
        assert(8 == write(fd, &tmp, 8)); // memory size

        // Alignment
        tmp = 0x1000;
        assert(8 == write(fd, &tmp, 8));
    }


    current_phdr_contents_file_offset = 0x1000;
    // Write the phdr contents
    for(int i = 0; i < 4; ++ i) {
        lseek(fd, current_phdr_contents_file_offset, SEEK_SET);

        u64 effective_phdr_size = (0xFFF + current_section_bytes[i]) & ~0xFFF;

        if(i != SECTION_BSS && effective_phdr_size) {
            assert(current_section_bytes[i] == write(fd, current_section_buf[i], current_section_bytes[i]));
            current_phdr_contents_file_offset += effective_phdr_size;
        }
    }

    fchmod(fd, 0755);
    close(fd);
}

void add_builtin_fn(char const *name, u64(*fn)(int)) {
    struct trie_node_value *node = get_or_create_node_value(name, builtin_root);
    assert(node->type == TRIE_TYPE_NONE);
    node->type = TRIE_TYPE_BUILTIN_FUNCTION;
    node->value = (u64)fn;
}

u32 read_regs[] = {
    REG_IDX_RSI,
};

u64 builtin_read8(int context) {
    assert(context == 1);

    // ptr in rsi
    put_fargs_in_regs(read_regs);

    // xor rax, rax
    // since this only touches al
    write8(0x48, SECTION_TEXT);
    write8(0x31, SECTION_TEXT);
    write8(0xC0, SECTION_TEXT);

    // lodsb
    write8(0xAC, SECTION_TEXT);

    return 0;
}

u64 builtin_read16(int context) {
    assert(context == 1);

    // ptr in rsi
    put_fargs_in_regs(read_regs);

    // xor rax, rax
    // since this only touches ax
    write8(0x48, SECTION_TEXT);
    write8(0x31, SECTION_TEXT);
    write8(0xC0, SECTION_TEXT);

    // lodsw
    write8(0x66, SECTION_TEXT);
    write8(0xAD, SECTION_TEXT);

    return 0;
}

u64 builtin_read32(int context) {
    assert(context == 1);

    // ptr in rsi
    put_fargs_in_regs(read_regs);

    // xor rax, rax
    // since this only touches eax
    write8(0x48, SECTION_TEXT);
    write8(0x31, SECTION_TEXT);
    write8(0xC0, SECTION_TEXT);

    // lodsd
    write8(0xAD, SECTION_TEXT);

    return 0;
}

u64 builtin_read64(int context) {
    assert(context == 1);

    // ptr in rsi
    put_fargs_in_regs(read_regs);

    // lodsq
    write8(0x48, SECTION_TEXT);
    write8(0xAD, SECTION_TEXT);

    return 0;
}

u32 write_regs[] = {
    REG_IDX_RDI,
    REG_IDX_RAX,
};

u64 builtin_write8(int context) {
    assert(context == 1);

    // ptr in rdi, value in rax
    put_fargs_in_regs(write_regs);

    // stosb
    write8(0xAA, SECTION_TEXT);

    return 0;
}

u64 builtin_write16(int context) {
    assert(context == 1);

    // ptr in rdi, value in rax
    put_fargs_in_regs(write_regs);

    // stosw
    write8(0x66, SECTION_TEXT);
    write8(0xAB, SECTION_TEXT);

    return 0;
}

u64 builtin_write32(int context) {
    assert(context == 1);

    // ptr in rdi, value in rax
    put_fargs_in_regs(write_regs);

    // stosd
    write8(0xAB, SECTION_TEXT);

    return 0;
}

u64 builtin_write64(int context) {
    assert(context == 1);

    // ptr in rdi, value in rax
    put_fargs_in_regs(write_regs);

    // stosq
    write8(0x48, SECTION_TEXT);
    write8(0xAB, SECTION_TEXT);

    return 0;
}

u64 builtin_size_of(int context) {
    switch(context) {
    case 0:
        // Read argument and collapse
        struct trie_node_value *arg = read_node_name(1);
        collapse_var_name_eval(&arg);

        skip_whitespace();
        assert(consume() == ')');

        switch(arg->type) {
        case TRIE_TYPE_GLOBAL_BUFFER:
            return arg->attribute;

        case TRIE_TYPE_FUNCTION_LOCAL:
            TODO
        default:
            TODO
        }
    case 1:
        TODO
    }
    TODO
}

u64 builtin_memcpy(int context) {
    u32 memcpy_regs[] = {
        REG_IDX_RDI,
        REG_IDX_RSI,
        REG_IDX_RCX,
    };

    assert(context == 1);
    
    put_fargs_in_regs(memcpy_regs);

    // rep
    write8(0xF3, SECTION_TEXT);

    // movsb
    write8(0xA4, SECTION_TEXT);

    return 0;
}

u64 builtin_syscall(int context) {
    u32 syscall_regs[] = {
        REG_IDX_RAX,
        REG_IDX_RDI,
        REG_IDX_RSI,
        REG_IDX_RDX,
        REG_IDX_R10,
        REG_IDX_R8,
        REG_IDX_R9,
    };

    assert(context == 1);

    put_fargs_in_regs(syscall_regs);

    // we don't care about the rcx clobber so just let it be for now

    // syscall
    write8(0x0F, SECTION_TEXT);
    write8(0x05, SECTION_TEXT);

    return 0;
}

void jump_to_assert_fail() {
    // TODO: Write the message and filename to .rodata, point to them and
    // set the line number correctly

    // Zero other arguments just for now

    // xor rsi, rsi
    write8(0x48, SECTION_TEXT);
    write8(0x31, SECTION_TEXT);
    write8(0xF6, SECTION_TEXT);

    // mov rdx, text_offset
    write8(0x48, SECTION_TEXT);
    write8(0xBA, SECTION_TEXT);
    write64(current_section_bytes[SECTION_TEXT], SECTION_TEXT);

    // xor rdx, rdx
    //write8(0x48, SECTION_TEXT);
    //write8(0x31, SECTION_TEXT);
    //write8(0xD2, SECTION_TEXT);

    // Call assert_fail(message, file, line);
    struct trie_node_value *node = get_or_create_node_value("assert_fail", root_root);
    assert(node->type == TRIE_TYPE_FUNCTION_OFFSET);

    // jmp assert_fail
    write8(0xE9, SECTION_TEXT);
    riprel_text_off_32(node->value);
}

u32 jmp_assert_regs[] = {
    REG_IDX_RDI, // Assert message string goes in here
};

u64 builtin_todo(int context) {
    skip_whitespace();

    switch(context) {
    case 0: TODO
    case 1:
        put_fargs_in_regs(jmp_assert_regs);
        jump_to_assert_fail();
        return 0;
    }

    return 0;
}

u64 builtin_assert(int context) {
    switch(context) {
    case 0:
        TODO
        break;

    case 1:
        parse_eval();

        // test rax, rax
        write8(0x48, SECTION_TEXT);
        write8(0x85, SECTION_TEXT);
        write8(0xC0, SECTION_TEXT);

        u64 success_fixup = current_section_bytes[SECTION_TEXT];

        // jnz success
        write8(0x0F, SECTION_TEXT);
        write8(0x85, SECTION_TEXT);
        write32(0x41414141, SECTION_TEXT);

        // xor rdi, rdi
        write8(0x48, SECTION_TEXT);
        write8(0x31, SECTION_TEXT);
        write8(0xFF, SECTION_TEXT);

        jump_to_assert_fail();

        // success:
        fixup32_to_here(success_fixup, 2);

        skip_whitespace();
        assert(consume() == ')');
        break;
    }

    return 0;
}

u64 builtin_call(int context) {
    switch(context) {
    case 0:
        TODO
        break;
    case 1:
        // push rbx
        write8(0x53, SECTION_TEXT);

        // Get the function pointer in rax
        parse_eval();

        skip_whitespace();
        if(peek() == ',') {
            consume();
            // Get all of the other argumens in there
            put_fargs_in_regs(arg_regs);
        } else {
            assert(consume() == ')');
        }

        // call rax
        write8(0xFF, SECTION_TEXT);
        write8(0xD0, SECTION_TEXT);

        // pop rbx
        write8(0x5B, SECTION_TEXT);
        break;
    }
    return 0;
}

u64 builtin_panic(int context) {
    skip_whitespace();

    switch(context) {
    case 0: TODO
    case 1:
        put_fargs_in_regs(jmp_assert_regs);
        jump_to_assert_fail();
        return 0;
    }

    return 0;
}

void add_builtins() {
    // Memory related builtins
    add_builtin_fn("read8", builtin_read8);
    add_builtin_fn("read16", builtin_read16);
    add_builtin_fn("read32", builtin_read32);
    add_builtin_fn("read64", builtin_read64);
    add_builtin_fn("write8", builtin_write8);
    add_builtin_fn("write16", builtin_write16);
    add_builtin_fn("write32", builtin_write32);
    add_builtin_fn("write64", builtin_write64);
    add_builtin_fn("size_of", builtin_size_of);
    add_builtin_fn("memcpy", builtin_memcpy);
    add_builtin_fn("call", builtin_call);

    // Helpers for writing code
    add_builtin_fn("todo", builtin_todo);
    add_builtin_fn("assert", builtin_assert);
    add_builtin_fn("panic", builtin_panic);

    // OS interface
    add_builtin_fn("syscall", builtin_syscall);
}

int main(int argc, char *argv[]) {
    // Compiler init
    builtin_root = alloc_trie_node();

    store_comptime_value("c_bootstrap_compiler", 1, builtin_root);
    store_comptime_value("pointer_bytes", 8, builtin_root);
    store_comptime_value("pointer_bits", 64, builtin_root);

    // Root file global scope
    root_root = current_file_root = alloc_trie_node();

    section_base_addr[0] = strtoll(argv[2], 0, 16);
    for(int i = 1; i <= LAST_SECTION; ++i) {
        section_base_addr[i] = section_base_addr[i-1] + MAX_SECTION_BYTES;
    }

    create_builtins_for_current_file();

    add_builtins();

    struct trie_node_value *root_node = get_or_create_node_value("@root", current_file_root);
    assert(root_node->type == TRIE_TYPE_NONE);
    root_node->type = TRIE_TYPE_FILE_DUP;
    root_node->file_scope_trie = current_file_root;

    if(argc < 3) {
        printf("Usage: %s <main file> <base addr>\n", argc == 0 ? "boostrap" : argv[0]);
        exit(1);
    }

    switch_file(argv[1]);

    int output_fd = 0;

    for(int i = 3; i < argc; ++ i) {
        if(argv[i][0] == '-' && argv[i][1] == 'o') {
            output_fd = open(argv[++i], O_WRONLY | O_CREAT);
            if(output_fd < 0) {
                printf("Error: Failed to open '%s' for writing: %d\n", argv[i], output_fd);
                exit(1);
            }
        }
    }

    if(output_fd == 0) {
        output_fd = open("a.out", O_WRONLY | O_CREAT);
        if(output_fd < 0) {
            printf("Error: Failed to open 'a.out' for writing: %d\n", output_fd);
            exit(1);
        }
    }

    parse_file();

    write_output_file(output_fd);
}
