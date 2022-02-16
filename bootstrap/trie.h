struct trie_node_value {
    int type;
    int attribute;

    union {
        struct {
            u64 value;
        };

        struct {
            int file_scope_trie;
        };
    };
};

#define MAX_TRIE_NODES 0x10000

struct trie_node {
    int next[0x100];
    struct trie_node_value value;
};

struct trie_node trie_node_storage[MAX_TRIE_NODES] = {};
int last_node_alloced = 0;
int current_file_root = 0;

enum {
    // Nothing on that node
    TRIE_TYPE_NONE = 0,

    // Has a compile time value
    TRIE_TYPE_COMPTIME,

    // Points to another trie node with the scope for the imported file
    TRIE_TYPE_FILE_SCOPE,

    // For member lookups, acts just like FILE_SCOPE, but is not
    // valid for any other purpose.
    TRIE_TYPE_FILE_DUP,

    // File that has not finished analyzing
    TRIE_TYPE_FILE_UNANALYZED,

    // Function offset
    TRIE_TYPE_FUNCTION_OFFSET,

    // Global variable
    TRIE_TYPE_GLOBAL_VARIABLE,

    // Local variable in function, stack pointer relative offset
    TRIE_TYPE_FUNCTION_LOCAL,

    // Local buffer in function, stack pointer relative offset, attribute is size
    TRIE_TYPE_FUNCTION_LOCAL_BUFFER,

    // Global buffer, attribute is size
    TRIE_TYPE_GLOBAL_BUFFER,

    // Builtin function
    TRIE_TYPE_BUILTIN_FUNCTION,
};

int alloc_trie_node(void) {
    return ++last_node_alloced;
}

int lookup_node(char const *name, int create, int current_trie_node) {
    if(!*name) {
        return current_trie_node;
    }

    struct trie_node *curr = &trie_node_storage[current_trie_node];
    if(!curr->next[(unsigned char)*name]) {
        if(create) {
            curr->next[(unsigned char)*name] = alloc_trie_node();
        } else {
            return 0;
        }
    }

    return lookup_node(name + 1, create, curr->next[(unsigned char)*name]);
}

void add_shorthand(int scope, char shorthand, int target) {
    trie_node_storage[scope].next[(unsigned char)shorthand] = target;
}

struct trie_node_value *get_or_create_node_value(char const *name, int root) {
    return &trie_node_storage[lookup_node(name, 1, root)].value;
}
