# Comp

Comp is a typeless language that tries to still provide modern facilities such as imports and compile time evaluation.

It is designed to be very easy to process, the compiler doing both parsing and code generation in a single pass.

## Example code

```zig
var my_global_var;

import "src/my_module.co" my_module;

fn my_fun(arg) [my_local_var] {
    // Treats `my_global_var` as a pointer and dereferences it
    my_local_var = my_global_var[arg];

    if(my_local_var) {
        // Asserts `arg`, on assertion failure, the `panic` function
        // in the root file is called:
        // if(!arg) @root.panic("Assertion failure: ", 0, @filename(), @line())
        @assert(arg);

        // if(!arg) @root.panic("Assertion failure: ", "has argument", @filename(), @line())
        @assert(arg, "has argument");
    } else {
        loop {
            switch(my_global_var) {
                // Implicit default case right after `switch() {`
                // @root.panic("PANIC: ", "What is this?", @filename(), @line())
                @panic("What is this?");

                // Case ranges work like expected...
            case 'a'...'z':
                @todo("letter"); // @root.panic("TODO: ", "letter", @filename(), @line())

                // Except that you can override cases in ranges listed before
            case 'a':
            case 'e':
            case 'i':
            case 'o':
            case 'u':
                print("Vowel!");
                // `endcase;` to end a switch case
                endcase;

            case 'q':
                // Now you can break your loops from within a switch!
                break;

            case '0':
                // Continue works as expected, just continues the loop outside
                continue;

            case '.':
                // Fall through out of switch for everything else
            }
        }

        return my_module.hello();
    }
}
```

## Notes
There are a few limitations to simplify the implementation, namely:
* Circular imports are disallowed
* You can only access things previously declared/imported
* Array subscript `my_buffer[idx]` parses the subscript as a byte offset
* Array subscript `my_buffer[idx]` is always a pointer-length memory reference. For accesses of other sizes, check `@{read,write}{8,16,32}` in the builtin list

## Builtins
Builtins are available as `builtin.<builtin name>` and `@<builtin name>` from every file.

Vital for the language:
* `read{8,16,32}(ptr)`

  Read from `ptr` with the specified bit size, returns a zero extended pointer length value for every read size.

* `write{8,16,32}(ptr, value)`

  Write `value` to the address specified in `ptr`. Does the write with the size specified.

* `syscall(arg...)`

  Does whatever a syscall means for your target.

  Linux example: `retval = @syscall(SYS_READ, fd, buf, len);`

* `call(ptr, arg...)`

  Calls the function pointer `ptr` with any arguments you supply

Would be missed if we didn't have them:
* `root`

  A way to access the root source file (the one specified on the command line) in the project

* `size_of(identifier)`

  Evaluates to the byte size of the object referenced by the identifier at compile time

* `memcpy(dst, src, size)`

  Good ol' memcpy. Does what it says on the tin, **but returns an undefined value**.

How we can have nice things:
* `line()`:

  Evaluates to the current line number at the invocation site at compile time

* `filename()`:

  Evaluates to the current source file path at the invocation site at compile time

* `todo()`:

  Equivalent to `@root.panic("TODO: ", 0, @filename(), @line());`

* `todo(message)`:

  Equivalent to `@root.panic("TODO: ", message, @filename(), @line());`

* `panic()`:

  Equivalent to `@root.panic("PANIC: ", 0, @filename(), @line());`

* `panic(message)`:

  Equivalent to `@root.panic("PANIC: ", message, @filename(), @line());`

* `assert(expr)`:

  Equivalent to `if(!expr) { @root.panic("Assetion failure: ", 0, @filename(), @line()); }`

* `assert(expr, message)`:

  Equivalent to `if(!expr) { @root.panic("Assetion failure: ", message, @filename(), @line()); }`

## Expressions
The expressions are designed in such a way where there are no ambigous expressions, so no operator precedence or associativity is needed.
* Complex expressions
  * Binary expressions

    `<simple expr> <standard binary operator> <simple expr>`

    Standard binary operators:
	  * `+` Addition
	  * `-` Subtraction
	  * `*` Multiplication
	  * `/` Division
	  * `%` Modulus
	  * `&` Bitwise and
	  * `^` Bitwise xor
	  * `|` Bitwise or
  * Unary expression

    `<unary op> <simple expr>`

    Unary operators:
      * `~` bitwise not
      * `-` 2's complement negate

   * Ternary expression

   	 `<simple expr> ? <non-inplace expr> : <non-inplace expr>`

   	 If the first expression is nonzero, evaluates to the first expression, otherwise the second one

   	 `<simple expr> ?: <non-inplace expr>`

   	 Evaluates to the first expression if nonzero, otherwise the second

* Simple expressions
  * Parenthesis

    `(<non-inplace expr>)`

  * Integral literals

    `420` or `0x69`

  * Identifiers

    `my_var`

  * Call expressions

    `<simple expr>(<non-inplace expr>, ...)`

  * Subscript expressions

    `<simple expr>[<non-inplace expr>]`

* In-place expression

  `<simple expr> <in-place binary operator> <non-inplace expr>`

  In-place binary operators:
    * `=` Assignment
    * `+=` Addition
    * `-=` Subtraction
    * `*=` Multiplication
    * `/=` Division
    * `%=` Modulus
    * `&=` Bitwise and
    * `^=` Bitwise xor
    * `|=` Bitwise or

## Types of statements
All statements are followed either by a block or a semicolon.
* `break`

  Jumps past the end of the current `loop` block

* `continue`

  Jumps back to the start of the current `loop` block

* `endcase`

  Jumps past the end of the current `switch` block

* `if`

  Runs either the first or the second branch based on the condition.

  Can optionally be followed by an `else` keyword and another block.

* `loop`

  Reruns the code within the block until a `break` or `return` statement.

  You can go to the top of the loop using `continue`.

* `return`

  Optionally return a value to the calling function.

* `switch`

  Jumps to the case matching the value switched on.

  Default case is the first piece of code within the following block, no label needed.

  If control flow reaches the end of the switch block it falls through.

* `unreachable`

  Assumes the statement is in dead code, a hint for compiler optimization

* Expression statements

  Any expression above (but only in-place and call expressions are useful)

## Keywords
Keywords can never be used as identifiers
* `break`
* `case`
* `comptime`
* `continue`
* `else`
* `endcase`
* `enum`
* `fn`
* `if`
* `import`
* `loop`
* `return`
* `switch`
* `undefined`
* `unreachable`
* `zeroes`
