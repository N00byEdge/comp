test: build/comp.s3

.PHONY: test clean
.SECONDARY:;

os_name = $(shell uname -s)
all_co_files = $(shell find src -name '*.co')

clean:
	rm -rf build

build/comp.s3: build/comp.s2 $(all_co_files)
	$< src/main.co 0x100000 -o $@

build/comp.s2: build/comp.s1 $(all_co_files)
	#$< src/main.co 0x100000 -o $@
	strace $< src/main.co 0x100000 -o $@
	#gdb $< -ex 'starti src/main.co 0x100000 -o $@'

build/comp.s1: build/$(os_name)_bootstrap $(all_co_files)
	$< src/main.co 0x100000 -o $@

build/$(os_name)_bootstrap: bootstrap/comp.c $(shell find bootstrap -name '*.h') Makefile
	@mkdir -p $(@D)
	$(CC) $< -o $@ -Wall -g -ggdb -Werror
