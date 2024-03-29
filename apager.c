#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

# define STACK_PAGES 64

// load segments
// mmap(addr)
// need to make sure addr doesn't conflict, otherwise will not be in correct place
// mmap is page aligned but data may not be
// anon populate
// how do you statically link?
// how do you detect trying to mmap to already mapped section?
// is the stack sanity check sufficient?
// how to get auxillary vectors

// execve steps:
// allocates binary program
// prepares creds?
// checks if unsafe
// opens file
// Create a new mm_struct and populate it with a temporary stack
//  * vm_area_struct.  We don't have enough context at this point to set the stack
//  * flags, permissions, and offset, so we use temporary values.  We'll update
//  * them later in setup_arg_pages().
// sets up stack
// sets fs
// indicates no longer in execve
// updates mm integral fields in task struct for accounting

void new_aux_ent(uint64_t* aux_ptr, uint64_t val, uint64_t id)
{
	*(aux_ptr) = val;
	*(--aux_ptr) = id;
}

void* setup_stack(char* filename, int argc, char** argv, char** envp)
{
    size_t size = STACK_PAGES * sysconf(_SC_PAGESIZE);
    uintptr_t addr = 0x600000;
    void* stack_addr = mmap((void *)addr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    char* stack_ptr = (char*) addr + size;

    // walk to auxv
    char** tmp = envp;
	while (*tmp++ != NULL) {}


    Elf64_auxv_t *auxv = (Elf64_auxv_t *) tmp;
    int auxc = 0;
    while (auxv->a_type != AT_NULL)
    {
        auxv++;
        auxc++;
    }

    // handle AT_NULL
    uint64_t* aux_ptr = (uint64_t*) stack_ptr;
    new_aux_ent(--aux_ptr, auxv->a_un.a_val, auxv->a_type);
    aux_ptr--;
    for (auxc; auxc > 0; auxc--)
    {
        auxv--;
        new_aux_ent(--aux_ptr, auxv->a_un.a_val, auxv->a_type);
        aux_ptr--;
    }

    // set up envp
    char** char_ptr = (char**) aux_ptr;
    memset(--char_ptr, 0, sizeof(char**));
    size_t envc = 0;
    for (char** env = envp; *env != NULL; env++)
    {
        envc++;
    }
    for (int i = envc - 1; i >= 0; i--)
    {
        *(--char_ptr) = envp[i];
    }

    // set up argv
    memset(--char_ptr, 0, sizeof(char**));
    // don't copy argv[i]; it's the pager
    for (int i = argc - 1; i >= 0; i--)
    {
        *(--char_ptr) = argv[i];
    }

    long* long_ptr = (long*) char_ptr;
    *(--long_ptr) = argc;

    return (void*) long_ptr;

}

void stack_check(void* top_of_stack, uint64_t argc, char** argv) {
	printf("----- stack check -----\n");

	assert(((uint64_t)top_of_stack) % 8 == 0);
	printf("top of stack is 8-byte aligned\n");

	uint64_t* stack = top_of_stack;
	uint64_t actual_argc = *(stack++);
	printf("argc: %lu\n", actual_argc);
	assert(actual_argc == argc);

	for (int i = 0; i < argc; i++) {
		char* argp = (char*)*(stack++);
		assert(strcmp(argp, argv[i]) == 0);
		printf("arg %d: %s\n", i, argp);
	}
	// Argument list ends with null pointer
	assert(*(stack++) == 0);

	int envp_count = 0;
	while (*(stack++) != 0)
		envp_count++;

	printf("env count: %d\n", envp_count);

    printf("%p\n", stack);

	Elf64_auxv_t* auxv_start = (Elf64_auxv_t*)stack;
	Elf64_auxv_t* auxv_null = auxv_start;
	while (auxv_null->a_type != AT_NULL) {
		auxv_null++;
	}
	printf("aux count: %lu\n", auxv_null - auxv_start);
	printf("----- end stack check -----\n");
}

int main(int argc, char** argv, char** envp)
{
    int elf_fd = open(argv[1], O_RDONLY);
    if (elf_fd == -1) {
        fprintf(stderr, "Error opening file, errno: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    void* stack_ptr = setup_stack(argv[1], argc, argv, envp);

    printf("%p\n", stack_ptr);
    stack_check(stack_ptr, argc, argv);

}

