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
#include <signal.h>

# define STACK_PAGES 64

char* filename;
void* phdr_addr;
Elf64_Ehdr ehdr;

static void handler(int sig, siginfo_t* si, void* unused)
{
    // printf("SIGSEGV at address: %p\n", (void*) si->si_addr);
    // catch NULL
    if (!si->si_addr)
    {
        printf("Segfault\n");
        exit(EXIT_FAILURE);
    }


    int elf_fd = open(filename, O_RDONLY);
    if (elf_fd == -1) {
        fprintf(stderr, "Error opening file, errno: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int err;

    off_t offset = lseek(elf_fd, ehdr.e_phoff, SEEK_SET);
    off_t base_offset = offset;
    for (Elf64_Half i = 1; i <= ehdr.e_phnum; i++)
    {
        Elf64_Phdr phdr;
        err = read(elf_fd, (void*) &phdr, sizeof(phdr));
        if (err == -1) {
            fprintf(stderr, "Error reading elf program header\n");
            exit(EXIT_FAILURE);
        }
        if (phdr.p_type != PT_LOAD || !phdr.p_memsz || (uint64_t) si->si_addr < phdr.p_vaddr || (uint64_t) si->si_addr > phdr.p_vaddr + phdr.p_memsz)
        {
            offset = lseek(elf_fd, base_offset + i * sizeof(phdr), SEEK_SET);
        }
        else 
        {

            int prot = 0;
            if(phdr.p_flags & PF_R)
                prot |= PROT_READ;
            if(phdr.p_flags & PF_W)
                prot |= PROT_WRITE;
            if(phdr.p_flags & PF_X)
                prot |= PROT_EXEC;
            
            size_t align_bytes_offset = (uint64_t) si->si_addr % sysconf(_SC_PAGESIZE);
            size_t align_vaddr = (uint64_t) si->si_addr - align_bytes_offset;
            size_t segment_offset = align_vaddr - phdr.p_vaddr;
            size_t new_offset = phdr.p_offset + segment_offset;
            size_t align_bytes = new_offset % sysconf(_SC_PAGESIZE);
            // zero out bytes afterwards

            char* seg_addr = mmap((void*) align_vaddr, sysconf(_SC_PAGESIZE), PROT_WRITE, 
                                MAP_PRIVATE | MAP_POPULATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
            if (seg_addr == MAP_FAILED) {
                fprintf(stderr, "mmap failed\n");
                exit(EXIT_FAILURE);
            }
            fprintf(stderr, "Allocated %ld bytes at %p with file offset %lx\n", sysconf(_SC_PAGESIZE), seg_addr, phdr.p_offset);

            lseek(elf_fd, new_offset, SEEK_SET);

            // read at most 1 page
            size_t read_bytes = sysconf(_SC_PAGESIZE) - align_bytes;
            if ((uint64_t) (phdr.p_filesz + phdr.p_vaddr) < (uint64_t) (seg_addr + sysconf(_SC_PAGESIZE)))
            {
                size_t sub_offset = (uint64_t) seg_addr + sysconf(_SC_PAGESIZE);
                sub_offset -= phdr.p_filesz;
                sub_offset -= phdr.p_vaddr;
                read_bytes -= sub_offset;
            }
            

            // if bss, don't read
            if (read_bytes <= sysconf(_SC_PAGESIZE))
            {
                err = read(elf_fd, (seg_addr + align_bytes), read_bytes);
                if (err == -1) {
                    fprintf(stderr, "Error reading elf program\n");
                    exit(EXIT_FAILURE);
                }
            }
            err = mprotect((void *) align_vaddr, sysconf(_SC_PAGESIZE), prot);
            if (err == -1) {
                fprintf(stderr, "mprotect failed\n");
                exit(EXIT_FAILURE);
            }
            close(elf_fd);
            return;

        }
    }
    close(elf_fd);

    printf("Segfault for real\n");

    exit(EXIT_FAILURE);
}

void* load_elf()
{
    int elf_fd = open(filename, O_RDONLY);
    if (elf_fd == -1) {
        fprintf(stderr, "Error opening file, errno: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int err = read(elf_fd, (void*) &ehdr, sizeof(Elf64_Ehdr));
    if (err == -1) {
        fprintf(stderr, "Error reading elf header\n");
        exit(EXIT_FAILURE);
    }

    // Elf
    uint8_t set_phdr = 1;

    off_t offset = lseek(elf_fd, ehdr.e_phoff, SEEK_SET);
    off_t base_offset = offset;
    for (Elf64_Half i = 1; i <= ehdr.e_phnum && set_phdr; i++)
    {
        Elf64_Phdr phdr;
        err = read(elf_fd, (void*) &phdr, sizeof(phdr));
        if (err == -1) {
            fprintf(stderr, "Error reading elf program header\n");
            exit(EXIT_FAILURE);
        }

        if (phdr.p_type == PT_LOAD && phdr.p_memsz > 0)
        {
            if (set_phdr)
            {
                phdr_addr = (char*) phdr.p_vaddr + ehdr.e_phoff;
                set_phdr = 0;
            }

            int prot = 0;
            if(phdr.p_flags & PF_R)
                prot |= PROT_READ;
            if(phdr.p_flags & PF_W)
                prot |= PROT_WRITE;
            if(phdr.p_flags & PF_X)
                prot |= PROT_EXEC;
            
            size_t align_bytes = phdr.p_offset % sysconf(_SC_PAGESIZE);
            size_t align_vaddr = phdr.p_vaddr - align_bytes;
            size_t align_offset = phdr.p_offset - align_bytes;
            size_t size = align_bytes + phdr.p_memsz;
            if (size > sysconf(_SC_PAGESIZE))
                size = sysconf(_SC_PAGESIZE);
            // zero out bytes afterwards

            char* seg_addr = mmap((void*) align_vaddr, size, PROT_WRITE, 
                                MAP_PRIVATE | MAP_POPULATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
            fprintf(stderr, "Allocated %ld bytes at %p with file offset %lx\n", size, seg_addr, phdr.p_offset);
            if (seg_addr == MAP_FAILED) {
                fprintf(stderr, "mmap failed\n");
                exit(EXIT_FAILURE);
            }
            
            lseek(elf_fd, phdr.p_offset, SEEK_SET);
            size_t fsize = align_bytes + phdr.p_filesz;
            if (fsize > sysconf(_SC_PAGESIZE))
                fsize = sysconf(_SC_PAGESIZE);
            fsize -= align_bytes;
            err = read(elf_fd, (seg_addr + align_bytes), fsize);
            if (err == -1) {
                fprintf(stderr, "Error reading elf program header\n");
                exit(EXIT_FAILURE);
            }
            err = mprotect((void *) align_vaddr, size, prot);
            if (err == -1) {
                fprintf(stderr, "mprotect failed\n");
                exit(EXIT_FAILURE);
            }
        }
        offset = lseek(elf_fd, base_offset + i * sizeof(phdr), SEEK_SET);
    }
    close(elf_fd);
    
    // return entry_addr
    return (void*) ehdr.e_entry;
}

void new_aux_ent(uint64_t* aux_ptr, uint64_t val, uint64_t id)
{
	*(aux_ptr) = val;
	*(--aux_ptr) = id;
}

void* setup_stack(char* filename, int argc, char** argv, char** envp, void* entry)
{
    size_t size = STACK_PAGES * sysconf(_SC_PAGESIZE);
    uintptr_t addr = 0x3e00000;
    char* stack_addr = mmap((void*)addr, size, PROT_READ | PROT_WRITE, 
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (stack_addr == MAP_FAILED) {
        fprintf(stderr, "mmap failed\n");
        exit(EXIT_FAILURE);
    }
    char* stack_ptr = (char*) addr + size;

    // walk to auxv
    char** tmp = envp;
	while (*tmp++ != NULL) {}

    // set up auxv
    Elf64_auxv_t* auxv = (Elf64_auxv_t*) tmp;
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
        // not sure this is necessary, but update the PHDR and ENTRY auxv
        switch (auxv->a_type)
        {
			case AT_PHDR:
			{
                new_aux_ent(--aux_ptr, (uint64_t) phdr_addr, AT_PHDR);
				break;
			}
            case AT_ENTRY:
            {
                new_aux_ent(--aux_ptr, (uint64_t) entry, AT_ENTRY);
                break;
            }
            default:
            {
                new_aux_ent(--aux_ptr, auxv->a_un.a_val, auxv->a_type);
                break;
            }
        }
        aux_ptr--;
    }

    // set up envp
    char** env_ptr = (char**) aux_ptr;
    memset(--env_ptr, 0, sizeof(char**));
    size_t envc = 0;
    for (char** env = envp; *env != NULL; env++)
    {
        envc++;
    }
    for (int i = envc - 1; i >= 0; i--)
    {
        *(--env_ptr) = envp[i];
    }

    // set up argv
    char** arg_ptr = (char**) env_ptr;
    memset(--arg_ptr, 0, sizeof(char**));
    for (int i = argc - 1; i >0; i--)
    {
        *(--arg_ptr) = argv[i];
    }

    long* argc_ptr = (long*) arg_ptr;
    *(--argc_ptr) = argc - 1;

    return (void*) argc_ptr;

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

int stack_check_2(char** argv) {
	char** sp = argv;
	printf("argv\n");
	/* walk past all argv pointers */
	while (*sp++ != NULL)
	{
        printf("argv %p \n", *sp);
		if(*sp != NULL)
			printf("%s\n", *sp);
	}

	printf("envp\n");
	/* walk past all env pointers */
	while (*sp++ != NULL)
	{
        printf("envp %p \n", *sp);
		// if(*sp != NULL)
		// 	printf("%s\n", *sp);
	}

        /* and find ELF auxiliary vectors (if this was an ELF binary) */
	int i = 0;
    for (Elf64_auxv_t *auxv = (Elf64_auxv_t *) sp; auxv->a_type != -1; ++auxv) {
        printf("%d : ", ++i);
        switch (auxv->a_type)
        {
            case AT_NULL:
            {
                printf("AT_NULL\n");
                return 0;
            }
            case AT_SYSINFO_EHDR:
            {
                printf("AT_SYSINFO_EHDR : %p\n", (void*) auxv->a_un.a_val);
                break;
            }
            case AT_MINSIGSTKSZ:
            {
                printf("AT_MINSIGSTKSZ : %lu\n", auxv->a_un.a_val);
                break;
            }
            case AT_HWCAP:
            {
                printf("AT_HWCAP : %lu\n", auxv->a_un.a_val);
                break;
            }
            case AT_PAGESZ:
            {
                printf("AT_PAGESZ : %lu\n", auxv->a_un.a_val);
                break;
            }
            case AT_CLKTCK:
            {
                printf("AT_CLKTCK : %lu\n", auxv->a_un.a_val);
                break;
            }	
            case AT_PHDR:
            {
                printf("AT_PHDR : %p\n", (void*) auxv->a_un.a_val);
                break;
            }
            case AT_PHENT:
            {
                printf("AT_PHENT : %lu\n", auxv->a_un.a_val);
                break;
            }
            case AT_PHNUM:
            {
                printf("AT_PHNUM : %lu\n", auxv->a_un.a_val);
                break;
            }
            case AT_BASE:
            {
                printf("AT_BASE : %p\n", (void*) auxv->a_un.a_val);
                break;
            }
            case AT_FLAGS:
            {
                printf("AT_FLAGS : %lu\n", auxv->a_un.a_val);
                break;
            }
            case AT_ENTRY:
            {
                printf("AT_ENTRY : %p\n", (void*) auxv->a_un.a_val);
                break;
            }
            case AT_UID:
            {
                printf("AT_UID : %lu\n", auxv->a_un.a_val);
                break;
            }
            case AT_EUID:
            {
                printf("AT_EUID : %lu\n", auxv->a_un.a_val);
                break;
            }
            case AT_GID:
            {
                printf("AT_GID : %lu\n", auxv->a_un.a_val);
                break;
            }
            case AT_EGID:
            {
                printf("AT_EGID : %lu\n", auxv->a_un.a_val);
                break;
            }	
            case AT_SECURE:
            {
                printf("AT_SECURE : %lu\n", auxv->a_un.a_val);
                break;
            }
            case AT_RANDOM:
            {
                printf("AT_RANDOM : %p\n", (void*) auxv->a_un.a_val);
                break;
            }
            case AT_EXECFN:
            {
                printf("AT_EXECFN : %lu\n", auxv->a_un.a_val);
                break;
            }
            case AT_HWCAP2:
            {
                printf("AT_HWCAP2 : %lu\n", auxv->a_un.a_val);
                break;
            }
            case AT_PLATFORM:
            {
                printf("AT_PLATFORM : %lu\n", auxv->a_un.a_val);
                break;
            }	
        }
    }
}

int main(int argc, char** argv, char** envp)
{
    // Set up SIGSEGV handler
    struct sigaction sa;
    int err;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sa.sa_sigaction = handler;
    err = sigaction(SIGSEGV, &sa, NULL);
    if (err == -1)
    {
        fprintf(stderr, "Failed to set up sigaction\n");
        exit(EXIT_FAILURE);
    }
    
    filename = argv[1];
    void* entry_addr = load_elf();

    void* stack_ptr = setup_stack(argv[1], argc, argv, envp, entry_addr);

    // stack_check(stack_ptr, argc - 1, argv + 1);
    // stack_check_2(stack_ptr);

    asm volatile("movq %0, %%rsp\n\t" : "+r" ((uint64_t) stack_ptr));
    asm volatile("movq %0, %%rax\n\t" : "+r" ((uint64_t) entry_addr));
    asm volatile("push %rax\n\t");
    asm volatile("movq $0, %rax");
    asm volatile("movq $0, %rbx");
    asm volatile("movq $0, %rcx");
    asm volatile("movq $0, %rdx");
    asm volatile("movq $0, %rsi");
    asm volatile("movq $0, %rdi");
    // asm volatile("movq $0, %rbp");
    asm volatile("movq $0, %r8");
    asm volatile("movq $0, %r9");
    asm volatile("movq $0, %r10");
    asm volatile("movq $0, %r11");
    asm volatile("movq $0, %r12");
    asm volatile("movq $0, %r13");
    asm volatile("movq $0, %r14");
    asm volatile("movq $0, %r15");
    asm volatile("ret\n\t");

}

