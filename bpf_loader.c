#include <gelf.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <libelf.h>
#include <unistd.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

int sys_perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
	attr->size = sizeof(*attr);
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int get_elf_section(Elf *elf, int sectionIndex, GElf_Ehdr *elfHeader, 
	char **sectionName, GElf_Shdr *sectionHeader, Elf_Data **sectionData)
{
	Elf_Scn *scn = elf_getscn(elf, sectionIndex);
	
	if (!scn) {
		return 1;
	}

	if (gelf_getshdr(scn, sectionHeader) != sectionHeader) {
		return 2;
	}

	*sectionName = elf_strptr(elf, elfHeader->e_shstrndx, sectionHeader->sh_name);
	
	if (!*sectionName || !sectionHeader->sh_size) {
		return 3;
	}

	*sectionData = elf_getdata(scn, 0);
	
	if (!*sectionData || elf_getdata(scn, *sectionData) != NULL) {
		return 4;
	}

	return 0;
}

int readFile(char* path) {
	int fd = open(path, O_RDONLY, 0);
	
	if (fd < 0) {
		printf("Error openning %s for read: %s\n", path, strerror(errno));
		return 1;
	}
	
	char buffer[1024];
	int err = read(fd, buffer, sizeof(buffer));
	
	close(fd);
	
	if (err < 0 || err >= sizeof(buffer)) {
		printf("Error reading from %s: %s\n", path, strerror(errno));
		return 1;
	}
	
	buffer[err] = 0;
	return atoi(buffer);
}

// Kept in a single long method for simplicity, avoid pointers, structs etc..
//
//	1. Read the bpf_program.o program and find its code section
//	2. Load the bpf code into the kernel
//	3. Enable the sys_enter_execve event
//  4. Link the loaded bpf with the sys_enter_execve event
//
int main(int argc, char *argv[]) {
	char* bpfProgramFilename = "bpf_program.o";
	
	int bpfProgramFileDescriptor = open(bpfProgramFilename, O_RDONLY, 0);
	
	if (bpfProgramFileDescriptor < 0) {
		printf("Error openning bpf_program.o for read: %s\n", strerror(errno));
		return 1;
	}
	
	printf("Opened file descriptor to bpf_program.o, fd: %d\n", bpfProgramFileDescriptor);
	printf("About to initialize libelf library\n");
	
	if (elf_version(EV_CURRENT) == EV_NONE) {
		printf("Error initializing elf library: %s\n", strerror(errno));
		return 1;
	}
	
	printf("Reading bpf_program.o as an Elf file\n");
	
	Elf *elf = elf_begin(bpfProgramFileDescriptor, ELF_C_READ, NULL);

	if (!elf) {
		printf("Error reading %s as elf file %s\n", bpfProgramFilename, strerror(errno));
		return 1;
	}
	
	printf("Successfully read bpf_program.o as an Elf file\n");
	
	GElf_Ehdr elfHeader;
	
	if (gelf_getehdr(elf, &elfHeader) != &elfHeader) {
		printf("Error reading elf headers\n");
		return 1;
	}
	
	printf("Elf file contains %d section, looking for the bpf code section\n", elfHeader.e_shnum);
	
	struct bpf_insn *bpfProgramInstuctions = NULL;
	size_t bpfProgramInstuctionsCount;
	
	for (int sectionIndex = 1; sectionIndex < elfHeader.e_shnum; sectionIndex++) {
		char *sectionName;
		GElf_Shdr sectionHeader;
		Elf_Data *sectionData;
		
		if (get_elf_section(elf, sectionIndex, &elfHeader, &sectionName, &sectionHeader, &sectionData)) {
			continue;
		}
		
		if (strcmp(sectionName, ".text") != 0) {
			continue;
		}
		
		bpfProgramInstuctions = sectionData->d_buf;
		bpfProgramInstuctionsCount = sectionData->d_size / sizeof(struct bpf_insn);
		break;
	}
	
	if (bpfProgramInstuctions == NULL) {
		printf("Unable to find .text section in bpf_program.o\n");
		return 1;
	}
	
	printf("Successfully read bpf code with %zd instuctions\n", bpfProgramInstuctionsCount);
		
	char log_buffer[1024] = {0};
	int loadedBpfDescriptor = bpf_load_program(BPF_PROG_TYPE_TRACEPOINT, bpfProgramInstuctions, bpfProgramInstuctionsCount, "GPL", 0, log_buffer, sizeof(log_buffer));
	
	if (loadedBpfDescriptor < 0) {
		printf("Error loading bpf program into the kernel %d %s %s\n", loadedBpfDescriptor, strerror(errno), log_buffer);
		return 1;
	}
	
	printf("Successfully loaded bpf program into the kernel, fd: %d\n", loadedBpfDescriptor);
	
	struct perf_event_attr perfEventAttributes = {};

	perfEventAttributes.type = PERF_TYPE_TRACEPOINT;
	perfEventAttributes.sample_type = PERF_SAMPLE_RAW;
	perfEventAttributes.sample_period = 1;
	perfEventAttributes.wakeup_events = 1;
	
	int eventId = readFile("/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/id");
	
	if (eventId < 0) {
		return 1;
	}
	
	perfEventAttributes.config = eventId;
	
	printf("About to open sys_enter_execve event with id: %llu\n", perfEventAttributes.config);
	
	int perfEvenDescriptor = sys_perf_event_open(&perfEventAttributes, -1/*pid*/, 0/*cpu*/, -1/*group_fd*/, 0);
	
	if (perfEvenDescriptor < 0) {
		printf("Error openning perf event %d %s\n", perfEvenDescriptor, strerror(errno));
		return 1;
	}
	
	printf("Successfully opened perf event, fd: %d\n", perfEvenDescriptor);
	
	int enableEventError = ioctl(perfEvenDescriptor, PERF_EVENT_IOC_ENABLE, 0);
	
	if (enableEventError < 0) {
		printf("Error enabling perf event %llu (error: %d)\n", perfEventAttributes.config, enableEventError);
		return 1;
	}
	
	int attachingBpfError = ioctl(perfEvenDescriptor, PERF_EVENT_IOC_SET_BPF, loadedBpfDescriptor);
	
	if (attachingBpfError < 0) {
		printf("Error attaching bpf to event %d %d\n", perfEvenDescriptor, loadedBpfDescriptor);
		return 1;
	}
	
	printf("\nBPF is loaded and enabled\n\trun 'cat /sys/kernel/debug/tracing/trace_pipe'\n\n\tThen from other terminal start new processes...\n");
	
	getchar();
	return 0;
}
