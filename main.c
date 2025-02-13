#include <stdio.h>      // Standard I/O (printf, fprintf, fopen, etc.)
#include <stdlib.h>     // Memory allocation (malloc, free), exit handling
#include <string.h>     // String manipulation (strcpy, strcmp, strncpy, sscanf)
#include <fcntl.h>      // File control (open, O_RDONLY)
#include <sys/mman.h>   // Memory mapping (mmap, munmap)
#include <sys/stat.h>   // File statistics (fstat)
#include <unistd.h>     // Close file descriptor (close)
#include <ctype.h>      // Character validation (isdigit)
#include "uthash.h"     // uthash provides the hash table macros

/* Define a structure for an instruction entry using uthash */
typedef struct {
    char name[16];         // Key: instruction name (e.g., "add", "subi")
    int opcode;            // Binary opcode for the instruction
    const char *format;    // Format description (e.g., "rd rs rt", "rd L")
    UT_hash_handle hh;     // makes this structure hashable
} InstructionEntry;

/* Global instruction map (hash table) */
InstructionEntry *instruction_map = NULL;

/* Add an instruction to the uthash table */
void addInstruction(const char *instr, int opcode, const char *format) {
    InstructionEntry *entry = (InstructionEntry *)malloc(sizeof(InstructionEntry));
    if (!entry) {
        fprintf(stderr, "Error: malloc failed\n");
        return;
    }
    /* Copy the instruction name into the fixed-size key field */
    strncpy(entry->name, instr, sizeof(entry->name));
    entry->name[sizeof(entry->name) - 1] = '\0';
    entry->opcode = opcode;
    entry->format = format;  // Point to constant string
    HASH_ADD_STR(instruction_map, name, entry);
}

/* Populate the instruction table with Tinker instructions */
void populateTinkerInstruction() {
    /* Initialize the hash table pointer to NULL */
    instruction_map = NULL;

    // Integer arithmetic instructions
    addInstruction("add",   0x18, "rd rs rt");
    addInstruction("addi",  0x19, "rd L");
    addInstruction("sub",   0x1a, "rd rs rt");
    addInstruction("subi",  0x1b, "rd L");
    addInstruction("mul",   0x1c, "rd rs rt");
    addInstruction("div",   0x1d, "rd rs rt");

    // Logic instructions
    addInstruction("and",   0x0, "rd rs rt");
    addInstruction("or",    0x1, "rd rs rt");
    addInstruction("xor",   0x2, "rd rs rt");
    addInstruction("not",   0x3, "rd rs");
    addInstruction("shftr", 0x4, "rd rs rt");
    addInstruction("shftri",0x5, "rd L");
    addInstruction("shftl", 0x6, "rd rs rt");
    addInstruction("shftli",0x7, "rd L");

    // Control instructions
    addInstruction("br",    0x8, "rd");
    addInstruction("brr",   0x9, "rd");
    addInstruction("brrL",  0xa, "L");
    addInstruction("brnz",  0xb, "rd rs");
    addInstruction("call",  0xc, "rd rs rt");
    addInstruction("return",0xd, "");
    addInstruction("brgt",  0xe, "rd rs rt");

    // Privileged instructions
    addInstruction("priv0", 0x0, "rd rs rt L");  // Halt
    addInstruction("priv1", 0x1, "rd rs rt L");  // Trap
    addInstruction("priv2", 0x2, "rd rs rt L");  // RTE
    addInstruction("priv3", 0x3, "rd rs rt L");  // Input

    // Data movement instructions
    addInstruction("mov",   0x10, "rd rs L");
    addInstruction("movr",  0x11, "rd rs");
    addInstruction("movL",  0x12, "rd L");
    addInstruction("movM",  0x13, "rd rs L");

    // Floating point instructions
    addInstruction("addf",  0x14, "rd rs rt");
    addInstruction("subf",  0x15, "rd rs rt");
    addInstruction("mulf",  0x16, "rd rs rt");
    addInstruction("divf",  0x17, "rd rs rt");
}

/* Free the allocated memory in the instruction hash table */
void free_instruction_table() {
    InstructionEntry *current_entry, *tmp;
    HASH_ITER(hh, instruction_map, current_entry, tmp) {
        HASH_DEL(instruction_map, current_entry);
        free(current_entry);
    }
}

/* Parse a register string (e.g., "r3") into its numeric value */
int parse_register(const char *reg) {
    if (reg[0] == 'r') {
        return atoi(reg + 1); // Convert "r3" -> 3
    }
    return -1; // Invalid register
}

/* Assemble a single line of assembly into a 32-bit binary string */
char *assemble_instruction(const char *assembly_line) {
    static char binary_code[33];  // 32-bit binary + null terminator
    char instr[10], op1[10], op2[10], op3[10];

    int num_parsed = sscanf(assembly_line, "%s %s %s %s", instr, op1, op2, op3);

    // Handle "hlt" instruction
    if (strcmp(instr, "hlt") == 0) {
        strcpy(binary_code, "00000000000000000000000000000000");
        return binary_code;
    }

    // Look up the instruction in the hash table
    InstructionEntry *entry = NULL;
    HASH_FIND_STR(instruction_map, instr, entry);
    if (!entry) {
        printf("Error: Unknown instruction %s\n", instr);
        return NULL;
    }

    // Extract opcode and operands
    int opcode = entry->opcode;
    int rd = 0, rs = 0, rt = 0, L = 0;

    if (strcmp(entry->format, "rd rs rt") == 0 && num_parsed == 4) {
        rd = parse_register(op1);
        rs = parse_register(op2);
        rt = parse_register(op3);
    } else if (strcmp(entry->format, "rd L") == 0 && num_parsed == 3) {
        rd = parse_register(op1);
        L = atoi(op2);
    } else if (strcmp(entry->format, "rd rs") == 0 && num_parsed == 3) {
        rd = parse_register(op1);
        rs = parse_register(op2);
    } else {
        printf("Error: Invalid operands for %s\n", instr);
        return NULL;
    }

    // Construct 32-bit binary instruction:
    //   opcode (8 bits) | rd (5 bits) | rs (5 bits) | rt (5 bits) | L (9 bits)
    int binary_value = (opcode << 24) | (rd << 19) | (rs << 14) | (rt << 9) | (L & 0x1FF);

    // Convert to binary string
    for (int i = 31; i >= 0; i--) {
        binary_code[31 - i] = ((binary_value >> i) & 1) + '0';
    }
    binary_code[32] = '\0';

    return binary_code;
}

/* Parse the input file and assemble each line into binary code */
void parse_and_assemble_file(const char *input_filename, const char *output_filename) {
    int fd = open(input_filename, O_RDONLY);
    if (fd == -1) {
        perror("Error opening input file");
        return;
    }

    // Get the file size
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        perror("Error getting file size");
        close(fd);
        return;
    }
    size_t file_size = sb.st_size;

    // Memory-map the file
    char *mapped = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        perror("Error mmapping input file");
        close(fd);
        return;
    }

    // Open the output file
    FILE *output_file = fopen(output_filename, "w");
    if (!output_file) {
        perror("Error opening output file");
        munmap(mapped, file_size);
        close(fd);
        return;
    }

    // Iterate over the file content line by line
    char *start = mapped;
    for (size_t i = 0; i < file_size; i++) {
        if (mapped[i] == '\n' || i == file_size - 1) {
            size_t line_length = &mapped[i] - start + 1;

            // Copy the line into a null-terminated string
            char line[line_length + 1];
            memcpy(line, start, line_length);
            line[line_length] = '\0';  // Null-terminate the string

            // Assemble the line
            char *binary = assemble_instruction(line);
            if (binary) {
                fprintf(output_file, "%s -> %s\n", line, binary);
            } else {
                fprintf(output_file, "Error: Could not assemble line: %s\n", line);
            }

            // Move to the next line
            start = &mapped[i] + 1;
        }
    }

    // Cleanup
    fclose(output_file);
    munmap(mapped, file_size);
    close(fd);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <assembly_file> <output_file>\n", argv[0]);
        return 1;
    }

    populateTinkerInstruction();
    parse_and_assemble_file(argv[1], argv[2]);
    free_instruction_table();

    return 0;
}
