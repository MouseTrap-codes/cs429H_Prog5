#include <czmq.h>
#include <stdio.h>
#include <stdlib.h>

/* Global instruction map */
zhash_t *instruction_map;

/* Define a structure for a Tinker instruction */
typedef struct {
    int opcode;         // Binary opcode for the instruction
    const char *format; // Format description (e.g., "rd rs rt", "rd L")
} TinkerInstruction;

/* Add an instruction to the zhash table */
void addInstruction(const char *instr, int opcode, const char *format) {
    TinkerInstruction *entry = (TinkerInstruction *)malloc(sizeof(TinkerInstruction));
    if (!entry) {
        fprintf(stderr, "Error: malloc failed\n");
        return;
    }
    entry->opcode = opcode;
    entry->format = format;  // No need to copy since it's a constant string
    zhash_insert(instruction_map, instr, entry);
}

/* Populate the instruction table */
void populateTinkerInstruction() {
    instruction_map = zhash_new();

    // Integer arithmetic instructions
    addInstruction("add", 0x18, "rd rs rt");
    addInstruction("addi", 0x19, "rd L");
    addInstruction("sub", 0x1a, "rd rs rt");
    addInstruction("subi", 0x1b, "rd L");
    addInstruction("mul", 0x1c, "rd rs rt");
    addInstruction("div", 0x1d, "rd rs rt");

    // Logic instructions
    addInstruction("and", 0x0, "rd rs rt");
    addInstruction("or", 0x1, "rd rs rt");
    addInstruction("xor", 0x2, "rd rs rt");
    addInstruction("not", 0x3, "rd rs");
    addInstruction("shftr", 0x4, "rd rs rt");
    addInstruction("shftri", 0x5, "rd L");
    addInstruction("shftl", 0x6, "rd rs rt");
    addInstruction("shftli", 0x7, "rd L");

    // Control instructions
    addInstruction("br", 0x8, "rd");
    addInstruction("brr", 0x9, "rd");
    addInstruction("brrL", 0xa, "L");
    addInstruction("brnz", 0xb, "rd rs");
    addInstruction("call", 0xc, "rd rs rt");
    addInstruction("return", 0xd, "");
    addInstruction("brgt", 0xe, "rd rs rt");

    // Privileged instructions
    addInstruction("priv0", 0x0, "rd rs rt L");  // Halt
    addInstruction("priv1", 0x1, "rd rs rt L");  // Trap
    addInstruction("priv2", 0x2, "rd rs rt L");  // RTE
    addInstruction("priv3", 0x3, "rd rs rt L");  // Input

    // Data movement instructions
    addInstruction("mov", 0x10, "rd rs L");
    addInstruction("movr", 0x11, "rd rs");
    addInstruction("movL", 0x12, "rd L");
    addInstruction("movM", 0x13, "rd rs L");

    // Floating point instructions
    addInstruction("addf", 0x14, "rd rs rt");
    addInstruction("subf", 0x15, "rd rs rt");
    addInstruction("mulf", 0x16, "rd rs rt");
    addInstruction("divf", 0x17, "rd rs rt");
}

/* Free the allocated memory in the table */
void free_instruction_table() {
    if (!instruction_map) return;

    const char *key;
    void *value;
    zhash_foreach(instruction_map, key, value) {
        free(value);  // Free each instruction entry
    }
    zhash_destroy(&instruction_map);
}

int parse_register(const char *reg) {
    if (reg[0] == 'r') {
        return atoi(reg + 1); // Convert r3 -> 3
    }
    return -1; // Invalid register
}

char *assemble_instruction(const char *assembly_line) {
    static char binary_code[33];  // 32-bit binary + null terminator
    char instr[10], op1[10], op2[10], op3[10];

    int num_parsed = sscanf(assembly_line, "%s %s %s %s", instr, op1, op2, op3);

    // Handle "hlt" instruction
    if (strcmp(instr, "hlt") == 0) {
        strcpy(binary_code, "00000000000000000000000000000000");
        return binary_code;
    }

    // Look up the instruction
    InstructionEntry *entry = (InstructionEntry *)zhash_lookup(instruction_map, instr);
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

    // Construct 32-bit binary instruction
    int binary_value = (opcode << 24) | (rd << 19) | (rs << 14) | (rt << 9) | (L & 0x1FF);

    // Convert to binary string
    for (int i = 31; i >= 0; i--) {
        binary_code[31 - i] = ((binary_value >> i) & 1) + '0';
    }
    binary_code[32] = '\0';

    return binary_code;
}


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

    // Open output file
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

            // Pass the line to the assembler function
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

    parse_and_assemble_file(argv[1], argv[2]);
    return 0;
}