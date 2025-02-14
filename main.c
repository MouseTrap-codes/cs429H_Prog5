#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <regex.h>
#include "uthash.h"

// ---------------- Label Map ----------------
typedef struct {
    char label[50];
    int address; // e.g., 0x1000 becomes 4096
    UT_hash_handle hh;
} LabelAddress;

static LabelAddress *labelMap = NULL;

void addLabel(const char *label, int address) {
    LabelAddress *entry = (LabelAddress *)malloc(sizeof(LabelAddress));
    if (!entry) {
        fprintf(stderr, "Error: malloc failed in addLabel.\n");
        exit(1);
    }
    strncpy(entry->label, label, sizeof(entry->label) - 1);
    entry->label[sizeof(entry->label) - 1] = '\0';
    entry->address = address;
    HASH_ADD_STR(labelMap, label, entry);
}

LabelAddress *findLabel(const char *label) {
    LabelAddress *entry;
    HASH_FIND_STR(labelMap, label, entry);
    return entry;
}

void freeLabelMap() {
    LabelAddress *cur, *tmp;
    HASH_ITER(hh, labelMap, cur, tmp) {
        HASH_DEL(labelMap, cur);
        free(cur);
    }
}

// ---------------- Utility Functions ----------------
void trim(char *s) {
    // Remove leading whitespace.
    char *p = s;
    while (isspace((unsigned char)*p)) {
        p++;
    }
    if (p != s) {
        memmove(s, p, strlen(p) + 1);
    }
    // Remove trailing whitespace.
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        len--;
    }
}

int parseSigned12(const char *str, int *valueOut) {
    errno = 0;
    long val = strtol(str, NULL, 0);
    if ((errno == ERANGE) || (val < -2048) || (val > 2047)) {
        return 0;
    }
    *valueOut = (int)val;
    return 1;
}

int parseUnsigned12(const char *str, int *valueOut) {
    errno = 0;
    unsigned long val = strtoul(str, NULL, 0);
    if ((errno == ERANGE) || (val > 4095)) {
        return 0;
    }
    *valueOut = (int)val;
    return 1;
}

// ---------------- Pass 1: Build Label Map & Compute PC ----------------
void pass1(const char *filename) {
    FILE *fin = fopen(filename, "r");
    if (!fin) {
        perror("pass1 fopen");
        exit(1);
    }
    enum { NONE, CODE, DATA } section = NONE;
    int pc = 0x1000; // starting address
    char line[1024];

    while (fgets(line, sizeof(line), fin)) {
        line[strcspn(line, "\n")] = '\0';
        trim(line);
        if (line[0] == '\0' || line[0] == ';')
            continue;

        if (line[0] == '.') {
            if (strncmp(line, ".code", 5) == 0) {
                section = CODE;
            } else if (strncmp(line, ".data", 5) == 0) {
                section = DATA;
            }
            continue;
        }

        if (line[0] == ':') {
            char label[50];
            if (sscanf(line + 1, "%49s", label) == 1) {
                addLabel(label, pc);
            }
            continue;
        }

        // Increase PC based on section and mnemonic
        if (section == CODE) {
            char temp[16];
            sscanf(line, "%15s", temp);
            if (strcmp(temp, "ld") == 0) {
                // ld expands to 12 instructions => 12 * 4 = 48 bytes
                pc += 48;
            } else if (strcmp(temp, "push") == 0 || strcmp(temp, "pop") == 0) {
                // push/pop expand to 2 instructions => 2 * 4 = 8 bytes
                pc += 8;
            } else {
                // normal instructions => 4 bytes
                pc += 4;
            }
        } else if (section == DATA) {
            // each data item is 64 bits => 8 bytes
            pc += 8;
        }
    }

    fclose(fin);
}

// ---------------- Binary Conversion ----------------
void intToBinaryStr(unsigned int value, int width, char *outStr) {
    for (int i = width - 1; i >= 0; i--) {
        outStr[width - 1 - i] = ((value >> i) & 1) ? '1' : '0';
    }
    outStr[width] = '\0';
}

// ---------------- Custom Assembly Routines ----------------
// brr: if operand begins with 'r', use opcode 0x9; otherwise, use opcode 0xa.
void assembleBrr(const char *operand, char *binStr) {
    // Skip leading whitespace
    while (isspace((unsigned char)*operand)) {
        operand++;
    }

    int opcode, reg = 0, imm = 0;
    if (operand[0] == 'r') {
        opcode = 0x9;
        reg = (int)strtol(operand + 1, NULL, 0);
    } else {
        opcode = 0xa;
        imm = (int)strtol(operand, NULL, 0);
    }
    unsigned int inst = (opcode << 27) | (reg << 22) | (imm & 0xFFF);
    intToBinaryStr(inst, 32, binStr);
}

// mov: determine form based on operands
void assembleMov(const char *line, char *binStr) {
    char mnemonic[10], token1[64], token2[64];
    if (sscanf(line, "%s %63[^,], %63s", mnemonic, token1, token2) < 3) {
        strcpy(binStr, "ERROR");
        return;
    }
    trim(token1);
    trim(token2);

    int opcode = 0, rd = 0, rs = 0, rt = 0, imm = 0;

    // If token1 looks like '(rD)(L)', it's form 4; else, parse normally.
    if (token1[0] == '(') {
        // Form 4: mov (rD)(L), rS => opcode 0x13
        opcode = 0x13;
        char regBuf[16], offBuf[16];
        // find "r" inside "(rD)..."
        char *p1 = strchr(token1, 'r');
        if (!p1) {
            strcpy(binStr, "ERROR");
            return;
        }
        // read the register number
        sscanf(p1, "r%[^)]", regBuf);
        rd = (int)strtol(regBuf, NULL, 0);

        // find the offset part
        char *p2 = strchr(p1, '(');
        if (!p2) {
            strcpy(binStr, "ERROR");
            return;
        }
        sscanf(p2, "(%[^)])", offBuf);
        imm = (int)strtol(offBuf, NULL, 0);

        // token2 must be "rS"
        if (token2[0] == 'r') {
            rs = (int)strtol(token2 + 1, NULL, 0);
        } else {
            strcpy(binStr, "ERROR");
            return;
        }
    } else {
        // If token1 is "rD"
        if (token1[0] != 'r') {
            strcpy(binStr, "ERROR");
            return;
        }
        rd = (int)strtol(token1 + 1, NULL, 0);

        if (token2[0] == '(') {
            // Form 1: mov rD, (rS)(L) => opcode 0x10
            opcode = 0x10;
            char regBuf[16], offBuf[16];
            char *p1 = strchr(token2, 'r');
            if (!p1) {
                strcpy(binStr, "ERROR");
                return;
            }
            sscanf(p1, "r%[^)]", regBuf);
            rs = (int)strtol(regBuf, NULL, 0);

            char *p2 = strchr(p1, '(');
            if (!p2) {
                strcpy(binStr, "ERROR");
                return;
            }
            sscanf(p2, "(%[^)])", offBuf);
            imm = (int)strtol(offBuf, NULL, 0);
        } else if (token2[0] == 'r') {
            // Form 2: mov rD, rS => opcode 0x11
            opcode = 0x11;
            rs = (int)strtol(token2 + 1, NULL, 0);
        } else {
            // Form 3: mov rD, L => opcode 0x12
            opcode = 0x12;
            imm = (int)strtol(token2, NULL, 0);
        }
    }

    unsigned int inst = (opcode << 27) | (rd << 22) | (rs << 17) | (rt << 12) | (imm & 0xFFF);
    intToBinaryStr(inst, 32, binStr);
}

// ---------------- Instruction Table for Standard Instructions ----------------
typedef struct {
    char name[16];
    int opcode;
    const char *format; // e.g., "rd rs rt", "rd L", etc.
    UT_hash_handle hh;
} InstructionEntry;

static InstructionEntry *instMap = NULL;

void addInst(const char *name, int opcode, const char *format) {
    InstructionEntry *e = (InstructionEntry *)malloc(sizeof(InstructionEntry));
    if (!e) {
        fprintf(stderr, "malloc error\n");
        exit(1);
    }
    strncpy(e->name, name, sizeof(e->name) - 1);
    e->name[sizeof(e->name) - 1] = '\0';
    e->opcode = opcode;
    e->format = format;
    HASH_ADD_STR(instMap, name, e);
}

void populateInstMap() {
    instMap = NULL;
    addInst("add",   0x18, "rd rs rt");
    addInst("addi",  0x19, "rd L");
    addInst("sub",   0x1a, "rd rs rt");
    addInst("subi",  0x1b, "rd L");
    addInst("mul",   0x1c, "rd rs rt");
    addInst("div",   0x1d, "rd rs rt");
    addInst("and",   0x0,  "rd rs rt");
    addInst("or",    0x1,  "rd rs rt");
    addInst("xor",   0x2,  "rd rs rt");
    addInst("not",   0x3,  "rd rs");
    addInst("shftr", 0x4,  "rd rs rt");
    addInst("shftri",0x5,  "rd L");
    addInst("shftl", 0x6,  "rd rs rt");
    addInst("shftli",0x7,  "rd L");
    addInst("br",    0x8,  "rd");
    addInst("call",  0xc,  "rd rs rt");
    addInst("return",0xd,  "");
    addInst("brgt",  0xe,  "rd rs rt");
    // "priv" used for special instructions like halt, in/out, etc.
    addInst("priv",  0xf,  "rd rs rt L");
    addInst("addf",  0x14, "rd rs rt");
    addInst("subf",  0x15, "rd rs rt");
    addInst("mulf",  0x16, "rd rs rt");
    addInst("divf",  0x17, "rd rs rt");
}

void freeInstMap() {
    InstructionEntry *cur, *tmp;
    HASH_ITER(hh, instMap, cur, tmp) {
        HASH_DEL(instMap, cur);
        free(cur);
    }
}

// Assemble standard instructions using the instMap
void assembleStandard(const char *line, char *binStr) {
    char mnemonic[16], op1[16], op2[16], op3[16];
    int num = sscanf(line, "%15s %15s %15s %15s", mnemonic, op1, op2, op3);

    InstructionEntry *e = NULL;
    HASH_FIND_STR(instMap, mnemonic, e);
    if (!e) {
        strcpy(binStr, "ERROR");
        return;
    }
    int opcode = e->opcode, rd = 0, rs = 0, rt = 0, imm = 0;

    if (strcmp(e->format, "rd rs rt") == 0 && num >= 4) {
        rd = (op1[0] == 'r') ? (int)strtol(op1 + 1, NULL, 0) : 0;
        rs = (op2[0] == 'r') ? (int)strtol(op2 + 1, NULL, 0) : 0;
        rt = (op3[0] == 'r') ? (int)strtol(op3 + 1, NULL, 0) : 0;
    }
    else if (strcmp(e->format, "rd L") == 0 && num >= 3) {
        rd = (op1[0] == 'r') ? (int)strtol(op1 + 1, NULL, 0) : 0;
        imm = (int)strtol(op2, NULL, 0);
    }
    else if (strcmp(e->format, "rd rs") == 0 && num >= 3) {
        rd = (op1[0] == 'r') ? (int)strtol(op1 + 1, NULL, 0) : 0;
        rs = (op2[0] == 'r') ? (int)strtol(op2 + 1, NULL, 0) : 0;
    }
    else if (strcmp(e->format, "") == 0) {
        // e.g., "return" (no operands)
    }
    else {
        strcpy(binStr, "ERROR");
        return;
    }

    unsigned int inst = (opcode << 27) | (rd << 22) | (rs << 17) | (rt << 12) | (imm & 0xFFF);
    intToBinaryStr(inst, 32, binStr);
}

// If mnemonic is "mov" or "brr", use custom routines; otherwise, standard.
void assembleInstruction(const char *line, char *binStr) {
    char mnemonic[16];
    sscanf(line, "%15s", mnemonic);

    if (strcmp(mnemonic, "mov") == 0) {
        assembleMov(line, binStr);
    }
    else if (strcmp(mnemonic, "brr") == 0) {
        // Expect "brr <operand>"
        char dummy[16], operand[64];
        if (sscanf(line, "%15s %63s", dummy, operand) < 2) {
            strcpy(binStr, "ERROR");
            return;
        }
        assembleBrr(operand, binStr);
    }
    else {
        assembleStandard(line, binStr);
    }
}

// ---------------- Macro Expansion ----------------
// This function uses POSIX regex functions to expand macros:
// (ld, push, pop, in, out, clr, halt)
void parseMacro(const char *line, FILE *fout) {
    regex_t regex;
    regmatch_t matches[3];
    char op[16];

    if (sscanf(line, "%15s", op) != 1) {
        fprintf(fout, "%s\n", line);
        return;
    }

    // ---- LD macro ----
    if (!strcmp(op, "ld")) {
        // Pattern: "ld r<regNum> ,?:?<immediateOrLabel>"
        const char *pattern = "^[[:space:]]*ld[[:space:]]+r([0-9]+)[[:space:]]*,?[[:space:]]*:?(\\S+)[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(fout, "%s\n", line);
            return;
        }
        if (regexec(&regex, line, 3, matches, 0) == 0) {
            char regBuf[16], immBuf[64];
            int rD;
            uint64_t imm;
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';
            rD = (int)strtol(regBuf, NULL, 0);

            len = matches[2].rm_eo - matches[2].rm_so;
            strncpy(immBuf, line + matches[2].rm_so, len);
            immBuf[len] = '\0';

            // If immBuf doesn't start with digit, treat as label
            if (immBuf[0] < '0' || immBuf[0] > '9') {
                LabelAddress *entry = findLabel(immBuf);
                if (!entry) {
                    fprintf(stderr, "Error: label %s not found\n", immBuf);
                    regfree(&regex);
                    return;
                }
                imm = entry->address;
            } else {
                errno = 0;
                char *endptr = NULL;
                uint64_t tmpVal = strtoull(immBuf, &endptr, 0);
                if (errno == ERANGE) {
                    fprintf(stderr, "Error: ld immediate out of range => %s\n", immBuf);
                    regfree(&regex);
                    return;
                }
                imm = tmpVal;
            }

            // Expand ld into instructions
            fprintf(fout, "xor r%d r%d r%d\n", rD, rD, rD);
            unsigned long long top12  = (imm >> 52) & 0xFFF;
            unsigned long long mid12a = (imm >> 40) & 0xFFF;
            unsigned long long mid12b = (imm >> 28) & 0xFFF;
            unsigned long long mid12c = (imm >> 16) & 0xFFF;
            unsigned long long mid4   = (imm >>  4) & 0xFFF;
            unsigned long long last4  = imm & 0xF;

            fprintf(fout, "addi r%d %llu\n", rD, top12);
            fprintf(fout, "shftli r%d 12\n", rD);

            fprintf(fout, "addi r%d %llu\n", rD, mid12a);
            fprintf(fout, "shftli r%d 12\n", rD);

            fprintf(fout, "addi r%d %llu\n", rD, mid12b);
            fprintf(fout, "shftli r%d 12\n", rD);

            fprintf(fout, "addi r%d %llu\n", rD, mid12c);
            fprintf(fout, "shftli r%d 12\n", rD);

            fprintf(fout, "addi r%d %llu\n", rD, mid4);
            fprintf(fout, "shftli r%d 4\n", rD);

            fprintf(fout, "addi r%d %llu\n", rD, last4);
        } else {
            fprintf(fout, "%s\n", line);
        }
        regfree(&regex);
    }
    // ---- PUSH macro ----
    else if (!strcmp(op, "push")) {
        const char *pattern = "^[[:space:]]*push[[:space:]]+r([0-9]+)[[:space:]]*,?[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(fout, "%s\n", line);
            return;
        }
        if (regexec(&regex, line, 2, matches, 0) == 0) {
            char regBuf[16];
            int rD;
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';
            rD = (int)strtol(regBuf, NULL, 0);

            // Macro expansion
            fprintf(fout, "mov (r31)(-8) r%d\n", rD);
            fprintf(fout, "subi r31 8\n");
        } else {
            fprintf(fout, "%s\n", line);
        }
        regfree(&regex);
    }
    // ---- POP macro ----
    else if (!strcmp(op, "pop")) {
        const char *pattern = "^[[:space:]]*pop[[:space:]]+r([0-9]+)[[:space:]]*,?[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(fout, "%s\n", line);
            return;
        }
        if (regexec(&regex, line, 2, matches, 0) == 0) {
            char regBuf[16];
            int rD;
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';
            rD = (int)strtol(regBuf, NULL, 0);

            // Macro expansion
            fprintf(fout, "mov r%d (r31)(0)\n", rD);
            fprintf(fout, "addi r31 8\n");
        } else {
            fprintf(fout, "%s\n", line);
        }
        regfree(&regex);
    }
    // ---- IN macro ----
    else if (!strcmp(op, "in")) {
        const char *pattern = "^[[:space:]]*in[[:space:]]+r([0-9]+)[[:space:]]*,?[[:space:]]*r([0-9]+)[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(fout, "%s\n", line);
            return;
        }
        if (regexec(&regex, line, 3, matches, 0) == 0) {
            char regBuf[16], regBuf2[16];
            int rD, rS;
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';

            len = matches[2].rm_eo - matches[2].rm_so;
            strncpy(regBuf2, line + matches[2].rm_so, len);
            regBuf2[len] = '\0';

            rD = (int)strtol(regBuf, NULL, 0);
            rS = (int)strtol(regBuf2, NULL, 0);

            // Use "priv" with immediate 3 for "in"
            fprintf(fout, "priv r%d r%d r0 3\n", rD, rS);
        } else {
            fprintf(fout, "%s\n", line);
        }
        regfree(&regex);
    }
    // ---- OUT macro ----
    else if (!strcmp(op, "out")) {
        const char *pattern = "^[[:space:]]*out[[:space:]]+r([0-9]+)[[:space:]]*,?[[:space:]]*r([0-9]+)[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(fout, "%s\n", line);
            return;
        }
        if (regexec(&regex, line, 3, matches, 0) == 0) {
            char regBuf[16], regBuf2[16];
            int rD, rS;
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';

            len = matches[2].rm_eo - matches[2].rm_so;
            strncpy(regBuf2, line + matches[2].rm_so, len);
            regBuf2[len] = '\0';

            rD = (int)strtol(regBuf, NULL, 0);
            rS = (int)strtol(regBuf2, NULL, 0);

            // Use "priv" with immediate 4 for "out"
            fprintf(fout, "priv r%d r%d r0 4\n", rD, rS);
        } else {
            fprintf(fout, "%s\n", line);
        }
        regfree(&regex);
    }
    // ---- CLR macro ----
    else if (!strcmp(op, "clr")) {
        const char *pattern = "^[[:space:]]*clr[[:space:]]+r([0-9]+)[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(fout, "%s\n", line);
            return;
        }
        if (regexec(&regex, line, 2, matches, 0) == 0) {
            char regBuf[16];
            int rD;
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';
            rD = (int)strtol(regBuf, NULL, 0);

            // Macro expansion => xor rD,rD,rD
            fprintf(fout, "xor r%d r%d r%d\n", rD, rD, rD);
        } else {
            fprintf(fout, "%s\n", line);
        }
        regfree(&regex);
    }
    // ---- HALT macro ----
    else if (!strcmp(op, "halt")) {
        const char *pattern = "^[[:space:]]*halt[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(fout, "%s\n", line);
            return;
        }
        if (regexec(&regex, line, 0, NULL, 0) == 0) {
            // Macro expansion => priv r0 r0 r0 0
            fprintf(fout, "priv r0 r0 r0 0\n");
        } else {
            fprintf(fout, "%s\n", line);
        }
        regfree(&regex);
    }
    // ---- Otherwise pass through ----
    else {
        fprintf(fout, "%s\n", line);
    }
}

// ---------------- Final Assembly Pass ----------------
void finalAssemble(const char *infile, const char *outfile) {
    FILE *fin = fopen(infile, "r");
    if (!fin) {
        perror("finalAssemble fopen");
        exit(1);
    }
    FILE *fout = fopen(outfile, "w");
    if (!fout) {
        perror("finalAssemble output fopen");
        fclose(fin);
        exit(1);
    }

    enum { CODE, DATA } currentSection = CODE;
    char line[1024];
    char assembled[128];

    while (fgets(line, sizeof(line), fin)) {
        line[strcspn(line, "\n")] = '\0';
        trim(line);
        if (line[0] == '\0' || line[0] == ';')
            continue;

        if (line[0] == '.') {
            if (strcmp(line, ".code") == 0) {
                currentSection = CODE;
            } else if (strcmp(line, ".data") == 0) {
                currentSection = DATA;
            }
            continue;
        }

        if (line[0] == ':') {
            // label line (already handled in pass1)
            continue;
        }

        // Label substitution: replace ":<label>" with its address in hex
        char *col = strchr(line, ':');
        if (col) {
            char lab[50];
            if (sscanf(col + 1, "%49s", lab) == 1) {
                LabelAddress *entry = findLabel(lab);
                if (entry) {
                    *col = '\0';
                    char temp[128];
                    sprintf(temp, "%s0x%x", line, entry->address);
                    strcpy(line, temp);
                }
            }
        }

        if (currentSection == CODE) {
            // Check if it's a macro instruction that needs expansion
            char token[16];
            sscanf(line, "%15s", token);

            if ((strcmp(token, "ld") == 0)   ||
                (strcmp(token, "push") == 0) ||
                (strcmp(token, "pop") == 0)  ||
                (strcmp(token, "in") == 0)   ||
                (strcmp(token, "out") == 0)  ||
                (strcmp(token, "clr") == 0)  ||
                (strcmp(token, "halt") == 0))
            {
                // Expand macro into multiple lines
                char macroExp[2048] = "";
                FILE *tempStream = fmemopen(macroExp, sizeof(macroExp), "w");
                if (!tempStream) {
                    perror("fmemopen");
                    exit(1);
                }

                // Parse macros & write expansions to tempStream
                parseMacro(line, tempStream);
                fflush(tempStream);
                fclose(tempStream);

                // Now read those expanded lines & assemble each
                char *expLine = strtok(macroExp, "\n");
                while (expLine) {
                    trim(expLine);
                    if (strlen(expLine) > 0) {
                        assembleInstruction(expLine, assembled);
                        trim(assembled);
                        fprintf(fout, "%s\n", assembled);
                    }
                    expLine = strtok(NULL, "\n");
                }
            }
            else if (strncmp(token, "mov", 3) == 0) {
                // Directly assemble mov
                assembleMov(line, assembled);
                trim(assembled);
                fprintf(fout, "%s\n", assembled);
            }
            else if (strncmp(token, "brr", 3) == 0) {
                // Directly assemble brr
                assembleBrr(line + 4, assembled);
                trim(assembled);
                fprintf(fout, "%s\n", assembled);
            }
            else {
                // Standard instruction
                assembleInstruction(line, assembled);
                trim(assembled);
                fprintf(fout, "%s\n", assembled);
            }
        }
        else {
            // DATA section => treat line as a 64-bit integer
            uint64_t dVal = strtoull(line, NULL, 0);
            char binData[65];
            for (int i = 63; i >= 0; i--) {
                binData[63 - i] = ((dVal >> i) & 1) ? '1' : '0';
            }
            binData[64] = '\0';
            trim(binData);
            fprintf(fout, "%s\n", binData);
        }
    }

    fclose(fin);
    fclose(fout);
}

// ---------------- main ----------------
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <assembly_file> <output_file>\n", argv[0]);
        return 1;
    }
    // Pass 1: Build label mapping
    pass1(argv[1]);

    // Populate the instruction table
    populateInstMap();

    // Final assembly: write final binary directly
    finalAssemble(argv[1], argv[2]);

    // Clean up
    freeInstMap();
    freeLabelMap();
    return 0;
}
