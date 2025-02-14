#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include "uthash.h"

// ----- Label Map (for resolving label addresses) -----
typedef struct {
    char label[50];
    int address;  // stored in decimal (e.g., 0x1000 becomes 4096)
    UT_hash_handle hh;
} LabelAddress;

static LabelAddress *labelMap = NULL;

void addLabel(const char *label, int address) {
    LabelAddress *entry = (LabelAddress *)malloc(sizeof(LabelAddress));
    if (!entry) {
        fprintf(stderr, "Error: malloc failed in addLabel.\n");
        exit(1);
    }
    strncpy(entry->label, label, sizeof(entry->label)-1);
    entry->label[sizeof(entry->label)-1] = '\0';
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

// ----- Utility Functions -----
void trim(char *s) {
    char *p = s;
    while (isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p)+1);
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len-1])) {
        s[len-1] = '\0';
        len--;
    }
}

int parseSigned12(const char *str, int *valueOut) {
    errno = 0;
    long val = strtol(str, NULL, 0);
    if ((errno == ERANGE) || (val < -2048) || (val > 2047))
        return 0;
    *valueOut = (int)val;
    return 1;
}

int parseUnsigned12(const char *str, int *valueOut) {
    errno = 0;
    unsigned long val = strtoul(str, NULL, 0);
    if ((errno == ERANGE) || (val > 4095))
        return 0;
    *valueOut = (int)val;
    return 1;
}

// ----- Pass 1: Build label map and compute instruction addresses -----
void pass1(const char *filename) {
    FILE *fin = fopen(filename, "r");
    if (!fin) { perror("pass1 fopen"); exit(1); }
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
            if (sscanf(line+1, "%49s", label) == 1)
                addLabel(label, pc);
            continue;
        }
        // For lines with label references (e.g. "ld r5, :L1"), we do nothing here.
        // Increase PC: in code, most instructions are 4 bytes; ld macro expands to 48 bytes;
        // push/pop expand to 8 bytes; in data, each item is 8 bytes.
        if (section == CODE) {
            // A simple heuristic: if the line starts with "ld" (ignoring whitespace), add 48; if push or pop, add 8; else add 4.
            char temp[16];
            sscanf(line, "%15s", temp);
            if (strcmp(temp, "ld") == 0)
                pc += 48;
            else if (strcmp(temp, "push") == 0 || strcmp(temp, "pop") == 0)
                pc += 8;
            else
                pc += 4;
        } else if (section == DATA) {
            pc += 8;
        }
    }
    fclose(fin);
}

// ----- Custom Assembly Functions -----
// We assume the binary encoding for a 32-bit instruction is:
//   [opcode:5][rd:5][rs:5][rt:5][imm:12]
// For non-immediate instructions the imm field is 0.

// Helper: Convert an integer to a binary string of given width.
void intToBinaryStr(unsigned int value, int width, char *outStr) {
    for (int i = width-1; i >= 0; i--) {
        outStr[width-1-i] = ((value >> i) & 1) ? '1' : '0';
    }
    outStr[width] = '\0';
}

// Custom assembly for brr and mov
// Assemble brr instruction:
void assembleBrr(const char *operand, char *binStr) {
    int opcode, reg = 0, imm = 0;
    if (operand[0]=='r') {
        opcode = 0x9; // form: brr rX
        reg = atoi(operand+1);
    } else {
        opcode = 0xa; // form: brr L
        imm = atoi(operand);
    }
    unsigned int inst = (opcode << 27) | (reg << 22) | (imm & 0xFFF);
    intToBinaryStr(inst, 32, binStr);
}

// Assemble mov instruction:
void assembleMov(const char *line, char *binStr) {
    // Tokenize the line.
    // Expect: "mov <op1>, <op2>" (commas optional)
    char mnemonic[10], token1[64], token2[64];
    if (sscanf(line, "%s %63[^,], %63s", mnemonic, token1, token2) < 3) {
        strcpy(binStr, "ERROR");
        return;
    }
    int opcode = 0, rd = 0, rs = 0, rt = 0, imm = 0;
    // Remove any extraneous spaces.
    trim(token1); trim(token2);
    // Determine form:
    if (token1[0] == '(') {
        // Form 4: mov (rD)(L), rS => opcode 0x13
        opcode = 0x13;
        // token1 format: "(rX)(L)"
        char regBuf[16], offBuf[16];
        char *p1 = strchr(token1, 'r');
        if (!p1) { strcpy(binStr, "ERROR"); return; }
        sscanf(p1, "r%[^)]", regBuf);
        rd = atoi(regBuf);
        char *p2 = strchr(p1, '(');
        if (!p2) { strcpy(binStr, "ERROR"); return; }
        sscanf(p2, "(%[^)])", offBuf);
        imm = atoi(offBuf);
        // token2: should be a register like "rY"
        if (token2[0]=='r')
            rs = atoi(token2+1);
        else { strcpy(binStr, "ERROR"); return; }
        // For form 4, rt is not used.
    } else {
        // token1 must be "rD"
        if (token1[0]!='r') { strcpy(binStr, "ERROR"); return; }
        rd = atoi(token1+1);
        // Now check token2:
        if (token2[0] == '(') {
            // Form 1: mov rD, (rS)(L) => opcode 0x10.
            opcode = 0x10;
            // token2 format: "(rY)(L)"
            char regBuf[16], offBuf[16];
            char *p1 = strchr(token2, 'r');
            if (!p1) { strcpy(binStr, "ERROR"); return; }
            sscanf(p1, "r%[^)]", regBuf);
            rs = atoi(regBuf);
            char *p2 = strchr(p1, '(');
            if (!p2) { strcpy(binStr, "ERROR"); return; }
            sscanf(p2, "(%[^)])", offBuf);
            imm = atoi(offBuf);
            // For form 1, rt is 0.
        } else if (token2[0] == 'r') {
            // Form 2: mov rD, rS => opcode 0x11.
            opcode = 0x11;
            rs = atoi(token2+1);
            // rt remains 0.
        } else {
            // Form 3: mov rD, L => opcode 0x12.
            opcode = 0x12;
            imm = atoi(token2);
        }
    }
    unsigned int inst = (opcode << 27) | (rd << 22) | (rs << 17) | (rt << 12) | (imm & 0xFFF);
    intToBinaryStr(inst, 32, binStr);
}

// Standard assembly for other instructions using instruction_map.
typedef struct {
    char name[16];
    int opcode;
    const char *format; // e.g., "rd rs rt", "rd L", "rd rs"
    UT_hash_handle hh;
} InstructionEntry;

static InstructionEntry *instMap = NULL;

void addInst(const char *name, int opcode, const char *format) {
    InstructionEntry *e = (InstructionEntry *)malloc(sizeof(InstructionEntry));
    if (!e) { fprintf(stderr, "malloc error\n"); exit(1); }
    strncpy(e->name, name, sizeof(e->name)-1);
    e->name[sizeof(e->name)-1] = '\0';
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
    // We handle brr specially.
    addInst("call",  0xc,  "rd rs rt");
    addInst("return",0xd,  "");
    addInst("brgt",  0xe,  "rd rs rt");
    // Halt expansion uses priv.
    addInst("priv",  0xf,  "rd rs rt L");
    // Other instructions:
    addInst("addf",  0x14, "rd rs rt");
    addInst("subf",  0x15, "rd rs rt");
    addInst("mulf",  0x16, "rd rs rt");
    addInst("divf",  0x17, "rd rs rt");
}

// Assemble a non-macro, non-special instruction using the instMap.
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
    if (strcmp(e->format, "rd rs rt") == 0 && num == 4) {
        rd = (op1[0]=='r') ? atoi(op1+1) : 0;
        rs = (op2[0]=='r') ? atoi(op2+1) : 0;
        rt = (op3[0]=='r') ? atoi(op3+1) : 0;
    } else if (strcmp(e->format, "rd L") == 0 && num == 3) {
        rd = (op1[0]=='r') ? atoi(op1+1) : 0;
        imm = atoi(op2);
    } else if (strcmp(e->format, "rd rs") == 0 && num == 3) {
        rd = (op1[0]=='r') ? atoi(op1+1) : 0;
        rs = (op2[0]=='r') ? atoi(op2+1) : 0;
    } else if (strcmp(e->format, "") == 0) {
        // e.g. "return"
    } else {
        strcpy(binStr, "ERROR");
        return;
    }
    unsigned int inst = (opcode << 27) | (rd << 22) | (rs << 17) | (rt << 12) | (imm & 0xFFF);
    intToBinaryStr(inst, 32, binStr);
}

// Custom assembly: if mnemonic is "mov" or "brr", call our custom functions; otherwise, use standard.
void assembleInstruction(const char *line, char *binStr) {
    char mnemonic[16];
    sscanf(line, "%15s", mnemonic);
    if (strcmp(mnemonic, "mov") == 0) {
        assembleMov(line, binStr);
    } else if (strcmp(mnemonic, "brr") == 0) {
        // Expect format: "brr <operand>"
        char dummy[16], operand[16];
        if (sscanf(line, "%15s %15s", dummy, operand) < 2) {
            strcpy(binStr, "ERROR");
            return;
        }
        assembleBrr(operand, binStr);
    } else {
        assembleStandard(line, binStr);
    }
}

// ----- Final Assembly Pass -----
// This function reads the original assembly file, performs macro expansion (in–line),
// label substitution, and writes the final binary to the output file.
// No intermediate file is created.
void finalAssemble(const char *infile, const char *outfile) {
    FILE *fin = fopen(infile, "r");
    if (!fin) { perror("finalAssemble fopen"); exit(1); }
    FILE *fout = fopen(outfile, "w");
    if (!fout) { perror("finalAssemble output fopen"); fclose(fin); exit(1); }
    
    enum { CODE, DATA } currentSection = CODE;
    int lastDirective = -1; // -1: none; 0: code; 1: data.
    char line[1024];
    char assembled[128];
    
    while (fgets(line, sizeof(line), fin)) {
        line[strcspn(line, "\n")] = '\0';
        trim(line);
        if (line[0] == '\0' || line[0] == ';')
            continue;
        if (line[0] == '.') {
            if (strcmp(line, ".code") == 0) {
                // Merge consecutive code segments.
                if (lastDirective != 0) {
                    currentSection = CODE;
                    lastDirective = 0;
                }
            } else if (strcmp(line, ".data") == 0) {
                currentSection = DATA;
                lastDirective = 1;
            }
            continue;
        }
        if (line[0] == ':')
            continue; // label definition line
        
        // Label substitution: if a colon appears later in the line, replace ":<label>" with its address (in decimal).
        char *colon = strchr(line, ':');
        if (colon) {
            char labelName[50];
            if (sscanf(colon+1, "%49s", labelName) == 1) {
                LabelAddress *entry = findLabel(labelName);
                if (entry) {
                    // Replace the colon and label with the resolved address in decimal.
                    *colon = '\0';
                    char temp[128];
                    sprintf(temp, "%s%d", line, entry->address);
                    strcpy(line, temp);
                }
            }
        }
        
        lastDirective = -1; // reset
        
        if (currentSection == CODE) {
            // Check if line is a macro. We consider ld, push, pop, in, out, clr, halt as macros.
            int isMacro = 0;
            char token[16];
            sscanf(line, "%15s", token);
            if ( (strcmp(token, "ld") == 0)  ||
                 (strcmp(token, "push") == 0) ||
                 (strcmp(token, "pop") == 0)  ||
                 (strcmp(token, "in") == 0)   ||
                 (strcmp(token, "out") == 0)  ||
                 (strcmp(token, "clr") == 0)  ||
                 (strcmp(token, "halt") == 0) )
                isMacro = 1;
            
            if (isMacro) {
                // For simplicity, we use the existing parseMacro routine to expand the macro.
                // Instead of writing to an intermediate file, we capture its expansion in a temporary buffer.
                // Here we assume that macro expansion outputs one or more assembly lines separated by newlines.
                // We use a fixed buffer.
                char macroExp[2048] = "";
                // Redirect output temporarily to a memory buffer by using fmemopen.
                FILE *tempStream = fmemopen(macroExp, sizeof(macroExp), "w");
                if (!tempStream) { perror("fmemopen"); exit(1); }
                // Use our existing parseMacro (which writes to a FILE*) to expand the macro.
                // (parseMacro is defined below and writes assembly lines.)
                // Note: parseMacro does not output a newline at the end; we assume it does.
                // We call parseMacro with the original line.
                // (Our parseMacro function is unmodified from earlier.)
                // For simplicity, we use the existing parseMacro.
                extern void parseMacro(const char *, FILE *);
                parseMacro(line, tempStream);
                fflush(tempStream);
                fclose(tempStream);
                // Now macroExp contains one or more assembly lines separated by '\n'.
                char *expLine = strtok(macroExp, "\n");
                while (expLine) {
                    trim(expLine);
                    if (strlen(expLine) > 0) {
                        assembleInstruction(expLine, assembled);
                        fprintf(fout, "%s\n", assembled);
                    }
                    expLine = strtok(NULL, "\n");
                }
            } else {
                // Regular code line.
                assembleInstruction(line, assembled);
                fprintf(fout, "%s\n", assembled);
            }
        } else { // DATA section
            // Each line is a 64-bit data item.
            uint64_t dataVal = strtoull(line, NULL, 0);
            char binStr[65];
            for (int i = 63; i >= 0; i--) {
                binStr[63 - i] = ((dataVal >> i) & 1) ? '1' : '0';
            }
            binStr[64] = '\0';
            fprintf(fout, "%s\n", binStr);
        }
    }
    fclose(fin);
    fclose(fout);
}

// ----- parseMacro (same as before, writing assembly lines) -----
// Note: This function writes assembly lines (one or more) to the given FILE*.
void parseMacro(const char *line, FILE *fout) {
    // We use regex-based macro expansion for ld, push, pop, in, out, clr, halt.
    // For brevity, we include the same implementation as before.
    // (In our implementation, halt expands to "priv r0, r0, r0, 0")
    regex_t regex;
    regmatch_t matches[4];
    char op[16];
    if (sscanf(line, "%15s", op) != 1) {
        fprintf(fout, "\t%s\n", line);
        return;
    }
    if (!strcmp(op, "ld")) {
        const char *pattern = "^[[:space:]]*ld[[:space:]]+r([0-9]+)[[:space:]]*,?[[:space:]]*(:?)([0-9a-fA-FxX:]+)[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(fout, "\t%s\n", line);
            return;
        }
        if (regexec(&regex, line, 4, matches, 0) == 0) {
            char regBuf[16], immBuf[64];
            int rD;
            uint64_t imm;
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';
            rD = atoi(regBuf);
            len = matches[3].rm_eo - matches[3].rm_so;
            strncpy(immBuf, line + matches[3].rm_so, len);
            immBuf[len] = '\0';
            if (immBuf[0] == ':') {
                LabelAddress *entry = findLabel(immBuf + 1);
                if (!entry) {
                    fprintf(stderr, "Error: label %s not found\n", immBuf+1);
                    regfree(&regex);
                    return;
                }
                imm = entry->address;
            } else {
                errno = 0;
                char *endptr = NULL;
                uint64_t tmpVal = strtoull(immBuf, &endptr, 0);
                if (errno == ERANGE) {
                    fprintf(stderr, "Error: ld immediate out of 64-bit range => %s\n", immBuf);
                    regfree(&regex);
                    return;
                }
                imm = tmpVal;
            }
            // Expand ld into 12 instructions.
            fprintf(fout, "\txor r%d, r%d, r%d\n", rD, rD, rD);
            unsigned long long top12  = (imm >> 52) & 0xFFF;
            unsigned long long mid12a = (imm >> 40) & 0xFFF;
            unsigned long long mid12b = (imm >> 28) & 0xFFF;
            unsigned long long mid12c = (imm >> 16) & 0xFFF;
            unsigned long long mid4   = (imm >> 4)  & 0xFFF;
            unsigned long long last4  = imm & 0xF;
            fprintf(fout, "\taddi r%d, %llu\n", rD, top12);
            fprintf(fout, "\tshftli r%d, 12\n", rD);
            fprintf(fout, "\taddi r%d, %llu\n", rD, mid12a);
            fprintf(fout, "\tshftli r%d, 12\n", rD);
            fprintf(fout, "\taddi r%d, %llu\n", rD, mid12b);
            fprintf(fout, "\tshftli r%d, 12\n", rD);
            fprintf(fout, "\taddi r%d, %llu\n", rD, mid12c);
            fprintf(fout, "\tshftli r%d, 12\n", rD);
            fprintf(fout, "\taddi r%d, %llu\n", rD, mid4);
            fprintf(fout, "\tshftli r%d, 4\n", rD);
            fprintf(fout, "\taddi r%d, %llu\n", rD, last4);
        } else {
            fprintf(fout, "\t%s\n", line);
        }
        regfree(&regex);
    }
    else if (!strcmp(op, "push")) {
        const char *pattern = "^[[:space:]]*push[[:space:]]+r([0-9]+)[[:space:]]*,?[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(fout, "\t%s\n", line);
            return;
        }
        if (regexec(&regex, line, 2, matches, 0) == 0) {
            char regBuf[16];
            int rD;
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';
            rD = atoi(regBuf);
            fprintf(fout, "\tmov (r31)(-8), r%d\n", rD);
            fprintf(fout, "\tsubi r31, 8\n");
        } else {
            fprintf(fout, "\t%s\n", line);
        }
        regfree(&regex);
    }
    else if (!strcmp(op, "pop")) {
        const char *pattern = "^[[:space:]]*pop[[:space:]]+r([0-9]+)[[:space:]]*,?[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(fout, "\t%s\n", line);
            return;
        }
        if (regexec(&regex, line, 2, matches, 0) == 0) {
            char regBuf[16];
            int rD;
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';
            rD = atoi(regBuf);
            fprintf(fout, "\tmov r%d, (r31)(0)\n", rD);
            fprintf(fout, "\taddi r31, 8\n");
        } else {
            fprintf(fout, "\t%s\n", line);
        }
        regfree(&regex);
    }
    else if (!strcmp(op, "in")) {
        const char *pattern = "^[[:space:]]*in[[:space:]]+r([0-9]+)[[:space:]]*,?[[:space:]]*r([0-9]+)[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(fout, "\t%s\n", line);
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
            rD = atoi(regBuf);
            rS = atoi(regBuf2);
            if (rD < 0 || rD > 31 || rS < 0 || rS > 31) {
                fprintf(stderr, "Error: register out of range in 'in': %s\n", line);
                regfree(&regex);
                return;
            }
            fprintf(fout, "\tpriv r%d, r%d, r0, 3\n", rD, rS);
        } else {
            fprintf(fout, "\t%s\n", line);
        }
        regfree(&regex);
    }
    else if (!strcmp(op, "out")) {
        const char *pattern = "^[[:space:]]*out[[:space:]]+r([0-9]+)[[:space:]]*,?[[:space:]]*r([0-9]+)[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(fout, "\t%s\n", line);
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
            rD = atoi(regBuf);
            rS = atoi(regBuf2);
            if (rD < 0 || rD > 31 || rS < 0 || rS > 31) {
                fprintf(stderr, "Error: register out of range in 'out': %s\n", line);
                regfree(&regex);
                return;
            }
            fprintf(fout, "\tpriv r%d, r%d, r0, 4\n", rD, rS);
        } else {
            fprintf(fout, "\t%s\n", line);
        }
        regfree(&regex);
    }
    else if (!strcmp(op, "clr")) {
        const char *pattern = "^[[:space:]]*clr[[:space:]]+r([0-9]+)[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(fout, "\t%s\n", line);
            return;
        }
        if (regexec(&regex, line, 2, matches, 0) == 0) {
            char regBuf[16];
            int rD;
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';
            rD = atoi(regBuf);
            fprintf(fout, "\txor r%d, r%d, r%d\n", rD, rD, rD);
        } else {
            fprintf(fout, "\t%s\n", line);
        }
        regfree(&regex);
    }
    else if (!strcmp(op, "halt")) {
        const char *pattern = "^[[:space:]]*halt[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(fout, "\t%s\n", line);
            return;
        }
        if (regexec(&regex, line, 0, NULL, 0) == 0) {
            fprintf(fout, "\tpriv r0, r0, r0, 0\n");
        } else {
            fprintf(fout, "\t%s\n", line);
        }
        regfree(&regex);
    }
    else {
        fprintf(fout, "\t%s\n", line);
    }
}

// ----- Final Assembly Pass (No Intermediate File) -----
void finalAssemble(const char *infile, const char *outfile) {
    FILE *fin = fopen(infile, "r");
    if (!fin) { perror("finalAssemble fopen"); exit(1); }
    FILE *fout = fopen(outfile, "w");
    if (!fout) { perror("finalAssemble output fopen"); fclose(fin); exit(1); }
    
    enum { CODE, DATA } currentSection = CODE;
    int lastDirective = -1; // -1: none; 0: code; 1: data.
    char line[1024];
    char assembled[128];
    
    while (fgets(line, sizeof(line), fin)) {
        line[strcspn(line, "\n")] = '\0';
        trim(line);
        if (line[0] == '\0' || line[0] == ';')
            continue;
        if (line[0] == '.') {
            if (strcmp(line, ".code") == 0) {
                if (lastDirective != 0) {
                    currentSection = CODE;
                    lastDirective = 0;
                }
            } else if (strcmp(line, ".data") == 0) {
                currentSection = DATA;
                lastDirective = 1;
            }
            continue;
        }
        if (line[0] == ':')
            continue;
        // Label substitution: if a colon appears (e.g. "ld r5, :L1"), replace with address.
        char *col = strchr(line, ':');
        if (col) {
            char lab[50];
            if (sscanf(col+1, "%49s", lab) == 1) {
                LabelAddress *entry = findLabel(lab);
                if (entry) {
                    *col = '\0';
                    char temp[128];
                    sprintf(temp, "%s%d", line, entry->address);
                    strcpy(line, temp);
                }
            }
        }
        lastDirective = -1;
        if (currentSection == CODE) {
            // If the line is a macro, use parseMacro to expand it.
            char token[16];
            sscanf(line, "%15s", token);
            if ( (strcmp(token, "ld")==0) ||
                 (strcmp(token, "push")==0) ||
                 (strcmp(token, "pop")==0) ||
                 (strcmp(token, "in")==0) ||
                 (strcmp(token, "out")==0) ||
                 (strcmp(token, "clr")==0) ||
                 (strcmp(token, "halt")==0) )
            {
                // Expand macro into a temporary buffer.
                char macroExp[2048] = "";
                FILE *tempStream = fmemopen(macroExp, sizeof(macroExp), "w");
                if (!tempStream) { perror("fmemopen"); exit(1); }
                parseMacro(line, tempStream);
                fflush(tempStream);
                fclose(tempStream);
                char *expLine = strtok(macroExp, "\n");
                while (expLine) {
                    trim(expLine);
                    if (strlen(expLine) > 0) {
                        // For expanded lines, use custom assembly if needed.
                        assembleInstruction(expLine, assembled);
                        fprintf(fout, "%s\n", assembled);
                    }
                    expLine = strtok(NULL, "\n");
                }
            } else if (strncmp(token, "mov", 3)==0) {
                // Use our custom mov assembler.
                assembleMov(line, assembled);
                fprintf(fout, "%s\n", assembled);
            } else if (strncmp(token, "brr", 3)==0) {
                assembleBrr(line+4, assembled); // token after "brr "
                fprintf(fout, "%s\n", assembled);
            } else {
                // Standard instruction.
                assembleInstruction(line, assembled);
                fprintf(fout, "%s\n", assembled);
            }
        } else { // DATA section
            uint64_t dVal = strtoull(line, NULL, 0);
            char binData[65];
            for (int i = 63; i >= 0; i--) {
                binData[63-i] = ((dVal >> i) & 1) ? '1' : '0';
            }
            binData[64] = '\0';
            fprintf(fout, "%s\n", binData);
        }
    }
    fclose(fin);
    fclose(fout);
}

// ----- main -----
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <assembly_file> <output_file>\n", argv[0]);
        return 1;
    }
    // Pass 1: Build label mapping.
    pass1(argv[1]);
    
    // Populate the instruction table for standard instructions.
    populateInstMap();
    
    // Final assembly: directly write binary to output.
    finalAssemble(argv[1], argv[2]);
    
    freeInstMap:
    {
        // Free instMap
        InstructionEntry *cur, *tmp;
        HASH_ITER(hh, instMap, cur, tmp) {
            HASH_DEL(instMap, cur);
            free(cur);
        }
    }
    
    freeLabelMap();
    return 0;
}
