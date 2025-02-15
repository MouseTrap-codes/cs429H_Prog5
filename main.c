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

// ===================================================================
//                           Label Map
// ===================================================================
typedef struct {
    char label[50];
    int address; // e.g., 0x1000 -> 4096
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

// ===================================================================
//                     Global Error-Handling
// ===================================================================
static FILE *g_fout = NULL;
static char g_outFilename[1024];

// If we detect an error mid-assembly, remove partial .tko and exit.
static void abortAssembly(void) {
    if (g_fout) {
        fclose(g_fout);
        g_fout = NULL;
    }
    unlink(g_outFilename); 
    exit(1);
}

// ===================================================================
//                     Utility Functions
// ===================================================================
void trim(char *s) {
    // Remove leading whitespace
    char *p = s;
    while (isspace((unsigned char)*p)) {
        p++;
    }
    if (p != s) {
        memmove(s, p, strlen(p) + 1);
    }
    // Remove trailing whitespace
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        len--;
    }
}

void intToBinaryStr(unsigned int value, int width, char *outStr) {
    for (int i = width - 1; i >= 0; i--) {
        outStr[width - 1 - i] = ((value >> i) & 1) ? '1' : '0';
    }
    outStr[width] = '\0';
}

uint32_t binStrToUint32(const char *binStr) {
    uint32_t value = 0;
    for (int i = 0; i < 32; i++) {
        value <<= 1;
        if (binStr[i] == '1') {
            value |= 1;
        }
    }
    return value;
}

// ===================================================================
//                  Pass 1:  Build Label Map & Compute PC
// ===================================================================
void pass1(const char *filename) {
    FILE *fin = fopen(filename, "r");
    if (!fin) {
        perror("pass1 fopen");
        exit(1);
    }
    enum { NONE, CODE, DATA } section = NONE;
    int pc = 0x1000; 
    char line[1024];

    while (fgets(line, sizeof(line), fin)) {
        line[strcspn(line, "\n")] = '\0';
        trim(line);
        if (line[0] == '\0' || line[0] == ';') {
            continue;
        }
        if (line[0] == '.') {
            if (strncmp(line, ".code", 5) == 0) {
                section = CODE;
            } else if (strncmp(line, ".data", 5) == 0) {
                section = DATA;
            }
            continue;
        }
        if (line[0] == ':') {
            // Label definition
            char label[50];
            if (sscanf(line + 1, "%49s", label) == 1) {
                addLabel(label, pc);
            }
            continue;
        }
        // Increase PC based on section and expansions
        if (section == CODE) {
            char temp[16];
            sscanf(line, "%15s", temp);
            if (!strcmp(temp, "ld")) {
                // ld => 12 instructions => 48 bytes
                pc += 48;
            } else if (!strcmp(temp, "push") || !strcmp(temp, "pop")) {
                // push/pop => 2 instructions => 8 bytes
                pc += 8;
            } else {
                // normal => 4 bytes
                pc += 4;
            }
        } else if (section == DATA) {
            // each data item => 8 bytes
            pc += 8;
        }
    }
    fclose(fin);
}

// ===================================================================
//       Instruction Table for Standard Instructions
// ===================================================================
typedef struct {
    char name[16];
    int  opcode;
    const char *format; 
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

void freeInstMap() {
    InstructionEntry *cur, *tmp;
    HASH_ITER(hh, instMap, cur, tmp) {
        HASH_DEL(instMap, cur);
        free(cur);
    }
}

void populateInstMap() {
    instMap = NULL;
    // Integer arithmetic
    addInst("add",   0x18, "rd rs rt");
    addInst("addi",  0x19, "rd L");  
    addInst("sub",   0x1a, "rd rs rt");
    addInst("subi",  0x1b, "rd L");  
    addInst("mul",   0x1c, "rd rs rt");
    addInst("div",   0x1d, "rd rs rt");
    // Logic
    addInst("and",   0x0,  "rd rs rt");
    addInst("or",    0x1,  "rd rs rt");
    addInst("xor",   0x2,  "rd rs rt");
    addInst("not",   0x3,  "rd rs");
    addInst("shftr", 0x4,  "rd rs rt");
    addInst("shftri",0x5,  "rd L");  
    addInst("shftl", 0x6,  "rd rs rt");
    addInst("shftli",0x7,  "rd L");  
    // Control
    addInst("br",    0x8,  "rd");
    addInst("brnz",  0xb,  "rd rs");
    addInst("call",  0xc,  "rd");
    addInst("return",0xd,  "");
    addInst("brgt",  0xe,  "rd rs rt");
    // priv
    addInst("priv",  0xf,  "rd rs rt L");
    // Floating
    addInst("addf",  0x14, "rd rs rt");
    addInst("subf",  0x15, "rd rs rt");
    addInst("mulf",  0x16, "rd rs rt");
    addInst("divf",  0x17, "rd rs rt");
}

// ===================================================================
// Assembling "brr", "mov", or standard instructions
// ===================================================================
void assembleBrrOperand(const char *operand, char *binStr) {
    while (isspace((unsigned char)*operand)) operand++;
    int opcode, reg=0, imm=0;
    if (operand[0]=='r'){
        opcode=0x9;
        reg=strtol(operand+1,NULL,0);
    } else {
        opcode=0xa;
        imm=strtol(operand,NULL,0);
    }
    unsigned int inst=(opcode<<27)|(reg<<22)|((imm&0xFFF));
    char tmp[33];
    intToBinaryStr(inst,32,tmp);
    strcpy(binStr,tmp);
}

// Handle "mov" in all 4 forms
//   - Form (4): "mov (rD)(L), rS" -> opcode 0x13
//   - Form (1): "mov rD, (rS)(L)" -> opcode 0x10
//   - Form (2): "mov rD, rS"      -> opcode 0x11
//   - Form (3): "mov rD, L"       -> opcode 0x12 (unsigned immediate)
void assembleMov(const char *line, char *binStr) {
    char mnemonic[10], token1[64], token2[64];
    if (sscanf(line, "%s %63[^,], %63s", mnemonic, token1, token2) < 3) {
        strcpy(binStr, "ERROR");
        return;
    }
    trim(token1);
    trim(token2);

    int opcode = 0, rd = 0, rs = 0, rt = 0, imm = 0;

    // If token1 starts with '(' => "mov (rD)(L), rS"
    if (token1[0] == '(') {
        opcode = 0x13; // store to memory
        // parse "(rD)(L)"
        // simpler approach: we expect "mov (rXX)(offset), rYY"
        // We'll do a quick parse
        char regBuf[16] = {0}, offBuf[32] = {0};
        // Find "r" inside
        char *p1 = strchr(token1, 'r');
        if (!p1) {
            strcpy(binStr, "ERROR");
            return;
        }
        // read the register number
        int rtemp = 0;
        sscanf(p1 + 1, "%d", &rtemp);
        rd = rtemp;

        // offset => substring after rN and before the closing ')'
        // e.g. "(r31)(-8)" -> offset = -8
        char *closeParen = strchr(token1, ')');
        if (!closeParen) {
            strcpy(binStr, "ERROR");
            return;
        }
        // everything after ) is ignoring, but between ) and '(' might be tricky
        // We'll do a small parse:
        // Already got register => next is the offset
        // simpler method: search for '(' or parse from the first '('?
        // We'll assume user typed "(r31)(-8)"
        // We'll find the second '(' if any...
        char *p2 = strchr(closeParen + 1, '(');
        if (p2) {
            // unusual format
            strcpy(binStr, "ERROR");
            return;
        } else {
            // parse the chunk between ) and the actual end. Actually, we might do simpler:
            // the offset might be in the substring ")(-8)"?
            // let’s do a direct approach: (r31)(-8) => skip '(r31)' => leftover '(-8)'
            // We'll find the second '(' from token1
            char *open2 = strchr(token1 + 1, '(');
            if (!open2) {
                strcpy(binStr, "ERROR");
                return;
            }
            // open2 points to the second '(', if it does exist
            // Actually, might be better to do a quick regex. But let's do manual parse:
            // We'll move forward until we see ')', skip it, then parse the rest as offset
            // We'll do it more simply: We do a manual approach:
            char *paren2 = strstr(token1, ")(");
            if (!paren2) {
                // maybe no offset => 0
                imm = 0; 
            } else {
                // e.g. (r31)(-8)
                // paren2 -> ")("
                char offsetBuf[32];
                // everything after ")(" and before final ')'
                char *startOffset = paren2 + 2; // skip ")("
                char *endParen = strrchr(token1, ')');
                if (!endParen || endParen <= startOffset) {
                    strcpy(binStr, "ERROR");
                    return;
                }
                size_t length = endParen - startOffset;
                if (length >= sizeof(offsetBuf)) {
                    strcpy(binStr, "ERROR");
                    return;
                }
                strncpy(offsetBuf, startOffset, length);
                offsetBuf[length] = '\0';

                imm = (int)strtol(offsetBuf, NULL, 0);
            }
        }
        // Now parse token2 => "rXX"
        if (token2[0] != 'r') {
            // must be register
            strcpy(binStr, "ERROR");
            return;
        }
        rs = (int)strtol(token2 + 1, NULL, 0);
    }
    else {
        // token1 => "rD"
        if (token1[0] != 'r') {
            strcpy(binStr, "ERROR");
            return;
        }
        rd = (int)strtol(token1 + 1, NULL, 0);
        if (token2[0] == '(') {
            // form (1): "mov rD, (rS)(L)" => opcode=0x10
            opcode = 0x10;
            // parse (rS)(offset)
            char regBuf[16] = {0};
            char *p1 = strchr(token2, 'r');
            if (!p1) {
                strcpy(binStr, "ERROR");
                return;
            }
            int rtemp=0;
            sscanf(p1+1, "%d", &rtemp);
            rs = rtemp;

            // parse offset
            char *paren2 = strstr(token2, ")("); // e.g. "(r31)(-8)"
            if (!paren2) {
                // might be just "(rX)" => offset=0
                // find final ')'
                imm = 0;
            } else {
                // we have ")(val)"
                char offsetBuf[32];
                char *startOffset = paren2 + 2; // skip ")("
                char *endParen = strrchr(token2, ')');
                if (!endParen || endParen <= startOffset) {
                    strcpy(binStr, "ERROR");
                    return;
                }
                size_t length = endParen - startOffset;
                if (length >= sizeof(offsetBuf)) {
                    strcpy(binStr, "ERROR");
                    return;
                }
                strncpy(offsetBuf, startOffset, length);
                offsetBuf[length] = '\0';
                imm = (int)strtol(offsetBuf, NULL, 0);
            }
        }
        else if (token2[0] == 'r') {
            // form (2): "mov rD, rS" => opcode=0x11
            opcode = 0x11;
            rs = (int)strtol(token2 + 1, NULL, 0);
        }
        else {
            // form (3): "mov rD, L" => opcode=0x12 (unsigned immediate)
            if (token2[0] == '-') {
                fprintf(stderr, "Error: negative immediate not allowed for mov rD, L\n");
                abortAssembly(); // remove partial file
            }
            opcode = 0x12;
            imm = (int)strtol(token2, NULL, 0);
        }
    }
    unsigned int inst = (opcode << 27) | (rd << 22) | (rs << 17) | (rt << 12) | ((imm & 0xFFF));
    char tmp[32+1];
    intToBinaryStr(inst, 32, tmp);
    strcpy(binStr, tmp);
}

// Standard instructions from the instMap
void assembleStandard(const char *line, char *binStr) {
    char mnemonic[16], op1[16], op2[16], op3[16], op4[16];
    int num = sscanf(line, "%15s %15s %15s %15s %15s",
                     mnemonic, op1, op2, op3, op4);

    InstructionEntry *e = NULL;
    HASH_FIND_STR(instMap, mnemonic, e);
    if (!e) {
        strcpy(binStr, "ERROR");
        return;
    }
    int opcode = e->opcode, rd = 0, rs = 0, rt = 0, imm = 0;

    // If format is "rd L" => check for negative immediate if the instruction’s known to be unsigned
    // Our table lumps addi/subi/shiftli/shftri => "rd L"
    // so we do a quick check if op2 starts with '-'.
    if ((strcmp(e->format, "rd L") == 0) && num >= 3) {
        // This covers addi, subi, shftli, shftri => no negative allowed
        if (op2[0] == '-') {
            fprintf(stderr, "Error: negative immediate not allowed for %s\n", mnemonic);
            abortAssembly();
        }
    }

    // Parse fields
    if (!strcmp(e->format, "rd rs rt") && num >= 4) {
        rd = (op1[0] == 'r') ? (int)strtol(op1+1,NULL,0) : 0;
        rs = (op2[0] == 'r') ? (int)strtol(op2+1,NULL,0) : 0;
        rt = (op3[0] == 'r') ? (int)strtol(op3+1,NULL,0) : 0;
    }
    else if (!strcmp(e->format, "rd L") && num >= 3) {
        rd = (op1[0] == 'r') ? (int)strtol(op1+1,NULL,0) : 0;
        imm = (int)strtol(op2,NULL,0);
    }
    else if (!strcmp(e->format, "rd rs") && num >= 3) {
        rd = (op1[0] == 'r') ? (int)strtol(op1+1,NULL,0) : 0;
        rs = (op2[0] == 'r') ? (int)strtol(op2+1,NULL,0) : 0;
    }
    else if (!strcmp(e->format, "rd rs rt L") && num >= 5) {
        rd = (op1[0] == 'r') ? (int)strtol(op1+1,NULL,0) : 0;
        rs = (op2[0] == 'r') ? (int)strtol(op2+1,NULL,0) : 0;
        rt = (op3[0] == 'r') ? (int)strtol(op3+1,NULL,0) : 0;
        imm = (int)strtol(op4,NULL,0);
    }
    else if (!strcmp(e->format, "rd") && num >= 2) {
        // e.g. call rd or br rd
        rd = (op1[0] == 'r') ? (int)strtol(op1+1,NULL,0) : 0;
    }
    else if (!strcmp(e->format, "") == 0) {
        // e.g. "return" => no operands
    }
    else {
        // mismatch
        strcpy(binStr, "ERROR");
        return;
    }

    // Build final bits:
    unsigned int inst = (opcode << 27) | (rd << 22) | (rs << 17) | (rt << 12) | ((imm & 0xFFF));
    intToBinaryStr(inst, 32, binStr);
}

// Single dispatch to the correct assembler approach
void assembleInstruction(const char *line, char *binStr) {
    char mnemonic[16];
    mnemonic[0] = '\0';
    sscanf(line, "%15s", mnemonic);

    if (!strcmp(mnemonic, "mov")) {
        assembleMov(line, binStr);
    }
    else if (!strcmp(mnemonic, "brr")) {
        // e.g. "brr operand"
        // parse operand after "brr "
        const char *p = line + 3;
        while (isspace((unsigned char)*p)) p++;
        assembleBrrOperand(p, binStr);
    }
    else {
        assembleStandard(line, binStr);
    }
}

// ===================================================================
//                      Macro Expansion
// ===================================================================
// We rewrite macros like `ld`, `push`, `pop`, `clr`, `halt`, `in`, `out`
// into one or more standard instructions, then feed them to assembleInstruction.
void parseMacro(const char *line, FILE *outStream) {
    regex_t regex;
    regmatch_t matches[3];
    char op[16];
    if (sscanf(line, "%15s", op) != 1) {
        fprintf(outStream, "%s\n", line);
        return;
    }

    // -------------- LD macro --------------
    if (!strcmp(op, "ld")) {
        // pattern: ld rX, VAL  (no negative allowed, can be label)
        const char *pattern = "^[[:space:]]*ld[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*(\\S+)";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            // fallback
            fprintf(outStream, "%s\n", line);
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

            // If immediate starts with '-', error (unsigned)
            if (immBuf[0] == '-') {
                fprintf(stderr, "Error: negative immediate not allowed in ld macro\n");
                regfree(&regex);
                abortAssembly();
            }

            // Could be label or numeric
            if (!isdigit((unsigned char)immBuf[0])) {
                // label
                LabelAddress *entry = findLabel(immBuf);
                if (!entry) {
                    fprintf(stderr, "Error: label '%s' not found (ld macro)\n", immBuf);
                    regfree(&regex);
                    abortAssembly();
                }
                imm = entry->address;
            } else {
                errno = 0;
                char *endptr = NULL;
                uint64_t tmpVal = strtoull(immBuf, &endptr, 0);
                if (errno == ERANGE) {
                    fprintf(stderr, "Error: ld immediate out of range => %s\n", immBuf);
                    regfree(&regex);
                    abortAssembly();
                }
                imm = tmpVal;
            }

            // Expand to 12 instructions
            // 1) xor rD, rD, rD
            // Then top12, shift, mid12, shift, ...
            fprintf(outStream, "xor r%d r%d r%d\n", rD, rD, rD);

            // break imm into chunks
            unsigned long long top12   = (imm >> 52) & 0xFFF;
            unsigned long long mid12a  = (imm >> 40) & 0xFFF;
            unsigned long long mid12b  = (imm >> 28) & 0xFFF;
            unsigned long long mid12c  = (imm >> 16) & 0xFFF;
            unsigned long long mid4    = (imm >> 4)  & 0xFFF; // Actually 12 bits, last 8 are zero
            unsigned long long last4   = imm & 0xF;

            fprintf(outStream, "addi r%d %llu\n", rD, top12);
            fprintf(outStream, "shftli r%d 12\n", rD);
            fprintf(outStream, "addi r%d %llu\n", rD, mid12a);
            fprintf(outStream, "shftli r%d 12\n", rD);
            fprintf(outStream, "addi r%d %llu\n", rD, mid12b);
            fprintf(outStream, "shftli r%d 12\n", rD);
            fprintf(outStream, "addi r%d %llu\n", rD, mid12c);
            fprintf(outStream, "shftli r%d 12\n", rD);
            fprintf(outStream, "addi r%d %llu\n", rD, mid4);
            fprintf(outStream, "shftli r%d 4\n", rD);
            fprintf(outStream, "addi r%d %llu\n", rD, last4);
        } else {
            // if not matched, fallback
            fprintf(outStream, "%s\n", line);
        }
        regfree(&regex);
    }
    // -------------- PUSH macro --------------
    else if (!strcmp(op, "push")) {
        const char *pattern = "^[[:space:]]*push[[:space:]]+r([0-9]+)";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(outStream, "%s\n", line);
            return;
        }
        if (!regexec(&regex, line, 2, matches, 0)) {
            char regBuf[16];
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';
            int rD = (int)strtol(regBuf, NULL, 0);

            // push rD => "mov (r31)(-8), rD" + "subi r31 8"
            fprintf(outStream, "mov (r31)(-8), r%d\n", rD);
            fprintf(outStream, "subi r31 8\n");
        } else {
            fprintf(outStream, "%s\n", line);
        }
        regfree(&regex);
    }
    // -------------- POP macro --------------
    else if (!strcmp(op, "pop")) {
        const char *pattern = "^[[:space:]]*pop[[:space:]]+r([0-9]+)";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(outStream, "%s\n", line);
            return;
        }
        if (!regexec(&regex, line, 2, matches, 0)) {
            char regBuf[16];
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';
            int rD = (int)strtol(regBuf, NULL, 0);

            // pop rD => "mov rD, (r31)(0)" + "addi r31 8"
            fprintf(outStream, "mov r%d, (r31)(0)\n", rD);
            fprintf(outStream, "addi r31 8\n");
        } else {
            fprintf(outStream, "%s\n", line);
        }
        regfree(&regex);
    }
    // -------------- IN macro --------------
    else if (!strcmp(op, "in")) {
        // in rD, rS => "priv rD rS r0 3"
        const char *pattern = "^[[:space:]]*in[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*r([0-9]+)";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(outStream, "%s\n", line);
            return;
        }
        if (!regexec(&regex, line, 3, matches, 0)) {
            char regBuf1[16], regBuf2[16];
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf1, line + matches[1].rm_so, len);
            regBuf1[len] = '\0';
            len = matches[2].rm_eo - matches[2].rm_so;
            strncpy(regBuf2, line + matches[2].rm_so, len);
            regBuf2[len] = '\0';
            int rD = (int)strtol(regBuf1, NULL, 0);
            int rS = (int)strtol(regBuf2, NULL, 0);
            fprintf(outStream, "priv r%d r%d r0 3\n", rD, rS);
        } else {
            fprintf(outStream, "%s\n", line);
        }
        regfree(&regex);
    }
    // -------------- OUT macro --------------
    else if (!strcmp(op, "out")) {
        // out rD, rS => "priv rD rS r0 4"
        const char *pattern = "^[[:space:]]*out[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*r([0-9]+)";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(outStream, "%s\n", line);
            return;
        }
        if (!regexec(&regex, line, 3, matches, 0)) {
            char regBuf1[16], regBuf2[16];
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf1, line + matches[1].rm_so, len);
            regBuf1[len] = '\0';
            len = matches[2].rm_eo - matches[2].rm_so;
            strncpy(regBuf2, line + matches[2].rm_so, len);
            regBuf2[len] = '\0';
            int rD = (int)strtol(regBuf1, NULL, 0);
            int rS = (int)strtol(regBuf2, NULL, 0);
            fprintf(outStream, "priv r%d r%d r0 4\n", rD, rS);
        } else {
            fprintf(outStream, "%s\n", line);
        }
        regfree(&regex);
    }
    // -------------- CLR macro --------------
    else if (!strcmp(op, "clr")) {
        // clr rD => "xor rD, rD, rD"
        const char *pattern = "^[[:space:]]*clr[[:space:]]+r([0-9]+)";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(outStream, "%s\n", line);
            return;
        }
        if (!regexec(&regex, line, 2, matches, 0)) {
            char regBuf[16];
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';
            int rD = (int)strtol(regBuf, NULL, 0);
            fprintf(outStream, "xor r%d r%d r%d\n", rD, rD, rD);
        } else {
            fprintf(outStream, "%s\n", line);
        }
        regfree(&regex);
    }
    // -------------- HALT macro --------------
    else if (!strcmp(op, "halt")) {
        // halt => "priv r0 r0 r0 0"
        const char *pattern = "^[[:space:]]*halt[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(outStream, "%s\n", line);
            return;
        }
        if (!regexec(&regex, line, 0, NULL, 0)) {
            fprintf(outStream, "priv r0 r0 r0 0\n");
        } else {
            fprintf(outStream, "%s\n", line);
        }
        regfree(&regex);
    }
    // -------------- Not recognized => pass through --------------
    else {
        fprintf(outStream, "%s\n", line);
    }
}

// ===================================================================
//                Final Assembly: Expand macros + output binary
// ===================================================================
void finalAssemble(const char *infile, const char *outfile) {
    FILE *fin = fopen(infile, "r");
    if (!fin) {
        perror("finalAssemble fopen");
        exit(1);
    }
    // Store global output path for error cleanup
    strncpy(g_outFilename, outfile, sizeof(g_outFilename)-1);
    g_outFilename[sizeof(g_outFilename)-1] = '\0';

    g_fout = fopen(outfile, "wb");
    if (!g_fout) {
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
        if (line[0] == '\0' || line[0] == ';') {
            continue;
        }
        if (line[0] == '.') {
            if (!strcmp(line, ".code")) {
                currentSection = CODE;
            } else if (!strcmp(line, ".data")) {
                currentSection = DATA;
            }
            continue;
        }
        // If line starts with ':', it’s a label => skip
        if (line[0] == ':') {
            continue;
        }

        // If there's a label reference like "some instruction :label", we swap
        char *col = strchr(line, ':');
        if (col) {
            char lab[50];
            if (sscanf(col + 1, "%49s", lab) == 1) {
                LabelAddress *entry = findLabel(lab);
                if (!entry) {
                    fprintf(stderr, "Error: label '%s' not found\n", lab);
                    fclose(fin);
                    abortAssembly();
                }
                // replace the ":label" with numeric address "0xXXXX"
                *col = '\0'; // cut the line
                char temp[256];
                sprintf(temp, "%s0x%x", line, entry->address);
                strcpy(line, temp);
            }
        }

        if (currentSection == CODE) {
            // Check if macro
            char token[16];
            token[0] = '\0';
            sscanf(line, "%15s", token);

            if (!strcmp(token, "ld")   ||
                !strcmp(token, "push") ||
                !strcmp(token, "pop")  ||
                !strcmp(token, "in")   ||
                !strcmp(token, "out")  ||
                !strcmp(token, "clr")  ||
                !strcmp(token, "halt"))
            {
                // Expand macro to multiple lines in memory, then assemble them
                char macroExp[4096] = "";
                FILE *tempStream = fmemopen(macroExp, sizeof(macroExp), "w");
                if (!tempStream) {
                    perror("fmemopen");
                    fclose(fin);
                    abortAssembly();
                }
                parseMacro(line, tempStream);
                fflush(tempStream);
                fclose(tempStream);

                // Now assemble each expanded line
                char *expLine = strtok(macroExp, "\n");
                while (expLine) {
                    trim(expLine);
                    if (strlen(expLine) > 0) {
                        assembleInstruction(expLine, assembled);
                        if (!strcmp(assembled, "ERROR")) {
                            fprintf(stderr, "Error assembling line: %s\n", expLine);
                            fclose(fin);
                            abortAssembly();
                        }
                        uint32_t word = binStrToUint32(assembled);
                        fwrite(&word, sizeof(word), 1, g_fout);
                    }
                    expLine = strtok(NULL, "\n");
                }
            }
            else if (!strcmp(token, "mov")) {
                // custom mov
                assembleMov(line, assembled);
                if (!strcmp(assembled, "ERROR")) {
                    fprintf(stderr, "Error assembling line: %s\n", line);
                    fclose(fin);
                    abortAssembly();
                }
                uint32_t word = binStrToUint32(assembled);
                fwrite(&word, sizeof(word), 1, g_fout);
            }
            else if (!strcmp(token, "brr")) {
                // custom brr
                // skip mnemonic
                char *rest = (char*)line + 3;
                while (isspace((unsigned char)*rest)) rest++;
                assembleBrrOperand(rest, assembled);
                if (!strcmp(assembled, "ERROR")) {
                    fprintf(stderr, "Error assembling line: %s\n", line);
                    fclose(fin);
                    abortAssembly();
                }
                uint32_t word = binStrToUint32(assembled);
                fwrite(&word, sizeof(word), 1, g_fout);
            }
            else {
                // standard
                assembleStandard(line, assembled);
                if (!strcmp(assembled, "ERROR")) {
                    fprintf(stderr, "Error assembling line: %s\n", line);
                    fclose(fin);
                    abortAssembly();
                }
                uint32_t word = binStrToUint32(assembled);
                fwrite(&word, sizeof(word), 1, g_fout);
            }
        } else {
            // DATA section => parse 64-bit value
            uint64_t dVal = strtoull(line, NULL, 0);
            // no specific check here unless you want to check negative, etc.
            fwrite(&dVal, sizeof(dVal), 1, g_fout);
        }
    }

    fclose(fin);
    fclose(g_fout);
    g_fout = NULL; // done
}

// ===================================================================
//                              main
// ===================================================================
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <assembly_file> <output_file>\n", argv[0]);
        return 1;
    }
    pass1(argv[1]);             // gather labels, compute pc
    populateInstMap();          // build the instruction table
    finalAssemble(argv[1], argv[2]);
    freeInstMap();
    freeLabelMap();
    return 0;
}
