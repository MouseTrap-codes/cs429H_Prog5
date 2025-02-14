#include <stdio.h>      // Standard I/O functions
#include <stdlib.h>     // Memory allocation and exit handling
#include <string.h>     // String manipulation functions
#include <fcntl.h>      // File control (open, O_RDONLY)
#include <sys/mman.h>   // Memory mapping (mmap, munmap)
#include <sys/stat.h>   // File statistics (fstat)
#include <unistd.h>     // close, remove
#include <ctype.h>      // Character classification (isspace)
#include <errno.h>
#include <regex.h>      // For regular expression handling
#include "uthash.h"     // uthash header for hash table macros

/******************************************************************************
 * Label -> Address Map
 ******************************************************************************/
typedef struct {
    char label[50];
    int address;        // e.g., 0x1000 stored as 4096 (decimal)
    UT_hash_handle hh;  // UTHash handle
} LabelAddress;

static LabelAddress *hashmap = NULL;

static void add_label(const char *label, int address) {
    LabelAddress *entry = (LabelAddress *)malloc(sizeof(LabelAddress));
    if (!entry) {
        fprintf(stderr, "Error: malloc failed in add_label.\n");
        return;
    }
    strncpy(entry->label, label, sizeof(entry->label) - 1);
    entry->label[sizeof(entry->label) - 1] = '\0';
    entry->address = address;
    HASH_ADD_STR(hashmap, label, entry);
}

static LabelAddress *find_label(const char *label) {
    LabelAddress *entry;
    HASH_FIND_STR(hashmap, label, entry);
    return entry;
}

static void free_hashmap(void) {
    LabelAddress *cur, *tmp;
    HASH_ITER(hh, hashmap, cur, tmp) {
        HASH_DEL(hashmap, cur);
        free(cur);
    }
}

/******************************************************************************
 * Trim leading/trailing whitespace in-place.
 ******************************************************************************/
static void trim(char *s) {
    char *p = s;
    while (isspace((unsigned char)*p)) { p++; }
    if (p != s) { memmove(s, p, strlen(p) + 1); }
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        len--;
    }
}

/******************************************************************************
 * Helper functions to parse 12-bit ranges
 ******************************************************************************/
static int parse_signed_12_bit(const char *str, int *valueOut) {
    errno = 0;
    long val = strtol(str, NULL, 0); // allow 0x prefix
    if ((errno == ERANGE) || (val < -2048) || (val > 2047))
        return 0;
    *valueOut = (int)val;
    return 1;
}

static int parse_unsigned_12_bit(const char *str, int *valueOut) {
    errno = 0;
    unsigned long val = strtoul(str, NULL, 0); // allow 0x prefix
    if ((errno == ERANGE) || (val > 4095))
        return 0;
    *valueOut = (int)val;
    return 1;
}

/******************************************************************************
 * Macros used in PASS 1 to detect expansions (e.g., ld, push, pop)
 ******************************************************************************/
static int starts_with_ld(const char *line) {
    while (isspace((unsigned char)*line)) { line++; }
    if (strncmp(line, "ld", 2) == 0) {
        char c = line[2];
        if (c == '\0' || isspace((unsigned char)c) || c == ',')
            return 1;
    }
    return 0;
}

static int starts_with_push(const char *line) {
    while (isspace((unsigned char)*line)) { line++; }
    if (!strncmp(line, "push", 4)) {
        char c = line[4];
        if (c == '\0' || isspace((unsigned char)c))
            return 1;
    }
    return 0;
}

static int starts_with_pop(const char *line) {
    while (isspace((unsigned char)*line)) { line++; }
    if (!strncmp(line, "pop", 3)) {
        char c = line[3];
        if (c == '\0' || isspace((unsigned char)c))
            return 1;
    }
    return 0;
}

/******************************************************************************
 * Instruction-specific validation functions (brr, mov, etc.)
 ******************************************************************************/
static int validate_brr(const char *line) {
    char op[32], operand[64];
    int count = sscanf(line, "%31s %63[^\n]", op, operand);
    if (count < 2) {
        fprintf(stderr, "Error: 'brr' missing operand: %s\n", line);
        return 0;
    }
    if (operand[0] == 'r') {
        int rd = atoi(operand + 1);
        if (rd < 0 || rd > 31) {
            fprintf(stderr, "Error: 'brr r%d' invalid register.\n", rd);
            return 0;
        }
        return 1;
    } else {
        int val;
        if (!parse_signed_12_bit(operand, &val)) {
            fprintf(stderr, "Error: 'brr' literal out of [-2048..2047]: %s\n", operand);
            return 0;
        }
        return 1;
    }
}

static int validate_mov(const char *line) {
    char op[32], part1[64], part2[64];
    int count = sscanf(line, "%31s %63[^,], %63[^\n]", op, part1, part2);
    if (count < 2) {
        fprintf(stderr, "Error: incomplete 'mov' instruction: %s\n", line);
        return 0;
    }
    if (count == 2) {
        char second[64] = {0};
        if (sscanf(part1, "%63s %63s", part1, second) == 2) {
            strcpy(part2, second);
            count = 3;
        }
    }
    {
        char *p = part1;
        while (isspace((unsigned char)*p) || *p == ',') p++;
        if (p != part1) memmove(part1, p, strlen(p)+1);
        p = part2;
        while (isspace((unsigned char)*p) || *p == ',') p++;
        if (p != part2) memmove(part2, p, strlen(p)+1);
        for (int i = (int)strlen(part1)-1; i >= 0; i--) {
            if (isspace((unsigned char)part1[i]) || part1[i] == ',')
                part1[i] = '\0';
            else break;
        }
        for (int i = (int)strlen(part2)-1; i >= 0; i--) {
            if (isspace((unsigned char)part2[i]) || part2[i] == ',')
                part2[i] = '\0';
            else break;
        }
    }
    if (part1[0] == '(') {
        if (part2[0] != 'r') {
            fprintf(stderr, "Error: 'mov (rD)(L), rS' => 'rS' is not a register? %s\n", line);
            return 0;
        }
        int rS = atoi(part2+1);
        if (rS < 0 || rS > 31) {
            fprintf(stderr, "Error: register out of range in mov (rD)(L), rS => %s\n", line);
            return 0;
        }
        char *p = strstr(part1, "r");
        if (!p) {
            fprintf(stderr, "Error: 'mov (rD)(L), rS': can't find register in %s\n", part1);
            return 0;
        }
        int rD = atoi(p+1);
        if (rD < 0 || rD > 31) {
            fprintf(stderr, "Error: 'mov (rD)(L), rS': register out of range => %s\n", line);
            return 0;
        }
        p = strchr(p, '(');
        if (!p) {
            fprintf(stderr, "Error: 'mov (rD)(L), rS': missing offset => %s\n", line);
            return 0;
        }
        p++;
        char offsetBuf[32];
        int i = 0;
        while (*p && *p != ')' && i < 31) {
            offsetBuf[i++] = *p++;
        }
        offsetBuf[i] = '\0';
        int offsetVal;
        if (!parse_signed_12_bit(offsetBuf, &offsetVal)) {
            fprintf(stderr, "Error: offset out of [-2048..2047] in 'mov (rD)(L), rS' => %s\n", offsetBuf);
            return 0;
        }
        return 1;
    }
    if (part1[0] != 'r') {
        fprintf(stderr, "Error: mov => expected 'rD' or '(rD)(L)' => got: %s\n", part1);
        return 0;
    }
    int rD = atoi(part1+1);
    if (rD < 0 || rD > 31) {
        fprintf(stderr, "Error: register out of range in mov => %s\n", line);
        return 0;
    }
    if (count < 3) {
        fprintf(stderr, "Error: incomplete 'mov' => missing second operand: %s\n", line);
        return 0;
    }
    if (part2[0] == 'r') {
        int rS = atoi(part2+1);
        if (rS < 0 || rS > 31) {
            fprintf(stderr, "Error: register out of range => %s\n", line);
            return 0;
        }
        return 1;
    }
    else if (part2[0] == '(') {
        char *p = strstr(part2, "r");
        if (!p) {
            fprintf(stderr, "Error: can't find register in 'mov rD, (rS)(L)' => %s\n", line);
            return 0;
        }
        int rS = atoi(p+1);
        if (rS < 0 || rS > 31) {
            fprintf(stderr, "Error: register out of range in 'mov rD, (rS)(L)' => %s\n", line);
            return 0;
        }
        p = strchr(p, '(');
        if (!p) {
            fprintf(stderr, "Error: missing offset => %s\n", line);
            return 0;
        }
        p++;
        char offsetBuf[32];
        int i = 0;
        while (*p && *p != ')' && i < 31) {
            offsetBuf[i++] = *p++;
        }
        offsetBuf[i] = '\0';
        int offsetVal;
        if (!parse_signed_12_bit(offsetBuf, &offsetVal)) {
            fprintf(stderr, "Error: offset out of [-2048..2047] => %s\n", offsetBuf);
            return 0;
        }
        return 1;
    }
    else {
        int val;
        if (!parse_unsigned_12_bit(part2, &val)) {
            fprintf(stderr, "Error: mov rD, L => L out of [0..4095]: %s\n", part2);
            return 0;
        }
        return 1;
    }
}

static int validate_instruction_immediate(const char *line) {
    char op[32], rdPart[32], immPart[64];
    int count = sscanf(line, "%31s %31s %63[^\n]", op, rdPart, immPart);
    if (count < 2) return 1;
    if (!strcmp(op, "addi") || !strcmp(op, "subi") || 
        !strcmp(op, "shftri") || !strcmp(op, "shftli")) 
    {
        if (count < 3) {
            fprintf(stderr, "Error: missing immediate => %s\n", line);
            return 0;
        }
        if (rdPart[0] != 'r') return 0;
        int rD = atoi(rdPart+1);
        if (rD < 0 || rD > 31) {
            fprintf(stderr, "Error: register out of range => %s\n", line);
            return 0;
        }
        char *p = immPart;
        while (*p == ',' || isspace((unsigned char)*p)) p++;
        int val;
        if (!parse_unsigned_12_bit(p, &val)) {
            fprintf(stderr, "Error: %s => immediate out of [0..4095]: %s\n", op, p);
            return 0;
        }
        return 1;
    }
    return 1;
}

static int is_valid_instruction_pass1(const char *line) {
    char op[32];
    if (sscanf(line, "%31s", op) != 1)
        return 0;
    const char *ops[] = {
        "add","addi","sub","subi","mul","div",
        "and","or","xor","not","shftr","shftri","shftl","shftli",
        "br","brr","brnz","call","return","brgt",
        "addf","subf","mulf","divf",
        "mov",
        "halt",
        "in","out","clr","ld","push","pop"
    };
    int recognized = 0;
    int n = (int)(sizeof(ops)/sizeof(ops[0]));
    for (int i = 0; i < n; i++) {
        if (!strcmp(op, ops[i])) {
            recognized = 1;
            break;
        }
    }
    if (!recognized)
        return 0;
    if (!strcmp(op, "brr")) {
        if (!validate_brr(line))
            return 0;
        return 1;
    }
    else if (!strcmp(op, "mov")) {
        if (!validate_mov(line))
            return 0;
        return 1;
    }
    if (!validate_instruction_immediate(line))
        return 0;
    return 1;
}

/******************************************************************************
 * PASS 1: Gather labels, track program counter, and validate instructions.
 * The PC starts at 0x1000.
 ******************************************************************************/
static void pass1(const char *filename) {
    FILE *fin = fopen(filename, "r");
    if (!fin) {
        perror("pass1: fopen");
        exit(1);
    }
    enum { NONE, CODE, DATA } section = NONE;
    int programCounter = 0x1000;
    char line[1024];
    while (fgets(line, sizeof(line), fin)) {
        line[strcspn(line, "\n")] = '\0';
        trim(line);
        if (!line[0] || line[0] == ';')
            continue;
        if (line[0] == '.') {
            if (!strncmp(line, ".code", 5))
                section = CODE;
            else if (!strncmp(line, ".data", 5))
                section = DATA;
            continue;
        }
        if (line[0] == ':') {
            char labelName[50];
            if (sscanf(line + 1, "%49s", labelName) == 1)
                add_label(labelName, programCounter);
            continue;
        }
        if (section == CODE) {
            if (!is_valid_instruction_pass1(line)) {
                fprintf(stderr, "pass1 error: invalid line => %s\n", line);
                fclose(fin);
                exit(1);
            }
            if (starts_with_ld(line))
                programCounter += 48;
            else if (starts_with_push(line))
                programCounter += 8;
            else if (starts_with_pop(line))
                programCounter += 8;
            else
                programCounter += 4;
        } else if (section == DATA) {
            programCounter += 8;
        }
    }
    fclose(fin);
}

/******************************************************************************
 * Macro expansions (Pass 2)
 ******************************************************************************/
static void expandIn(int rD, int rS, FILE *fout) {
    fprintf(fout, "\tpriv r%d, r%d, r0, 3\n", rD, rS);
}
static void expandOut(int rD, int rS, FILE *fout) {
    fprintf(fout, "\tpriv r%d, r%d, r0, 4\n", rD, rS);
}
static void expandClr(int rD, FILE *fout) {
    fprintf(fout, "\txor r%d, r%d, r%d\n", rD, rD, rD);
}
// Now halt expands to the original "priv r0, r0, r0, 0"
static void expandHalt(FILE *fout) {
    fprintf(fout, "\tpriv r0, r0, r0, 0\n");
}
static void expandPush(int rD, FILE *fout) {
    fprintf(fout, "\tmov (r31)(-8), r%d\n", rD);
    fprintf(fout, "\tsubi r31, 8\n");
}
static void expandPop(int rD, FILE *fout) {
    fprintf(fout, "\tmov r%d, (r31)(0)\n", rD);
    fprintf(fout, "\taddi r31, 8\n");
}
static void expandLd(int rD, uint64_t L, FILE *fout) {
    fprintf(fout, "\txor r%d, r%d, r%d\n", rD, rD, rD);
    unsigned long long top12  = (L >> 52) & 0xFFF;
    unsigned long long mid12a = (L >> 40) & 0xFFF;
    unsigned long long mid12b = (L >> 28) & 0xFFF;
    unsigned long long mid12c = (L >> 16) & 0xFFF;
    unsigned long long mid4   = (L >> 4)  & 0xFFF;
    unsigned long long last4  = L & 0xF;
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
}
static void parseMacro(const char *line, FILE *fout) {
    regex_t regex;
    regmatch_t matches[4];
    char op[16];
    if (sscanf(line, "%15s", op) != 1) {
        fprintf(stderr, "parseMacro: cannot parse op from line: %s\n", line);
        return;
    }
    if (!strcmp(op, "ld")) {
        const char *pattern =
          "^[[:space:]]*ld[[:space:]]+r([0-9]+)[[:space:]]*,?[[:space:]]*(:?)([0-9a-fA-FxX:]+)[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(stderr, "Could not compile regex for ld\n");
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
                LabelAddress *entry = find_label(immBuf + 1);
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
                    fprintf(stderr, "Error: 'ld' immediate out of 64-bit range => %s\n", immBuf);
                    regfree(&regex);
                    return;
                }
                imm = tmpVal;
            }
            expandLd(rD, imm, fout);
        } else {
            fprintf(stderr, "Error parsing ld macro: %s\n", line);
        }
        regfree(&regex);
    }
    else if (!strcmp(op, "push")) {
        const char *pattern =
          "^[[:space:]]*push[[:space:]]+r([0-9]+)[[:space:]]*,?[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(stderr, "Could not compile regex for push\n");
            return;
        }
        if (regexec(&regex, line, 2, matches, 0) == 0) {
            char regBuf[16];
            int rD;
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';
            rD = atoi(regBuf);
            expandPush(rD, fout);
        } else {
            fprintf(stderr, "Error parsing push macro: %s\n", line);
        }
        regfree(&regex);
    }
    else if (!strcmp(op, "pop")) {
        const char *pattern =
          "^[[:space:]]*pop[[:space:]]+r([0-9]+)[[:space:]]*,?[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(stderr, "Could not compile regex for pop\n");
            return;
        }
        if (regexec(&regex, line, 2, matches, 0) == 0) {
            char regBuf[16];
            int rD;
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';
            rD = atoi(regBuf);
            expandPop(rD, fout);
        } else {
            fprintf(stderr, "Error parsing pop macro: %s\n", line);
        }
        regfree(&regex);
    }
    else if (!strcmp(op, "in")) {
        const char *pattern =
          "^[[:space:]]*in[[:space:]]+r([0-9]+)[[:space:]]*,?[[:space:]]*r([0-9]+)[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(stderr, "Could not compile regex for in\n");
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
            expandIn(rD, rS, fout);
        } else {
            fprintf(stderr, "Error parsing in macro: %s\n", line);
        }
        regfree(&regex);
    }
    else if (!strcmp(op, "out")) {
        const char *pattern =
          "^[[:space:]]*out[[:space:]]+r([0-9]+)[[:space:]]*,?[[:space:]]*r([0-9]+)[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(stderr, "Could not compile regex for out\n");
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
            expandOut(rD, rS, fout);
        } else {
            fprintf(stderr, "Error parsing out macro: %s\n", line);
        }
        regfree(&regex);
    }
    else if (!strcmp(op, "clr")) {
        const char *pattern =
          "^[[:space:]]*clr[[:space:]]+r([0-9]+)[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(stderr, "Could not compile regex for clr\n");
            return;
        }
        if (regexec(&regex, line, 2, matches, 0) == 0) {
            char regBuf[16];
            int rD;
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';
            rD = atoi(regBuf);
            if (rD < 0 || rD > 31) {
                fprintf(stderr, "Error: register out of range in clr => %s\n", line);
                regfree(&regex);
                return;
            }
            expandClr(rD, fout);
        } else {
            fprintf(stderr, "Error parsing clr macro: %s\n", line);
        }
        regfree(&regex);
    }
    // Now halt expands to "priv r0, r0, r0, 0"
    else if (!strcmp(op, "halt")) {
        const char *pattern = "^[[:space:]]*halt[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(stderr, "Could not compile regex for halt\n");
            return;
        }
        if (regexec(&regex, line, 0, NULL, 0) == 0) {
            expandHalt(fout);
        } else {
            fprintf(stderr, "Error parsing halt macro: %s\n", line);
        }
        regfree(&regex);
    }
    else {
        fprintf(fout, "\t%s\n", line);
    }
}

static int is_macro_line(const char *line) {
    char op[16];
    if (sscanf(line, "%15s", op) != 1)
        return 0;
    if (!strcmp(op, "ld")   || !strcmp(op, "push") ||
        !strcmp(op, "pop")  || !strcmp(op, "in")   ||
        !strcmp(op, "out")  || !strcmp(op, "clr")  ||
        !strcmp(op, "halt"))
    {
        return 1;
    }
    return 0;
}

/******************************************************************************
 * PASS 2: Generate the .tk file (macro expansion and label substitution)
 ******************************************************************************/
static void pass2(const char *infile, const char *outfile) {
    FILE *fin = fopen(infile, "r");
    if (!fin) {
        perror("pass2: fopen input");
        exit(1);
    }
    FILE *fout = fopen(outfile, "w");
    if (!fout) {
        perror("pass2: fopen output");
        fclose(fin);
        exit(1);
    }
    char line[1024];
    while (fgets(line, sizeof(line), fin)) {
        line[strcspn(line, "\n")] = '\0';
        trim(line);
        if (!line[0] || line[0] == ';')
            continue;
        if (!strcmp(line, ".code")) {
            fprintf(fout, ".code\n");
            continue;
        }
        if (!strcmp(line, ".data")) {
            fprintf(fout, ".data\n");
            continue;
        }
        if (line[0] == ':')
            continue;
        char *colon = strchr(line, ':');
        if (colon) {
            char lbl[50];
            if (sscanf(colon + 1, "%49s", lbl) == 1) {
                LabelAddress *entry = find_label(lbl);
                if (entry) {
                    *colon = '\0';
                    char buffer[1024];
                    snprintf(buffer, sizeof(buffer), "\t%s%d", line, entry->address);
                    if (is_macro_line(buffer))
                        parseMacro(buffer, fout);
                    else
                        fprintf(fout, "%s\n", buffer);
                    continue;
                } else {
                    fprintf(stderr, "Warning: label '%s' not found.\n", lbl);
                    fprintf(fout, "\t%s\n", line);
                    continue;
                }
            }
        }
        if (is_macro_line(line))
            parseMacro(line, fout);
        else
            fprintf(fout, "\t%s\n", line);
    }
    fclose(fin);
    fclose(fout);
}

/******************************************************************************
 * Instruction Table for Assembler
 ******************************************************************************/
typedef struct {
    char name[16];         // instruction mnemonic
    int opcode;            // Binary opcode
    const char *format;    // Format string (e.g., "rd rs rt", "rd L", "L")
    UT_hash_handle hh;
} InstructionEntry;

InstructionEntry *instruction_map = NULL;

void addInstruction(const char *instr, int opcode, const char *format) {
    InstructionEntry *entry = (InstructionEntry *)malloc(sizeof(InstructionEntry));
    if (!entry) {
        fprintf(stderr, "Error: malloc failed\n");
        return;
    }
    strncpy(entry->name, instr, sizeof(entry->name));
    entry->name[sizeof(entry->name) - 1] = '\0';
    entry->opcode = opcode;
    entry->format = format;
    HASH_ADD_STR(instruction_map, name, entry);
}

void populateTinkerInstruction() {
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
    // Privileged instruction for halt expansion:
    addInstruction("priv",  0xf, "rd rs rt L");
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

void free_instruction_table() {
    InstructionEntry *current_entry, *tmp;
    HASH_ITER(hh, instruction_map, current_entry, tmp) {
        HASH_DEL(instruction_map, current_entry);
        free(current_entry);
    }
}

/******************************************************************************
 * Helper: Skip leading whitespace.
 ******************************************************************************/
const char *skip_whitespace(const char *s) {
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }
    return s;
}

/******************************************************************************
 * Assemble a single line of assembly into a 32-bit binary string.
 * Encoding: opcode (5 bits) | rd (5 bits) | rs (5 bits) | rt (5 bits) | L (12 bits)
 ******************************************************************************/
char *assemble_instruction(const char *assembly_line) {
    static char binary_code[33];  // 32-bit binary plus null terminator
    char instr[10], op1[10], op2[10], op3[10];
    int num_parsed = sscanf(assembly_line, "%s %s %s %s", instr, op1, op2, op3);
    if (strcmp(instr, "hlt") == 0) {
        strcpy(binary_code, "00000000000000000000000000000000");
        return binary_code;
    }
    InstructionEntry *entry = NULL;
    HASH_FIND_STR(instruction_map, instr, entry);
    if (!entry) {
        printf("Error: Unknown instruction %s\n", instr);
        return NULL;
    }
    int opcode = entry->opcode;
    int rd = 0, rs = 0, rt = 0, L = 0;
    if (strcmp(entry->format, "rd rs rt") == 0 && num_parsed == 4) {
        rd = (op1[0]=='r') ? atoi(op1+1) : 0;
        rs = (op2[0]=='r') ? atoi(op2+1) : 0;
        rt = (op3[0]=='r') ? atoi(op3+1) : 0;
    } else if (strcmp(entry->format, "rd L") == 0 && num_parsed == 3) {
        rd = (op1[0]=='r') ? atoi(op1+1) : 0;
        L = atoi(op2);
    } else if (strcmp(entry->format, "rd rs") == 0 && num_parsed == 3) {
        rd = (op1[0]=='r') ? atoi(op1+1) : 0;
        rs = (op2[0]=='r') ? atoi(op2+1) : 0;
    } else if (strcmp(entry->format, "L") == 0 && num_parsed == 2) {
        L = atoi(op1);
        rd = rs = rt = 0;
    } else {
        printf("Error: Invalid operands for %s\n", instr);
        return NULL;
    }
    int binary_value = (opcode << 27) | (rd << 22) | (rs << 17) | (rt << 12) | (L & 0xFFF);
    for (int i = 31; i >= 0; i--) {
        binary_code[31 - i] = ((binary_value >> i) & 1) ? '1' : '0';
    }
    binary_code[32] = '\0';
    return binary_code;
}

/******************************************************************************
 * New parse_and_assemble_file: Process .tk file line by line, and based on the
 * current section (code vs data) assemble the line appropriately.
 * In the code section, instructions are assembled into 32-bit binary strings.
 * In the data section, 64-bit data items are converted into 64-bit binary strings.
 ******************************************************************************/
void parse_and_assemble_file(const char *input_filename, const char *output_filename) {
    FILE *fp = fopen(input_filename, "r");
    if (!fp) {
        perror("Error opening input file");
        return;
    }
    FILE *out = fopen(output_filename, "w");
    if (!out) {
        perror("Error opening output file");
        fclose(fp);
        return;
    }
    int current_section = 0; // 0 for code, 1 for data. Default to code.
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        trim(line);
        if (strlen(line) == 0)
            continue;
        if (strncmp(line, ".code", 5) == 0) {
            current_section = 0;
            continue;
        }
        if (strncmp(line, ".data", 5) == 0) {
            current_section = 1;
            continue;
        }
        if (current_section == 0) {
            // Code section: assemble instruction (32-bit)
            char *binary = assemble_instruction(line);
            if (binary)
                fprintf(out, "%s\n", binary);
            else
                fprintf(out, "Error: Could not assemble line: %s\n", line);
        } else {
            // Data section: treat line as a 64-bit data item.
            // The line should be a number (already label-resolved)
            unsigned long long data_val = strtoull(line, NULL, 0);
            char data_binary[65];
            for (int i = 63; i >= 0; i--) {
                data_binary[63 - i] = ((data_val >> i) & 1) ? '1' : '0';
            }
            data_binary[64] = '\0';
            fprintf(out, "%s\n", data_binary);
        }
    }
    fclose(fp);
    fclose(out);
}

/******************************************************************************
 * main
 * This version accepts only an input assembly file and an output file.
 * Internally a temporary .tk file is created for Pass 2.
 ******************************************************************************/
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <assembly_file> <output_file>\n", argv[0]);
        return 1;
    }
    pass1(argv[1]);
    char temp_filename[] = "tempXXXXXX";
    int temp_fd = mkstemp(temp_filename);
    if (temp_fd == -1) {
        perror("mkstemp failed");
        exit(1);
    }
    close(temp_fd);
    pass2(argv[1], temp_filename);
    free_hashmap();
    populateTinkerInstruction();
    parse_and_assemble_file(temp_filename, argv[2]);
    free_instruction_table();
    remove(temp_filename);
    return 0;
}
