/* tinker_assembler.c */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>
#include <errno.h>
#include "uthash.h"

/*--------------------------------------------------------------
   Data Structures and Helpers (Stage 1)
--------------------------------------------------------------*/

/* Label-to-address hash map structure */
typedef struct {
    char label[50];
    int address;           // e.g. 0x1000 is stored as 4096
    UT_hash_handle hh;     // hash handle for uthash
} LabelAddress;

static LabelAddress *hashmap = NULL;

static void add_label(const char *label, int address) {
    LabelAddress *entry = malloc(sizeof(LabelAddress));
    if (!entry) {
        fprintf(stderr, "Error: malloc failed in add_label.\n");
        exit(1);
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

/* Trim leading and trailing whitespace in-place */
static void trim(char *s) {
    char *p = s;
    while (isspace((unsigned char)*p)) p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        len--;
    }
}

/* Helpers to parse 12-bit immediate values */
static int parse_signed_12_bit(const char *str, int *valueOut) {
    errno = 0;
    long val = strtol(str, NULL, 0);
    if ((errno == ERANGE) || (val < -2048) || (val > 2047))
        return 0;
    *valueOut = (int)val;
    return 1;
}

static int parse_unsigned_12_bit(const char *str, int *valueOut) {
    errno = 0;
    unsigned long val = strtoul(str, NULL, 0);
    if ((errno == ERANGE) || (val > 4095))
        return 0;
    *valueOut = (int)val;
    return 1;
}

/* Macros for pass-1: helpers to detect macro instructions */
static int starts_with_ld(const char *line) {
    while (isspace((unsigned char)*line)) line++;
    return (strncmp(line, "ld", 2) == 0 && (line[2] == '\0' || isspace((unsigned char)line[2]) || line[2] == ','));
}
static int starts_with_push(const char *line) {
    while (isspace((unsigned char)*line)) line++;
    return (!strncmp(line, "push", 4) && (line[4] == '\0' || isspace((unsigned char)line[4])));
}
static int starts_with_pop(const char *line) {
    while (isspace((unsigned char)*line)) line++;
    return (!strncmp(line, "pop", 3) && (line[3] == '\0' || isspace((unsigned char)line[3])));
}

/*--------------------------------------------------------------
   Validation Functions for Stage 1
--------------------------------------------------------------*/

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
    /* Trim leading/trailing whitespace and commas */
    {
        char *p = part1;
        while (isspace((unsigned char)*p) || *p == ',') p++;
        if (p != part1)
            memmove(part1, p, strlen(p) + 1);
        p = part2;
        while (isspace((unsigned char)*p) || *p == ',') p++;
        if (p != part2)
            memmove(part2, p, strlen(p) + 1);
        for (int i = (int)strlen(part1) - 1; i >= 0; i--) {
            if (isspace((unsigned char)part1[i]) || part1[i] == ',')
                part1[i] = '\0';
            else break;
        }
        for (int i = (int)strlen(part2) - 1; i >= 0; i--) {
            if (isspace((unsigned char)part2[i]) || part2[i] == ',')
                part2[i] = '\0';
            else break;
        }
    }
    /* Check which form of mov this is */
    if (part1[0] == '(') {  // form: mov (rD)(L), rS
        if (part2[0] != 'r') {
            fprintf(stderr, "Error: 'mov (rD)(L), rS' => second operand not a register: %s\n", line);
            return 0;
        }
        int rS = atoi(part2 + 1);
        if (rS < 0 || rS > 31) {
            fprintf(stderr, "Error: register out of range in mov (rD)(L), rS: %s\n", line);
            return 0;
        }
        char *p = strstr(part1, "r");
        if (!p) {
            fprintf(stderr, "Error: 'mov (rD)(L), rS' missing register: %s\n", line);
            return 0;
        }
        int rD = atoi(p + 1);
        if (rD < 0 || rD > 31) {
            fprintf(stderr, "Error: register out of range in mov (rD)(L), rS: %s\n", line);
            return 0;
        }
        p = strchr(p, '(');
        if (!p) {
            fprintf(stderr, "Error: 'mov (rD)(L), rS' missing offset: %s\n", line);
            return 0;
        }
        p++; // skip '('
        char offsetBuf[32];
        int i = 0;
        while (*p && *p != ')' && i < 31) {
            offsetBuf[i++] = *p++;
        }
        offsetBuf[i] = '\0';
        int offsetVal;
        if (!parse_signed_12_bit(offsetBuf, &offsetVal)) {
            fprintf(stderr, "Error: offset out of [-2048..2047] in mov (rD)(L), rS: %s\n", offsetBuf);
            return 0;
        }
        return 1;
    }
    if (part1[0] != 'r') {
        fprintf(stderr, "Error: mov instruction expected rD: %s\n", line);
        return 0;
    }
    int rD = atoi(part1 + 1);
    if (rD < 0 || rD > 31) {
        fprintf(stderr, "Error: register out of range in mov: %s\n", line);
        return 0;
    }
    if (count < 3) {
        fprintf(stderr, "Error: incomplete 'mov' instruction: %s\n", line);
        return 0;
    }
    if (part2[0] == 'r') { // form: mov rD, rS
        int rS = atoi(part2 + 1);
        if (rS < 0 || rS > 31) {
            fprintf(stderr, "Error: register out of range in mov rD, rS: %s\n", line);
            return 0;
        }
        return 1;
    } else if (part2[0] == '(') { // form: mov rD, (rS)(L)
        char *p = strstr(part2, "r");
        if (!p) {
            fprintf(stderr, "Error: mov rD, (rS)(L) missing register: %s\n", line);
            return 0;
        }
        int rS = atoi(p + 1);
        if (rS < 0 || rS > 31) {
            fprintf(stderr, "Error: register out of range in mov rD, (rS)(L): %s\n", line);
            return 0;
        }
        p = strchr(p, '(');
        if (!p) {
            fprintf(stderr, "Error: mov rD, (rS)(L) missing offset: %s\n", line);
            return 0;
        }
        p++; // skip '('
        char offsetBuf[32];
        int i = 0;
        while (*p && *p != ')' && i < 31) {
            offsetBuf[i++] = *p++;
        }
        offsetBuf[i] = '\0';
        int offsetVal;
        if (!parse_signed_12_bit(offsetBuf, &offsetVal)) {
            fprintf(stderr, "Error: offset out of [-2048..2047] in mov rD, (rS)(L): %s\n", offsetBuf);
            return 0;
        }
        return 1;
    } else { // form: mov rD, L
        int val;
        if (!parse_unsigned_12_bit(part2, &val)) {
            fprintf(stderr, "Error: immediate out of [0..4095] in mov rD, L: %s\n", part2);
            return 0;
        }
        return 1;
    }
}

static int validate_instruction_immediate(const char *line) {
    char op[32], rdPart[32], immPart[64];
    int count = sscanf(line, "%31s %31s %63[^\n]", op, rdPart, immPart);
    if (count < 2) return 1; // nothing to check
    if (!strcmp(op, "addi") || !strcmp(op, "subi") ||
        !strcmp(op, "shftri") || !strcmp(op, "shftli")) {
        if (count < 3) {
            fprintf(stderr, "Error: missing immediate in %s: %s\n", op, line);
            return 0;
        }
        if (rdPart[0] != 'r') return 0;
        int rD = atoi(rdPart + 1);
        if (rD < 0 || rD > 31) {
            fprintf(stderr, "Error: register out of range in %s: %s\n", op, line);
            return 0;
        }
        char *p = immPart;
        while (*p == ',' || isspace((unsigned char)*p)) p++;
        int val;
        if (!parse_unsigned_12_bit(p, &val)) {
            fprintf(stderr, "Error: immediate out of [0..4095] in %s: %s\n", op, p);
            return 0;
        }
    }
    return 1;
}

static int is_valid_instruction_pass1(const char *line) {
    char op[32];
    if (sscanf(line, "%31s", op) != 1)
        return 0;
    const char *ops[] = {
        "add", "addi", "sub", "subi", "mul", "div",
        "and", "or", "xor", "not", "shftr", "shftri", "shftl", "shftli",
        "br", "brr", "brnz", "call", "return", "brgt",
        "addf", "subf", "mulf", "divf",
        "mov",
        "halt",
        "in", "out", "clr", "ld", "push", "pop"
    };
    int recognized = 0;
    int n = sizeof(ops) / sizeof(ops[0]);
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
    } else if (!strcmp(op, "mov")) {
        if (!validate_mov(line))
            return 0;
        return 1;
    }
    if (!validate_instruction_immediate(line))
        return 0;
    return 1;
}

/*--------------------------------------------------------------
   Pass 1: Label Resolution and Instruction Validation
--------------------------------------------------------------*/
static void pass1(const char *filename) {
    FILE *fin = fopen(filename, "r");
    if (!fin) {
        perror("pass1 fopen");
        exit(1);
    }
    enum { NONE, CODE, DATA } section = NONE;
    int programCounter = 0x1000; // Code starts at address 0x1000
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
                fprintf(stderr, "pass1 error: invalid instruction: %s\n", line);
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

/*--------------------------------------------------------------
   Pass 2: Macro Expansion and Label Substitution
   (Produces an intermediate file with macros expanded and labels resolved)
--------------------------------------------------------------*/

/* Expansion helper functions */
static void expandIn(int rD, int rS, FILE *fout) {
    fprintf(fout, "\tpriv r%d, r%d, r0, 3\n", rD, rS);
}
static void expandOut(int rD, int rS, FILE *fout) {
    fprintf(fout, "\tpriv r%d, r%d, r0, 4\n", rD, rS);
}
static void expandClr(int rD, FILE *fout) {
    fprintf(fout, "\txor r%d, r%d, r%d\n", rD, rD, rD);
}
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

/* Macro parser */
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
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line + matches[1].rm_so, len);
            regBuf[len] = '\0';
            rD = atoi(regBuf);
            if (rD < 0 || rD > 31) {
                fprintf(stderr, "Error: register out of range in ld: r%d\n", rD);
                regfree(&regex);
                return;
            }
            len = matches[3].rm_eo - matches[3].rm_so;
            strncpy(immBuf, line + matches[3].rm_so, len);
            immBuf[len] = '\0';
            uint64_t imm;
            if (immBuf[0] == ':') {
                LabelAddress *entry = find_label(immBuf + 1);
                if (!entry) {
                    fprintf(stderr, "Error: label %s not found\n", immBuf + 1);
                    regfree(&regex);
                    return;
                }
                imm = entry->address;
            } else {
                errno = 0;
                uint64_t tmpVal = strtoull(immBuf, NULL, 0);
                if (errno == ERANGE) {
                    fprintf(stderr, "Error: ld immediate out of 64-bit range: %s\n", immBuf);
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
    } else if (!strcmp(op, "push")) {
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
            if (rD < 0 || rD > 31) {
                fprintf(stderr, "Error: register out of range in push: %s\n", line);
                regfree(&regex);
                return;
            }
            expandPush(rD, fout);
        } else {
            fprintf(stderr, "Error parsing push macro: %s\n", line);
        }
        regfree(&regex);
    } else if (!strcmp(op, "pop")) {
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
            if (rD < 0 || rD > 31) {
                fprintf(stderr, "Error: register out of range in pop: %s\n", line);
                regfree(&regex);
                return;
            }
            expandPop(rD, fout);
        } else {
            fprintf(stderr, "Error parsing pop macro: %s\n", line);
        }
        regfree(&regex);
    } else if (!strcmp(op, "in")) {
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
                fprintf(stderr, "Error: register out of range in in: %s\n", line);
                regfree(&regex);
                return;
            }
            expandIn(rD, rS, fout);
        } else {
            fprintf(stderr, "Error parsing in macro: %s\n", line);
        }
        regfree(&regex);
    } else if (!strcmp(op, "out")) {
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
                fprintf(stderr, "Error: register out of range in out: %s\n", line);
                regfree(&regex);
                return;
            }
            expandOut(rD, rS, fout);
        } else {
            fprintf(stderr, "Error parsing out macro: %s\n", line);
        }
        regfree(&regex);
    } else if (!strcmp(op, "clr")) {
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
                fprintf(stderr, "Error: register out of range in clr: %s\n", line);
                regfree(&regex);
                return;
            }
            expandClr(rD, fout);
        } else {
            fprintf(stderr, "Error parsing clr macro: %s\n", line);
        }
        regfree(&regex);
    } else if (!strcmp(op, "halt")) {
        const char *pattern = "^[[:space:]]*halt[[:space:]]*$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(stderr, "Could not compile regex for halt\n");
            return;
        }
        if (regexec(&regex, line, 0, NULL, 0) == 0)
            expandHalt(fout);
        else
            fprintf(stderr, "Error parsing halt macro: %s\n", line);
        regfree(&regex);
    } else {
        /* Not a macro: print as-is */
        fprintf(fout, "\t%s\n", line);
    }
}

static int is_macro_line(const char *line) {
    char op[16];
    if (sscanf(line, "%15s", op) != 1)
        return 0;
    if (!strcmp(op, "ld") || !strcmp(op, "push") ||
        !strcmp(op, "pop") || !strcmp(op, "in") ||
        !strcmp(op, "out") || !strcmp(op, "clr") ||
        !strcmp(op, "halt"))
        return 1;
    return 0;
}

static void pass2(const char *infile, const char *outfile) {
    FILE *fin = fopen(infile, "r");
    if (!fin) {
        perror("pass2 fopen input");
        exit(1);
    }
    FILE *fout = fopen(outfile, "w");
    if (!fout) {
        perror("pass2 fopen output");
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

/*--------------------------------------------------------------
   Pass 3: Binary Encoding (Stage 2)
   This converts the intermediate .tk file into a binary .tko file.
   Instructions are encoded as 32-bit words; data items as 64-bit values.
--------------------------------------------------------------*/

/*
   Tinker instruction format (32 bits):
   Bits 31-27: 5-bit opcode
   Bits 26-22: 5-bit destination register (rd)
   Bits 21-17: 5-bit source register (rs)
   Bits 16-12: 5-bit source register (rt)
   Bits 11-0 : 12-bit immediate (L)
*/
uint32_t encode_instruction(char *line) {
    uint32_t opcode = 0, rd = 0, rs = 0, rt = 0, imm = 0;
    char buf[256];
    strncpy(buf, line, sizeof(buf));
    buf[sizeof(buf)-1] = '\0';
    char *token = strtok(buf, " \t,");
    if (!token) return 0;
    
    /* Special case: hlt (which is implemented as a macro) */
    if (strcmp(token, "hlt") == 0) {
        opcode = 0xF;
        return (opcode << 27);
    }
    
    /* Handle mov instructions which have several forms */
    if (strcmp(token, "mov") == 0) {
        char *op1 = strtok(NULL, " \t,");
        if (!op1) {
            fprintf(stderr, "Incomplete mov instruction\n");
            exit(1);
        }
        if (op1[0] == '(') {
            opcode = 0x13;  // mov (rD)(L), rS
            char *p = op1 + 1;
            rd = atoi(p + 1);  // simplistic parsing (assumes format: (rX)(L))
            p = strchr(op1, '(');
            if (!p) {
                fprintf(stderr, "Malformed mov instruction: %s\n", line);
                exit(1);
            }
            p++; // skip '('
            char immStr[32] = {0};
            char *endp = strchr(p, ')');
            if (!endp) {
                fprintf(stderr, "Malformed immediate in mov: %s\n", line);
                exit(1);
            }
            strncpy(immStr, p, endp - p);
            imm = (uint32_t)strtol(immStr, NULL, 0);
            char *op2 = strtok(NULL, " \t,");
            if (!op2) {
                fprintf(stderr, "Missing register in mov (rD)(L), rS\n");
                exit(1);
            }
            rs = atoi(op2 + 1);
            return ((opcode & 0x1F) << 27) | ((rd & 0x1F) << 22) | ((rs & 0x1F) << 17) | (imm & 0xFFF);
        }
        rd = atoi(op1 + 1);
        char *op2 = strtok(NULL, " \t,");
        if (!op2) {
            fprintf(stderr, "Incomplete mov instruction\n");
            exit(1);
        }
        if (op2[0] == '(') {
            opcode = 0x10;  // mov rd, (rS)(L)
            char *p = op2 + 1;
            rs = atoi(p + 1);
            p = strchr(op2, ')');
            if (!p) {
                fprintf(stderr, "Malformed mov operand: %s\n", line);
                exit(1);
            }
            p = strchr(p, '(');
            if (!p) {
                fprintf(stderr, "Missing immediate in mov operand: %s\n", line);
                exit(1);
            }
            p++;
            char immStr[32] = {0};
            char *endp = strchr(p, ')');
            if (!endp) {
                fprintf(stderr, "Malformed immediate in mov: %s\n", line);
                exit(1);
            }
            strncpy(immStr, p, endp - p);
            imm = (uint32_t)strtol(immStr, NULL, 0);
            return ((opcode & 0x1F) << 27) | ((rd & 0x1F) << 22) | ((rs & 0x1F) << 17) | (imm & 0xFFF);
        }
        if (op2[0] == 'r') {
            opcode = 0x11;  // mov rd, rs
            rs = atoi(op2 + 1);
            return ((opcode & 0x1F) << 27) | ((rd & 0x1F) << 22) | ((rs & 0x1F) << 17);
        }
        opcode = 0x12;  // mov rd, L
        imm = (uint32_t)strtol(op2, NULL, 0);
        return ((opcode & 0x1F) << 27) | ((rd & 0x1F) << 22) | (imm & 0xFFF);
    }
    
    /* For other instructions, map the mnemonic to its opcode */
    if (strcmp(token, "add") == 0)       { opcode = 0x18; }
    else if (strcmp(token, "addi") == 0) { opcode = 0x19; }
    else if (strcmp(token, "sub") == 0)  { opcode = 0x1A; }
    else if (strcmp(token, "subi") == 0) { opcode = 0x1B; }
    else if (strcmp(token, "mul") == 0)  { opcode = 0x1C; }
    else if (strcmp(token, "div") == 0)  { opcode = 0x1D; }
    else if (strcmp(token, "and") == 0)  { opcode = 0x00; }
    else if (strcmp(token, "or") == 0)   { opcode = 0x01; }
    else if (strcmp(token, "xor") == 0)  { opcode = 0x02; }
    else if (strcmp(token, "not") == 0)  { opcode = 0x03; }
    else if (strcmp(token, "shftr") == 0){ opcode = 0x04; }
    else if (strcmp(token, "shftri") == 0){ opcode = 0x05; }
    else if (strcmp(token, "shftl") == 0){ opcode = 0x06; }
    else if (strcmp(token, "shftli") == 0){ opcode = 0x07; }
    else if (strcmp(token, "br") == 0)   { opcode = 0x08; }
    else if (strcmp(token, "brr") == 0)  {
        char *peek = strtok(NULL, " \t,");
        if (!peek) {
            fprintf(stderr, "Incomplete brr instruction\n");
            exit(1);
        }
        if (peek[0] == 'r') {
            opcode = 0x09;
            rd = atoi(peek + 1);
        } else {
            opcode = 0x0A;
            imm = (uint32_t)strtol(peek, NULL, 0);
        }
        return ((opcode & 0x1F) << 27) | ((rd & 0x1F) << 22) | (imm & 0xFFF);
    }
    else if (strcmp(token, "brnz") == 0){ opcode = 0x0B; }
    else if (strcmp(token, "call") == 0){ opcode = 0x0C; }
    else if (strcmp(token, "return") == 0){ opcode = 0x0D; }
    else if (strcmp(token, "brgt") == 0){ opcode = 0x0E; }
    else if (strcmp(token, "priv") == 0){ opcode = 0x0F; }
    else if (strcmp(token, "addf") == 0){ opcode = 0x14; }
    else if (strcmp(token, "subf") == 0){ opcode = 0x15; }
    else if (strcmp(token, "mulf") == 0){ opcode = 0x16; }
    else if (strcmp(token, "divf") == 0){ opcode = 0x17; }
    else {
        fprintf(stderr, "Unknown instruction: %s\n", token);
        exit(1);
    }
    
    /* For most instructions, read the remaining tokens */
    if (opcode != 0x0D && opcode != 0x0F) { // not 'return' or hlt
        char *t = strtok(NULL, " \t,");
        if (t && t[0] == 'r') {
            rd = atoi(t + 1);
        }
    }
    char *t = strtok(NULL, " \t,");
    if (t && t[0] == 'r') {
        rs = atoi(t + 1);
    }
    t = strtok(NULL, " \t,");
    if (t && t[0] == 'r') {
        rt = atoi(t + 1);
    }
    t = strtok(NULL, " \t,");
    if (t) {
        imm = (uint32_t)strtol(t, NULL, 0);
    }
    uint32_t word = 0;
    word |= (opcode & 0x1F) << 27;
    word |= (rd & 0x1F) << 22;
    word |= (rs & 0x1F) << 17;
    word |= (rt & 0x1F) << 12;
    word |= (imm & 0xFFF);
    return word;
}

/*--------------------------------------------------------------
   Main: Combined Assembler (Stages 1 & 2)
--------------------------------------------------------------
   This program takes a Tinker assembly file (.tk) as input and produces
   a binary object file (.tko). It runs three passes:
   1. Label resolution and validation.
   2. Macro expansion and label substitution (producing an intermediate file).
   3. Binary encoding (instructions as 32-bit words, data as 64-bit words).
--------------------------------------------------------------*/

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input_file.tk> <output_file.tko>\n", argv[0]);
        exit(1);
    }
    
    /* Pass 1: Process the original assembly file */
    pass1(argv[1]);
    
    /* Pass 2: Generate an intermediate file with macros expanded and labels resolved */
    char tempFilename[] = "temp_intermediate.tk";
    pass2(argv[1], tempFilename);
    
    /* Pass 3: Read the intermediate file and output binary code */
    FILE *fin = fopen(tempFilename, "r");
    if (!fin) {
        perror("fopen temp file");
        exit(1);
    }
    FILE *fout = fopen(argv[2], "wb");
    if (!fout) {
        perror("fopen output file");
        exit(1);
    }
    
    char line[1024];
    enum { NONE, CODE, DATA } section = NONE;
    while (fgets(line, sizeof(line), fin)) {
        line[strcspn(line, "\n")] = '\0';
        char *ptr = line;
        while (isspace((unsigned char)*ptr)) ptr++;
        if (strlen(ptr) == 0) continue;
        if (ptr[0] == '.') {
            if (strcmp(ptr, ".code") == 0)
                section = CODE;
            else if (strcmp(ptr, ".data") == 0)
                section = DATA;
            continue;
        }
        if (ptr[0] == ':') continue;
        if (section == CODE) {
            uint32_t word = encode_instruction(ptr);
            fwrite(&word, sizeof(word), 1, fout);
        } else if (section == DATA) {
            uint64_t data = strtoull(ptr, NULL, 0);
            fwrite(&data, sizeof(data), 1, fout);
        }
    }
    fclose(fin);
    fclose(fout);
    remove(tempFilename);
    free_hashmap();
    return 0;
}
