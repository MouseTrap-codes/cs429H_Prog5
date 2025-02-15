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

/*
  -------------------------------------------------------
     GLOBALS & STRUCTS
  -------------------------------------------------------
*/

// ---------- Label map ----------
typedef struct {
    char label[50];
    int address;             // e.g. 0x1000 -> 4096
    UT_hash_handle hh;
} LabelAddress;

static LabelAddress *labelMap = NULL;

void addLabel(const char *label, int address) {
    LabelAddress *entry = (LabelAddress*)malloc(sizeof(LabelAddress));
    if (!entry) {
        fprintf(stderr, "Error: malloc failed in addLabel.\n");
        exit(1);
    }
    strncpy(entry->label, label, sizeof(entry->label) - 1);
    entry->label[sizeof(entry->label) - 1] = '\0';
    entry->address = address;
    HASH_ADD_STR(labelMap, label, entry);
}

LabelAddress* findLabel(const char *label) {
    LabelAddress *entry = NULL;
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

// ---------- For partial-file cleanup on error ----------
static FILE *g_fout = NULL;
static char g_outFilename[1024] = {0};

// If an error arises mid-assembly, remove partial .tko and exit
static void abortAssembly(void) {
    if (g_fout) {
        fclose(g_fout);
        g_fout = NULL;
    }
    unlink(g_outFilename);  // remove partial .tko
    exit(1);
}

// ---------- Utility: trim leading/trailing space ----------
static void trim(char *s) {
    // leading
    char *p = s;
    while (isspace((unsigned char)*p)) {
        p++;
    }
    if (p != s) {
        memmove(s, p, strlen(p) + 1);
    }
    // trailing
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len-1])) {
        s[len-1] = '\0';
        len--;
    }
}

// ---------- Convert 32-bit => 32-char binary, then parse that => uint32 ----------
static void intToBinaryStr(unsigned int value, int width, char *outStr) {
    for (int i = width - 1; i >= 0; i--) {
        outStr[width - 1 - i] = ((value >> i) & 1) ? '1' : '0';
    }
    outStr[width] = '\0';
}

static uint32_t binStrToUint32(const char *binStr) {
    uint32_t value = 0;
    for (int i = 0; i < 32; i++) {
        value <<= 1;
        if (binStr[i] == '1') {
            value |= 1;
        }
    }
    return value;
}

/*
  -------------------------------------------------------
     PASS 1: Parse .tk file, build label map, compute PC
  -------------------------------------------------------
*/
static void pass1(const char *filename) {
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
        if (strncmp(line, ".code", 5) == 0) {
            section = CODE;
            continue;
        } else if (strncmp(line, ".data", 5) == 0) {
            section = DATA;
            continue;
        }

        // If line starts with ':', parse label plus leftover instructions
        if (line[0] == ':') {
            // Extract label name after the colon
            int i = 1, j = 0;
            char label[50];
            while (line[i] && !isspace((unsigned char)line[i])) {
                if (j < 49) label[j++] = line[i];
                i++;
            }
            label[j] = '\0';
            trim(label);

            // record label => labelMap
            addLabel(label, pc);

            // skip spaces after label
            while (isspace((unsigned char)line[i])) i++;
            // leftover => code or data
            if (line[i] != '\0') {
                // shift leftover code to front of 'line'
                memmove(line, &line[i], strlen(&line[i]) + 1);
            } else {
                // no leftover
                line[0] = '\0';
            }
        }

        // If line is empty after label parse => skip
        if (line[0] == '\0') {
            continue;
        }

        // Increase PC
        if (section == CODE) {
            // Check first token
            char token[16];
            sscanf(line, "%15s", token);
            if (!strcmp(token, "ld")) {
                pc += 48;  // 12 instructions => 48 bytes
            } else if (!strcmp(token, "push") ||
                       !strcmp(token, "pop"))
            {
                pc += 8;   // 2 instructions => 8 bytes
            } else {
                pc += 4;   // normal => 4 bytes
            }
        } else if (section == DATA) {
            // each data => 8 bytes
            pc += 8;
        }
    }
    fclose(fin);
}

/*
  -------------------------------------------------------
    Instruction table: opcodes, formats
  -------------------------------------------------------
*/
typedef struct {
    char name[16];
    int  opcode;
    const char *format;
    UT_hash_handle hh;
} InstructionEntry;

static InstructionEntry *instMap = NULL;

static void addInst(const char *name, int opcode, const char *format) {
    InstructionEntry *e = (InstructionEntry*)malloc(sizeof(InstructionEntry));
    if (!e) {
        fprintf(stderr, "malloc error\n");
        exit(1);
    }
    strncpy(e->name, name, sizeof(e->name)-1);
    e->name[sizeof(e->name)-1] = '\0';
    e->opcode = opcode;
    e->format = format;
    HASH_ADD_STR(instMap, name, e);
}

static void freeInstMap() {
    InstructionEntry *cur, *tmp;
    HASH_ITER(hh, instMap, cur, tmp) {
        HASH_DEL(instMap, cur);
        free(cur);
    }
}

static void populateInstMap() {
    instMap = NULL;
    // Integer arithmetic
    addInst("add",   0x18, "rd rs rt");
    addInst("addi",  0x19, "rd L");   // unsigned immediate
    addInst("sub",   0x1a, "rd rs rt");
    addInst("subi",  0x1b, "rd L");   // unsigned immediate
    addInst("mul",   0x1c, "rd rs rt");
    addInst("div",   0x1d, "rd rs rt");
    // Logic
    addInst("and",   0x0,  "rd rs rt");
    addInst("or",    0x1,  "rd rs rt");
    addInst("xor",   0x2,  "rd rs rt");
    addInst("not",   0x3,  "rd rs");
    addInst("shftr", 0x4,  "rd rs rt");
    addInst("shftri",0x5,  "rd L");   // unsigned
    addInst("shftl", 0x6,  "rd rs rt");
    addInst("shftli",0x7,  "rd L");   // unsigned
    // Control
    addInst("br",    0x8,  "rd");
    addInst("brnz",  0xb,  "rd rs");
    // call rd
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

/*
  -------------------------------------------------------
    Assembling "brr" / "mov" / standard instructions
  -------------------------------------------------------
*/
static void assembleBrrOperand(const char *operand, char *binStr) {
    // brr => either opcode=0x9 (brr rX => pc=pc+rX) or 0xa (brr imm => pc=pc+imm)
    while (isspace((unsigned char)*operand)) operand++;
    int opcode, reg=0, imm=0;
    if (operand[0] == 'r') {
        // register
        opcode = 0x9;
        reg = strtol(operand+1,NULL,0);
    } else {
        // immediate
        opcode = 0xa;
        imm = strtol(operand,NULL,0); // signed
    }
    unsigned int inst = (opcode<<27) | (reg<<22) | ((imm & 0xFFF));
    char tmp[33];
    intToBinaryStr(inst, 32, tmp);
    strcpy(binStr, tmp);
}

// 4 forms of mov
//  - (rD)(L), rS   => opcode=0x13
//  - rD, (rS)(L)   => opcode=0x10
//  - rD, rS        => opcode=0x11
//  - rD, L         => opcode=0x12 (unsigned)
static void assembleMov(const char *line, char *binStr) {
    char mnemonic[16], token1[64], token2[64];
    if (sscanf(line, "%15s %63[^,], %63s", mnemonic, token1, token2)<3) {
        strcpy(binStr,"ERROR");
        return;
    }
    trim(token1); trim(token2);

    int opcode=0, rd=0, rs=0, rt=0, imm=0;

    if (token1[0] == '(') {
        // form (4): mov (rD)(L), rS => store
        opcode = 0x13;
        // parse (rXX)(offset)
        // simpler approach => check " (r31)(-8) " style
        // find r
        char *pR = strchr(token1, 'r');
        if (!pR) { strcpy(binStr,"ERROR"); return; }
        rd = strtol(pR+1,NULL,0);

        // find second '(' => typically ")(" pattern => offset
        char *paren2 = strstr(token1, ")(");
        if (!paren2) {
            // offset=0 if none
            imm=0;
        } else {
            char offsetBuf[32];
            char *startOff = paren2+2; // skip ")("
            char *endParen = strrchr(token1,')');
            if (!endParen || endParen<=startOff) {
                strcpy(binStr,"ERROR");
                return;
            }
            size_t length = endParen - startOff;
            if (length>=sizeof(offsetBuf)) {
                strcpy(binStr,"ERROR");
                return;
            }
            strncpy(offsetBuf, startOff, length);
            offsetBuf[length] = '\0';
            imm = (int)strtol(offsetBuf,NULL,0); // signed offset
        }
        // parse token2 => must be rX
        if (token2[0] != 'r') {
            strcpy(binStr,"ERROR");
            return;
        }
        rs = strtol(token2+1,NULL,0);
    }
    else {
        // token1 => "rD"
        if (token1[0] != 'r') {
            strcpy(binStr,"ERROR");
            return;
        }
        rd = strtol(token1+1,NULL,0);

        if (token2[0] == '(') {
            // form (1): mov rD, (rS)(L) => load
            opcode=0x10;
            char *pR = strchr(token2,'r');
            if(!pR){ strcpy(binStr,"ERROR"); return; }
            rs = strtol(pR+1,NULL,0);
            char *paren2 = strstr(token2, ")(");
            if(!paren2){
                imm=0; // if no )(
            } else {
                char offsetBuf[32];
                char *startOff=paren2+2;
                char *endParen=strrchr(token2,')');
                if(!endParen||endParen<=startOff){
                    strcpy(binStr,"ERROR");
                    return;
                }
                size_t length=endParen-startOff;
                if(length>=sizeof(offsetBuf)){
                    strcpy(binStr,"ERROR");
                    return;
                }
                strncpy(offsetBuf,startOff,length);
                offsetBuf[length]='\0';
                imm=strtol(offsetBuf,NULL,0);
            }
        }
        else if (token2[0] == 'r') {
            // form (2): mov rD, rS => opcode=0x11
            opcode=0x11;
            rs=strtol(token2+1,NULL,0);
        }
        else {
            // form (3): mov rD, L => opcode=0x12 => unsigned
            if(token2[0]=='-'){
                fprintf(stderr,"Error: negative immediate not allowed in mov rD, L\n");
                abortAssembly();
            }
            opcode=0x12;
            imm=strtol(token2,NULL,0);
        }
    }
    unsigned int inst = (opcode<<27)|(rd<<22)|(rs<<17)|(rt<<12)|((imm & 0xFFF));
    char tmp[33];
    intToBinaryStr(inst,32,tmp);
    strcpy(binStr,tmp);
}

static void assembleStandard(const char *line, char *binStr) {
    char mnemonic[16], op1[16], op2[16], op3[16], op4[16];
    int num = sscanf(line, "%15s %15s %15s %15s %15s",
                     mnemonic, op1, op2, op3, op4);
    if(num<1){
        strcpy(binStr,"ERROR");
        return;
    }

    // find entry in instMap
    InstructionEntry *e=NULL;
    HASH_FIND_STR(instMap, mnemonic, e);
    if(!e){
        strcpy(binStr,"ERROR");
        return;
    }
    int opcode=e->opcode, rd=0, rs=0, rt=0, imm=0;

    // If it has format "rd L" => check negative
    // that hits addi, subi, shftli, shftri, etc.
    if(!strcmp(e->format,"rd L") && num>=3){
        // e.g. "addi r1 -10" => not allowed => error
        if(op2[0]=='-'){
            fprintf(stderr,"Error: negative immediate not allowed for %s\n", mnemonic);
            abortAssembly();
        }
    }

    // parse
    if(!strcmp(e->format,"rd rs rt") && num>=4){
        rd=(op1[0]=='r')? strtol(op1+1,NULL,0):0;
        rs=(op2[0]=='r')? strtol(op2+1,NULL,0):0;
        rt=(op3[0]=='r')? strtol(op3+1,NULL,0):0;
    }
    else if(!strcmp(e->format,"rd L") && num>=3){
        rd=(op1[0]=='r')? strtol(op1+1,NULL,0):0;
        imm=strtol(op2,NULL,0);
    }
    else if(!strcmp(e->format,"rd rs") && num>=3){
        rd=(op1[0]=='r')? strtol(op1+1,NULL,0):0;
        rs=(op2[0]=='r')? strtol(op2+1,NULL,0):0;
    }
    else if(!strcmp(e->format,"rd rs rt L") && num>=5){
        rd=(op1[0]=='r')? strtol(op1+1,NULL,0):0;
        rs=(op2[0]=='r')? strtol(op2+1,NULL,0):0;
        rt=(op3[0]=='r')? strtol(op3+1,NULL,0):0;
        imm=strtol(op4,NULL,0);
    }
    else if(!strcmp(e->format,"rd") && num>=2){
        rd=(op1[0]=='r')? strtol(op1+1,NULL,0):0;
    }
    else if(!strcmp(e->format,"")==0){
        // e.g. return => no operands
    }
    else {
        strcpy(binStr,"ERROR");
        return;
    }

    // build bits
    unsigned int inst=(opcode<<27)|(rd<<22)|(rs<<17)|(rt<<12)|((imm&0xFFF));
    char tmp[33];
    intToBinaryStr(inst,32,tmp);
    strcpy(binStr, tmp);
}

static void assembleInstruction(const char *line, char *binStr) {
    char mnemonic[16];
    mnemonic[0]='\0';
    sscanf(line,"%15s",mnemonic);

    if(!strcmp(mnemonic,"mov")){
        assembleMov(line,binStr);
    }
    else if(!strcmp(mnemonic,"brr")){
        // skip 'brr' => parse operand
        const char *p=line+3;
        while(isspace((unsigned char)*p)) p++;
        assembleBrrOperand(p,binStr);
    }
    else {
        assembleStandard(line,binStr);
    }
}

/*
  -------------------------------------------------------
    Macro expansions (ld, push, pop, in, out, clr, halt)
  -------------------------------------------------------
*/
static void parseMacro(const char *line, FILE *outStream) {
    regex_t regex;
    regmatch_t matches[3];
    char op[16];
    if(sscanf(line,"%15s",op)!=1){
        // fallback => just write
        fprintf(outStream, "%s\n", line);
        return;
    }

    // ---------- ld ----------
    if(!strcmp(op,"ld")){
        const char *pattern="^[[:space:]]*ld[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*(\\S+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)){
            fprintf(outStream,"%s\n",line);
            return;
        }
        if(!regexec(&regex,line,3,matches,0)){
            char regBuf[16], immBuf[64];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=strtol(regBuf,NULL,0);

            len=matches[2].rm_eo - matches[2].rm_so;
            strncpy(immBuf, line+matches[2].rm_so,len);
            immBuf[len]='\0';

            // check if negative => error
            if(immBuf[0]=='-'){
                fprintf(stderr,"Error: negative immediate not allowed in ld macro\n");
                regfree(&regex);
                abortAssembly();
            }

            // can be label or numeric
            LabelAddress *labEnt=NULL;
            uint64_t immVal=0;
            if(!isdigit((unsigned char)immBuf[0])){
                // label
                labEnt=findLabel(immBuf);
                if(!labEnt){
                    fprintf(stderr,"Error: label '%s' not found\n",immBuf);
                    regfree(&regex);
                    abortAssembly();
                }
                immVal=labEnt->address;
            } else {
                errno=0;
                uint64_t tmpVal=strtoull(immBuf,NULL,0);
                if(errno==ERANGE){
                    fprintf(stderr,"Error: ld immediate out of range => %s\n",immBuf);
                    regfree(&regex);
                    abortAssembly();
                }
                immVal=tmpVal;
            }
            // Expand to 12 instructions
            fprintf(outStream,"xor r%d r%d r%d\n",rD,rD,rD);
            uint64_t top12   = (immVal>>52) & 0xFFF;
            uint64_t mid12a  = (immVal>>40) & 0xFFF;
            uint64_t mid12b  = (immVal>>28) & 0xFFF;
            uint64_t mid12c  = (immVal>>16) & 0xFFF;
            uint64_t mid4    = (immVal>>4)  & 0xFFF;
            uint64_t last4   = immVal & 0xF;

            fprintf(outStream,"addi r%d %llu\n", rD, (unsigned long long)top12);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n", rD, (unsigned long long)mid12a);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n", rD, (unsigned long long)mid12b);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n", rD, (unsigned long long)mid12c);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n", rD, (unsigned long long)mid4);
            fprintf(outStream,"shftli r%d 4\n",rD);
            fprintf(outStream,"addi r%d %llu\n", rD, (unsigned long long)last4);
        }
        else {
            // fallback
            fprintf(outStream,"%s\n",line);
        }
        regfree(&regex);
    }
    // ---------- push ----------
    else if(!strcmp(op,"push")){
        const char *pattern="^[[:space:]]*push[[:space:]]+r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)){
            fprintf(outStream,"%s\n",line);
            return;
        }
        if(!regexec(&regex,line,2,matches,0)){
            char regBuf[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=strtol(regBuf,NULL,0);
            // expand
            fprintf(outStream,"mov (r31)(-8), r%d\n",rD);
            fprintf(outStream,"subi r31 8\n");
        } else {
            fprintf(outStream,"%s\n",line);
        }
        regfree(&regex);
    }
    // ---------- pop ----------
    else if(!strcmp(op,"pop")){
        const char *pattern="^[[:space:]]*pop[[:space:]]+r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)){
            fprintf(outStream,"%s\n",line);
            return;
        }
        if(!regexec(&regex,line,2,matches,0)){
            char regBuf[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=strtol(regBuf,NULL,0);
            // expand
            fprintf(outStream,"mov r%d, (r31)(0)\n",rD);
            fprintf(outStream,"addi r31 8\n");
        } else {
            fprintf(outStream,"%s\n",line);
        }
        regfree(&regex);
    }
    // ---------- in ----------
    else if(!strcmp(op,"in")){
        // in rD, rS => "priv rD rS r0 3"
        const char *pattern="^[[:space:]]*in[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)){
            fprintf(outStream,"%s\n",line);
            return;
        }
        if(!regexec(&regex,line,3,matches,0)){
            char regBuf1[16], regBuf2[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf1,line+matches[1].rm_so,len);
            regBuf1[len]='\0';
            len=matches[2].rm_eo - matches[2].rm_so;
            strncpy(regBuf2,line+matches[2].rm_so,len);
            regBuf2[len]='\0';
            int rD=strtol(regBuf1,NULL,0);
            int rS=strtol(regBuf2,NULL,0);
            fprintf(outStream,"priv r%d r%d r0 3\n",rD,rS);
        } else {
            fprintf(outStream,"%s\n",line);
        }
        regfree(&regex);
    }
    // ---------- out ----------
    else if(!strcmp(op,"out")){
        // out rD, rS => "priv rD rS r0 4"
        const char *pattern="^[[:space:]]*out[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)){
            fprintf(outStream,"%s\n",line);
            return;
        }
        if(!regexec(&regex,line,3,matches,0)){
            char regBuf1[16], regBuf2[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf1,line+matches[1].rm_so,len);
            regBuf1[len]='\0';
            len=matches[2].rm_eo - matches[2].rm_so;
            strncpy(regBuf2,line+matches[2].rm_so,len);
            regBuf2[len]='\0';
            int rD=strtol(regBuf1,NULL,0);
            int rS=strtol(regBuf2,NULL,0);
            fprintf(outStream,"priv r%d r%d r0 4\n",rD,rS);
        } else {
            fprintf(outStream,"%s\n",line);
        }
        regfree(&regex);
    }
    // ---------- clr ----------
    else if(!strcmp(op,"clr")){
        // clr rD => "xor rD rD rD"
        const char *pattern="^[[:space:]]*clr[[:space:]]+r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)){
            fprintf(outStream,"%s\n",line);
            return;
        }
        if(!regexec(&regex,line,2,matches,0)){
            char regBuf[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=strtol(regBuf,NULL,0);
            fprintf(outStream,"xor r%d r%d r%d\n",rD,rD,rD);
        } else {
            fprintf(outStream,"%s\n",line);
        }
        regfree(&regex);
    }
    // ---------- halt ----------
    else if(!strcmp(op,"halt")){
        // => "priv r0 r0 r0 0"
        const char *pattern="^[[:space:]]*halt[[:space:]]*$";
        if(regcomp(&regex,pattern,REG_EXTENDED)){
            fprintf(outStream,"%s\n",line);
            return;
        }
        if(!regexec(&regex,line,0,NULL,0)){
            fprintf(outStream,"priv r0 r0 r0 0\n");
        } else {
            fprintf(outStream,"%s\n",line);
        }
        regfree(&regex);
    }
    else {
        // not a recognized macro => pass through
        fprintf(outStream,"%s\n",line);
    }
}

/*
  -------------------------------------------------------
    Final pass: Expand macros, assemble => .tko binary
  -------------------------------------------------------
*/
static void finalAssemble(const char *infile, const char *outfile) {
    FILE *fin = fopen(infile,"r");
    if(!fin){
        perror("finalAssemble fopen");
        exit(1);
    }
    strncpy(g_outFilename,outfile,sizeof(g_outFilename)-1);
    g_outFilename[sizeof(g_outFilename)-1]='\0';
    g_fout = fopen(outfile,"wb");
    if(!g_fout){
        perror("finalAssemble output fopen");
        fclose(fin);
        exit(1);
    }

    enum { CODE, DATA } currentSection=CODE;
    char line[1024];
    char assembled[64];

    while(fgets(line,sizeof(line),fin)) {
        line[strcspn(line,"\n")]='\0';
        trim(line);
        if(line[0]=='\0' || line[0]==';') {
            continue;
        }
        if(!strcmp(line,".code")) {
            currentSection=CODE;
            continue;
        }
        else if(!strcmp(line,".data")) {
            currentSection=DATA;
            continue;
        }

        // If line begins with colon => label + leftover code
        if(line[0]==':'){
            // parse label
            int i=1, j=0;
            char lab[50];
            while(line[i] && !isspace((unsigned char)line[i])) {
                if(j<49) lab[j++]=line[i];
                i++;
            }
            lab[j]='\0';
            trim(lab);
            LabelAddress *ent=findLabel(lab);
            if(!ent) {
                fprintf(stderr,"Error: label '%s' not found\n",lab);
                fclose(fin);
                abortAssembly();
            }
            // skip whitespace
            while(isspace((unsigned char)line[i])) i++;
            if(line[i]!='\0'){
                memmove(line,&line[i],strlen(&line[i])+1);
            } else {
                line[0]='\0';
            }
        }
        if(line[0]=='\0'){
            // no leftover
            continue;
        }

        if(currentSection==CODE) {
            // check if macro
            char token[16];
            token[0]='\0';
            sscanf(line,"%15s",token);

            if(!strcmp(token,"ld") || !strcmp(token,"push") ||
               !strcmp(token,"pop")|| !strcmp(token,"in")   ||
               !strcmp(token,"out")|| !strcmp(token,"clr")  ||
               !strcmp(token,"halt"))
            {
                // expand macro => multiple lines => assemble
                char macroBuf[4096]="";
                FILE *tempStream=fmemopen(macroBuf,sizeof(macroBuf),"w");
                if(!tempStream){
                    perror("fmemopen");
                    fclose(fin);
                    abortAssembly();
                }
                parseMacro(line,tempStream);
                fflush(tempStream);
                fclose(tempStream);

                // now assemble each expanded line
                char *exLine=strtok(macroBuf,"\n");
                while(exLine){
                    trim(exLine);
                    if(*exLine){
                        assembleInstruction(exLine,assembled);
                        if(!strcmp(assembled,"ERROR")){
                            fprintf(stderr,"Error assembling line: %s\n", exLine);
                            fclose(fin);
                            abortAssembly();
                        }
                        uint32_t w=binStrToUint32(assembled);
                        fwrite(&w,sizeof(w),1,g_fout);
                    }
                    exLine=strtok(NULL,"\n");
                }
            }
            else if(!strcmp(token,"mov")) {
                assembleMov(line,assembled);
                if(!strcmp(assembled,"ERROR")){
                    fprintf(stderr,"Error assembling line: %s\n",line);
                    fclose(fin);
                    abortAssembly();
                }
                uint32_t w=binStrToUint32(assembled);
                fwrite(&w,sizeof(w),1,g_fout);
            }
            else if(!strcmp(token,"brr")){
                const char *p=line+3;
                while(isspace((unsigned char)*p)) p++;
                assembleBrrOperand(p,assembled);
                if(!strcmp(assembled,"ERROR")){
                    fprintf(stderr,"Error assembling line: %s\n",line);
                    fclose(fin);
                    abortAssembly();
                }
                uint32_t w=binStrToUint32(assembled);
                fwrite(&w,sizeof(w),1,g_fout);
            }
            else {
                // standard
                assembleStandard(line,assembled);
                if(!strcmp(assembled,"ERROR")){
                    fprintf(stderr,"Error assembling line: %s\n",line);
                    fclose(fin);
                    abortAssembly();
                }
                uint32_t w=binStrToUint32(assembled);
                fwrite(&w,sizeof(w),1,g_fout);
            }
        }
        else {
            // DATA
            uint64_t dVal=strtoull(line,NULL,0);
            fwrite(&dVal,sizeof(dVal),1,g_fout);
        }
    }

    fclose(fin);
    fclose(g_fout);
    g_fout=NULL; 
}

/*
  -------------------------------------------------------
                           main
  -------------------------------------------------------
*/
int main(int argc, char *argv[]) {
    if(argc!=3){
        fprintf(stderr,"Usage: %s <assembly_file> <output_file>\n",argv[0]);
        return 1;
    }

    pass1(argv[1]);        // gather labels, compute addresses
    populateInstMap();     // build opcode table

    finalAssemble(argv[1],argv[2]);

    freeInstMap();
    freeLabelMap();
    return 0;
}
