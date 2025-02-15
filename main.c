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

// ------------------------------------------------------------------
//                          Label Map
// ------------------------------------------------------------------
typedef struct {
    char label[50];
    int address; 
    UT_hash_handle hh;
} LabelAddress;

static LabelAddress *labelMap = NULL;

static void addLabel(const char *label, int address) {
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

static LabelAddress* findLabel(const char *label) {
    LabelAddress *entry;
    HASH_FIND_STR(labelMap, label, entry);
    return entry;
}

static void freeLabelMap() {
    LabelAddress *cur, *tmp;
    HASH_ITER(hh, labelMap, cur, tmp) {
        HASH_DEL(labelMap, cur);
        free(cur);
    }
}

// ------------------------------------------------------------------
//                       Global Error Handling
// ------------------------------------------------------------------
static FILE *g_fout = NULL;
static char g_outFilename[1024];

static void abortAssembly(void) {
    if (g_fout) {
        fclose(g_fout);
        g_fout = NULL;
    }
    unlink(g_outFilename);
    exit(1);
}

// ------------------------------------------------------------------
//                       Utility Functions
// ------------------------------------------------------------------
static void trim(char *s) {
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

// ------------------------------------------------------------------
//    parseRegister(): ensures "r<number>" with 0 <= number <= 31
// ------------------------------------------------------------------
static int parseRegister(const char *str) {
    // str should be like "r0", "r15", "r31", etc.
    // We'll check:
    //   1) starts with 'r'
    //   2) next is digits only
    //   3) parse, check 0..31
    // If fail => error -> abortAssembly
    if (str[0] != 'r') {
        fprintf(stderr, "Error: invalid register format '%s'\n", str);
        abortAssembly();
    }
    const char *digits = str + 1;
    if (*digits == '\0') {
        fprintf(stderr, "Error: missing digits after 'r' in '%s'\n", str);
        abortAssembly();
    }
    // confirm all are digits
    for (const char *p = digits; *p; p++) {
        if (!isdigit((unsigned char)*p)) {
            fprintf(stderr, "Error: invalid register format '%s'\n", str);
            abortAssembly();
        }
    }
    errno = 0;
    long val = strtol(digits, NULL, 10);
    if (errno == ERANGE || val < 0 || val > 31) {
        fprintf(stderr, "Error: register out of range '%s'\n", str);
        abortAssembly();
    }
    return (int) val;
}

// ------------------------------------------------------------------
//               Pass 1: Build Label Map & PC
// ------------------------------------------------------------------
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
        if (line[0] == '.') {
            if (!strncmp(line, ".code", 5)) {
                section = CODE;
            } else if (!strncmp(line, ".data", 5)) {
                section = DATA;
            }
            continue;
        }
        if (line[0] == ':') {
            // label
            char label[50];
            if (sscanf(line + 1, "%49s", label) == 1) {
                addLabel(label, pc);
            }
            continue;
        }
        if (section == CODE) {
            char temp[16];
            sscanf(line, "%15s", temp);
            if (!strcmp(temp, "ld")) {
                pc += 48; 
            } else if (!strcmp(temp, "push") || !strcmp(temp, "pop")) {
                pc += 8;  
            } else {
                pc += 4;  
            }
        } else if (section == DATA) {
            pc += 8;
        }
    }
    fclose(fin);
}

// ------------------------------------------------------------------
// Instruction Table
// ------------------------------------------------------------------
typedef struct {
    char name[16];
    int  opcode;
    const char *format; 
    UT_hash_handle hh;
} InstructionEntry;

static InstructionEntry *instMap = NULL;

static void addInst(const char *name, int opcode, const char *format) {
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

static void freeInstMap() {
    InstructionEntry *cur, *tmp;
    HASH_ITER(hh, instMap, cur, tmp) {
        HASH_DEL(instMap, cur);
        free(cur);
    }
}

static void populateInstMap() {
    instMap = NULL;
    // integer arithmetic
    addInst("add",   0x18, "rd rs rt");
    addInst("addi",  0x19, "rd L");  
    addInst("sub",   0x1a, "rd rs rt");
    addInst("subi",  0x1b, "rd L");  
    addInst("mul",   0x1c, "rd rs rt");
    addInst("div",   0x1d, "rd rs rt");
    // logic
    addInst("and",   0x0,  "rd rs rt");
    addInst("or",    0x1,  "rd rs rt");
    addInst("xor",   0x2,  "rd rs rt");
    addInst("not",   0x3,  "rd rs");
    addInst("shftr", 0x4,  "rd rs rt");
    addInst("shftri",0x5,  "rd L");  
    addInst("shftl", 0x6,  "rd rs rt");
    addInst("shftli",0x7,  "rd L");  
    // control
    addInst("br",    0x8,  "rd");
    addInst("brnz",  0xb,  "rd rs");
    addInst("call",  0xc,  "rd"); 
    addInst("return",0xd,  "");
    addInst("brgt",  0xe,  "rd rs rt");
    // priv
    addInst("priv",  0xf,  "rd rs rt L");
    // float
    addInst("addf",  0x14, "rd rs rt");
    addInst("subf",  0x15, "rd rs rt");
    addInst("mulf",  0x16, "rd rs rt");
    addInst("divf",  0x17, "rd rs rt");
}

// ------------------------------------------------------------------
//  assembleBrrOperand
// ------------------------------------------------------------------
static void assembleBrrOperand(const char *operand, char *binStr) {
    while (isspace((unsigned char)*operand)) operand++;
    int opcode, reg=0, imm=0;
    if (operand[0] == 'r') {
        opcode = 0x9;
        reg = parseRegister(operand);  // Validate
    } else {
        opcode = 0xa;
        imm = (int)strtol(operand, NULL, 0);
    }
    unsigned int inst = ((opcode<<27)|(reg<<22)|((imm&0xFFF)));
    char tmp[33]; 
    intToBinaryStr(inst,32,tmp);
    strcpy(binStr,tmp);
}

// ------------------------------------------------------------------
//  assembleMov
// ------------------------------------------------------------------
static void assembleMov(const char *line, char *binStr) {
    char mnemonic[10], token1[64], token2[64];
    if (sscanf(line, "%s %63[^,], %63s", mnemonic, token1, token2) < 3) {
        strcpy(binStr, "ERROR");
        return;
    }
    trim(token1);
    trim(token2);

    int opcode=0, rd=0, rs=0, rt=0, imm=0;

    if (token1[0] == '(') {
        // mov (rD)(L), rS
        opcode = 0x13;
        // parse rD
        char *pR = strchr(token1,'r');
        if (!pR) {
            strcpy(binStr,"ERROR");
            return;
        }
        rd = parseRegister(pR);  // check format & range
        // parse offset
        char *paren2 = strstr(token1,")(");
        if (!paren2) {
            imm=0;
        } else {
            char offsetBuf[32];
            char *startOffset = paren2+2;
            char *endParen = strrchr(token1,')');
            if (!endParen || endParen <= startOffset) {
                strcpy(binStr,"ERROR");
                return;
            }
            size_t length = endParen - startOffset;
            if (length >= sizeof(offsetBuf)) {
                strcpy(binStr,"ERROR");
                return;
            }
            strncpy(offsetBuf, startOffset, length);
            offsetBuf[length]='\0';
            imm=(int)strtol(offsetBuf,NULL,0);
        }
        // parse rS
        rs = parseRegister(token2);
    }
    else {
        // token1 => rD
        rd = parseRegister(token1);
        if (token2[0]=='(') {
            // mov rD, (rS)(L)
            opcode=0x10;
            char *pR = strchr(token2,'r');
            if (!pR) {
                strcpy(binStr,"ERROR");
                return;
            }
            rs = parseRegister(pR);
            // offset
            char *paren2 = strstr(token2,")(");
            if(!paren2) {
                imm=0;
            } else {
                char offsetBuf[32];
                char *startOffset=paren2+2;
                char *endParen=strrchr(token2,')');
                if(!endParen||endParen<=startOffset){
                    strcpy(binStr,"ERROR");
                    return;
                }
                size_t length=endParen-startOffset;
                if(length>=sizeof(offsetBuf)){
                    strcpy(binStr,"ERROR");
                    return;
                }
                strncpy(offsetBuf,startOffset,length);
                offsetBuf[length]='\0';
                imm=(int)strtol(offsetBuf,NULL,0);
            }
        }
        else if (token2[0]=='r') {
            // mov rD, rS
            opcode=0x11;
            rs = parseRegister(token2);
        }
        else {
            // mov rD, L
            if(token2[0]=='-'){
                fprintf(stderr,"Error: negative immediate not allowed for mov rD, L\n");
                abortAssembly();
            }
            opcode=0x12;
            imm=(int)strtol(token2,NULL,0);
        }
    }

    unsigned int inst = (opcode<<27)|(rd<<22)|(rs<<17)|(rt<<12)|((imm&0xFFF));
    char tmp[33];
    intToBinaryStr(inst,32,tmp);
    strcpy(binStr,tmp);
}

// ------------------------------------------------------------------
//  assembleStandard
// ------------------------------------------------------------------
static void assembleStandard(const char *line, char *binStr) {
    char mnemonic[16], op1[16], op2[16], op3[16], op4[16];
    int num = sscanf(line, "%15s %15s %15s %15s %15s",
                     mnemonic, op1, op2, op3, op4);

    InstructionEntry *e=NULL;
    HASH_FIND_STR(instMap, mnemonic, e);
    if(!e){
        strcpy(binStr,"ERROR");
        return;
    }
    int opcode=e->opcode, rd=0, rs=0, rt=0, imm=0;

    // check for negative if it's "rd L" for an unsigned immediate
    if(!strcmp(e->format,"rd L") && num>=3){
        if(op2[0]=='-'){
            fprintf(stderr,"Error: negative immediate not allowed for %s\n",mnemonic);
            abortAssembly();
        }
    }

    // parse according to format
    if(!strcmp(e->format,"rd rs rt") && num>=4){
        rd = parseRegister(op1);
        rs = parseRegister(op2);
        rt = parseRegister(op3);
    }
    else if(!strcmp(e->format,"rd L") && num>=3){
        rd = parseRegister(op1);
        imm=(int)strtol(op2,NULL,0);
    }
    else if(!strcmp(e->format,"rd rs") && num>=3){
        rd = parseRegister(op1);
        rs = parseRegister(op2);
    }
    else if(!strcmp(e->format,"rd rs rt L") && num>=5){
        rd = parseRegister(op1);
        rs = parseRegister(op2);
        rt = parseRegister(op3);
        imm=(int)strtol(op4,NULL,0);
    }
    else if(!strcmp(e->format,"rd") && num>=2){
        rd = parseRegister(op1);
    }
    else if(!strcmp(e->format,"")==0){
        // e.g. return => no operand
    }
    else {
        strcpy(binStr,"ERROR");
        return;
    }

    unsigned int inst=(opcode<<27)|(rd<<22)|(rs<<17)|(rt<<12)|((imm&0xFFF));
    char tmp[33];
    intToBinaryStr(inst,32,tmp);
    strcpy(binStr,tmp);
}

// ------------------------------------------------------------------
//  assembleInstruction dispatch
// ------------------------------------------------------------------
static void assembleInstruction(const char *line, char *binStr) {
    char mnemonic[16];
    mnemonic[0]='\0';
    sscanf(line,"%15s",mnemonic);

    if(!strcmp(mnemonic,"mov")){
        assembleMov(line,binStr);
    }
    else if(!strcmp(mnemonic,"brr")){
        const char *p=line+3;
        while(isspace((unsigned char)*p)) p++;
        assembleBrrOperand(p, binStr);
    }
    else {
        assembleStandard(line, binStr);
    }
}

// ------------------------------------------------------------------
//  parseMacro
// ------------------------------------------------------------------
// We do rigorous checks w/ regex. If something fails => abortAssembly.
static void parseMacro(const char *line, FILE *outStream) {
    regex_t regex;
    regmatch_t matches[3];
    char op[16];
    if (sscanf(line, "%15s", op) != 1) {
        fprintf(stderr,"Error: invalid macro usage => %s\n",line);
        abortAssembly();
    }

    // ------------ ld -------------
    if(!strcmp(op,"ld")){
        const char*pat="^[[:space:]]*ld[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*(\\S+)";
        if(regcomp(&regex,pat,REG_EXTENDED)){
            fprintf(stderr,"Regex error for ld\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,3,matches,0)){
            char regBuf[16], immBuf[64];
            int rD;
            uint64_t imm;
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            // parse register
            // check range
            rD=(int)strtol(regBuf,NULL,0);
            if(rD<0||rD>31){
                fprintf(stderr,"Error: register out of range 'r%d' in ld\n",rD);
                regfree(&regex);
                abortAssembly();
            }

            len=matches[2].rm_eo - matches[2].rm_so;
            strncpy(immBuf,line+matches[2].rm_so,len);
            immBuf[len]='\0';
            if(immBuf[0]=='-'){
                fprintf(stderr,"Error: negative immediate not allowed in ld macro\n");
                regfree(&regex);
                abortAssembly();
            }
            if(!isdigit((unsigned char)immBuf[0])){
                LabelAddress *entry=findLabel(immBuf);
                if(!entry){
                    fprintf(stderr,"Error: label '%s' not found (ld)\n",immBuf);
                    regfree(&regex);
                    abortAssembly();
                }
                imm=entry->address;
            } else {
                errno=0;
                char*endp=NULL;
                uint64_t val=strtoull(immBuf,&endp,0);
                if(errno==ERANGE){
                    fprintf(stderr,"Error: ld immediate out of range => %s\n",immBuf);
                    regfree(&regex);
                    abortAssembly();
                }
                imm=val;
            }

            // expand
            fprintf(outStream,"xor r%d r%d r%d\n",rD,rD,rD);
            unsigned long long t12 =(imm>>52)&0xFFF;
            unsigned long long m12a=(imm>>40)&0xFFF;
            unsigned long long m12b=(imm>>28)&0xFFF;
            unsigned long long m12c=(imm>>16)&0xFFF;
            unsigned long long m4 =(imm>>4)&0xFFF;
            unsigned long long l4 =(imm&0xF);

            fprintf(outStream,"addi r%d %llu\n",rD,t12);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n",rD,m12a);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n",rD,m12b);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n",rD,m12c);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n",rD,m4);
            fprintf(outStream,"shftli r%d 4\n",rD);
            fprintf(outStream,"addi r%d %llu\n",rD,l4);

        } else {
            fprintf(stderr,"Error: invalid 'ld' usage => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    // ------------- push -----------
    else if(!strcmp(op,"push")){
        const char*pat="^[[:space:]]*push[[:space:]]+r([0-9]+)";
        if(regcomp(&regex,pat,REG_EXTENDED)){
            fprintf(stderr,"Regex error push\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,2,matches,0)){
            char regBuf[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=(int)strtol(regBuf,NULL,0);
            if(rD<0||rD>31){
                fprintf(stderr,"Error: register out of range 'r%d' in push\n",rD);
                regfree(&regex);
                abortAssembly();
            }
            fprintf(outStream,"mov (r31)(-8), r%d\n",rD);
            fprintf(outStream,"subi r31 8\n");
        } else {
            fprintf(stderr,"Error: invalid 'push' => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    // ------------- pop ------------
    else if(!strcmp(op,"pop")){
        const char*pat="^[[:space:]]*pop[[:space:]]+r([0-9]+)";
        if(regcomp(&regex,pat,REG_EXTENDED)){
            fprintf(stderr,"Regex err pop\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,2,matches,0)){
            char regBuf[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=(int)strtol(regBuf,NULL,0);
            if(rD<0||rD>31){
                fprintf(stderr,"Error: register out of range 'r%d' in pop\n",rD);
                regfree(&regex);
                abortAssembly();
            }
            fprintf(outStream,"mov r%d, (r31)(0)\n",rD);
            fprintf(outStream,"addi r31 8\n");
        } else {
            fprintf(stderr,"Error: invalid 'pop' => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    // ------------- in -------------
    else if(!strcmp(op,"in")){
        const char*pat="^[[:space:]]*in[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*r([0-9]+)";
        if(regcomp(&regex,pat,REG_EXTENDED)){
            fprintf(stderr,"Regex err in\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,3,matches,0)){
            char regBuf1[16], regBuf2[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf1,line+matches[1].rm_so,len);
            regBuf1[len]='\0';
            len=matches[2].rm_eo - matches[2].rm_so;
            strncpy(regBuf2,line+matches[2].rm_so,len);
            regBuf2[len]='\0';
            int rD=(int)strtol(regBuf1,NULL,0);
            if(rD<0||rD>31){
                fprintf(stderr,"Error: register out of range 'r%d' in in\n",rD);
                regfree(&regex);
                abortAssembly();
            }
            int rS=(int)strtol(regBuf2,NULL,0);
            if(rS<0||rS>31){
                fprintf(stderr,"Error: register out of range 'r%d' in in\n",rS);
                regfree(&regex);
                abortAssembly();
            }
            fprintf(outStream,"priv r%d r%d r0 3\n",rD,rS);
        } else {
            fprintf(stderr,"Error: invalid 'in' => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    // ------------- out ------------
    else if(!strcmp(op,"out")){
        const char*pat="^[[:space:]]*out[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*r([0-9]+)";
        if(regcomp(&regex,pat,REG_EXTENDED)){
            fprintf(stderr,"Regex err out\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,3,matches,0)){
            char regBuf1[16], regBuf2[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf1,line+matches[1].rm_so,len);
            regBuf1[len]='\0';
            len=matches[2].rm_eo - matches[2].rm_so;
            strncpy(regBuf2,line+matches[2].rm_so,len);
            regBuf2[len]='\0';
            int rD=(int)strtol(regBuf1,NULL,0);
            if(rD<0||rD>31){
                fprintf(stderr,"Error: register out of range 'r%d' in out\n",rD);
                regfree(&regex);
                abortAssembly();
            }
            int rS=(int)strtol(regBuf2,NULL,0);
            if(rS<0||rS>31){
                fprintf(stderr,"Error: register out of range 'r%d' in out\n",rS);
                regfree(&regex);
                abortAssembly();
            }
            fprintf(outStream,"priv r%d r%d r0 4\n",rD,rS);
        } else {
            fprintf(stderr,"Error: invalid 'out' => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    // ------------- clr ------------
    else if(!strcmp(op,"clr")){
        const char*pat="^[[:space:]]*clr[[:space:]]+r([0-9]+)";
        if(regcomp(&regex,pat,REG_EXTENDED)){
            fprintf(stderr,"Regex err clr\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,2,matches,0)){
            char regBuf[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=(int)strtol(regBuf,NULL,0);
            if(rD<0||rD>31){
                fprintf(stderr,"Error: register out of range 'r%d' in clr\n",rD);
                regfree(&regex);
                abortAssembly();
            }
            fprintf(outStream,"xor r%d r%d r%d\n",rD,rD,rD);
        } else {
            fprintf(stderr,"Error: invalid 'clr' => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    // ------------- halt -----------
    else if(!strcmp(op,"halt")){
        const char*pat="^[[:space:]]*halt[[:space:]]*$";
        if(regcomp(&regex,pat,REG_EXTENDED)){
            fprintf(stderr,"Regex err halt\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,0,NULL,0)){
            fprintf(outStream,"priv r0 r0 r0 0\n");
        } else {
            fprintf(stderr,"Error: invalid 'halt' => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    // fallback
    else {
        // If the line starts with e.g. "ld"/"push"/... we handle above,
        // otherwise we pass it along as non-macro
        // or we can forcibly error. 
        // We'll do a pass-through:
        fprintf(outStream,"%s\n",line);
    }
}

// ------------------------------------------------------------------
// finalAssemble
// ------------------------------------------------------------------
static void finalAssemble(const char *infile, const char *outfile){
    FILE *fin = fopen(infile,"r");
    if(!fin){
        perror("finalAssemble fopen");
        exit(1);
    }
    strncpy(g_outFilename,outfile,sizeof(g_outFilename)-1);
    g_outFilename[sizeof(g_outFilename)-1]='\0';

    g_fout=fopen(outfile,"wb");
    if(!g_fout){
        perror("finalAssemble output fopen");
        fclose(fin);
        exit(1);
    }

    enum { CODE, DATA } currentSection=CODE;
    char line[1024];
    char assembled[128];

    while(fgets(line,sizeof(line),fin)){
        line[strcspn(line,"\n")]='\0';
        trim(line);
        if(line[0]=='\0' || line[0]==';') {
            continue;
        }
        if(!strcmp(line,".code")){
            currentSection=CODE;
            continue;
        }
        else if(!strcmp(line,".data")){
            currentSection=DATA;
            continue;
        }
        if(line[0]==':'){
            // skip label lines
            continue;
        }
        // label references e.g. "instr :label"
        char*col=strchr(line,':');
        if(col){
            char lab[50];
            if(sscanf(col+1,"%49s",lab)==1){
                LabelAddress *entry=findLabel(lab);
                if(!entry){
                    fprintf(stderr,"Error: label '%s' not found\n",lab);
                    fclose(fin);
                    abortAssembly();
                }
                *col='\0';
                char temp[256];
                sprintf(temp,"%s0x%x",line,entry->address);
                strcpy(line,temp);
            }
        }

        if(currentSection==CODE){
            char token[16];
            token[0]='\0';
            sscanf(line,"%15s",token);

            if(!strcmp(token,"ld")||
               !strcmp(token,"push")||
               !strcmp(token,"pop")||
               !strcmp(token,"in")||
               !strcmp(token,"out")||
               !strcmp(token,"clr")||
               !strcmp(token,"halt"))
            {
                // expand macro
                char macroExp[4096]="";
                FILE*tempStream=fmemopen(macroExp,sizeof(macroExp),"w");
                if(!tempStream){
                    perror("fmemopen");
                    fclose(fin);
                    abortAssembly();
                }
                parseMacro(line,tempStream);
                fflush(tempStream);
                fclose(tempStream);

                // now assemble each expanded line
                char*exLine=strtok(macroExp,"\n");
                while(exLine){
                    trim(exLine);
                    if(exLine[0]){
                        assembleInstruction(exLine,assembled);
                        if(!strcmp(assembled,"ERROR")){
                            fprintf(stderr,"Error assembling line: %s\n",exLine);
                            fclose(fin);
                            abortAssembly();
                        }
                        uint32_t w=binStrToUint32(assembled);
                        fwrite(&w,sizeof(w),1,g_fout);
                    }
                    exLine=strtok(NULL,"\n");
                }
            }
            else if(!strcmp(token,"mov")){
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
                const char*p=line+3;
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
        else { // DATA
            if(line[0]=='-'){
                fprintf(stderr,"Error: Invalid data: %s\n",line);
                fclose(fin);
                abortAssembly();
            }
            errno=0;
            char*endp=NULL;
            uint64_t val=strtoull(line,&endp,0);
            if(errno==ERANGE){
                fprintf(stderr,"Error: Invalid data: %s\n",line);
                fclose(fin);
                abortAssembly();
            }
            // check leftover
            while(endp && isspace((unsigned char)*endp)) endp++;
            if(!endp || *endp!='\0'){
                fprintf(stderr,"Error: Invalid data: %s\n",line);
                fclose(fin);
                abortAssembly();
            }
            fwrite(&val,sizeof(val),1,g_fout);
        }
    }

    fclose(fin);
    fclose(g_fout);
    g_fout=NULL;
}

// ------------------------------------------------------------------
//                             main
// ------------------------------------------------------------------
int main(int argc, char *argv[]){
    if(argc!=3){
        fprintf(stderr,"Usage: %s <assembly_file> <output_file>\n",argv[0]);
        return 1;
    }
    pass1(argv[1]);
    populateInstMap();
    finalAssemble(argv[1], argv[2]);
    freeInstMap();
    freeLabelMap();
    return 0;
}
