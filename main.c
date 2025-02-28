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
//                          Label Map
// ===================================================================
typedef struct {
    char label[50];
    int address; // e.g., 0x1000 -> 4096
    UT_hash_handle hh;
} LabelAddress;

static LabelAddress *labelMap = NULL;

// ===================================================================
//                     Global Error-Handling
// ===================================================================
static FILE *g_fout = NULL;
static char g_outFilename[1024];

// If we detect an error mid-assembly in Pass 2, remove partial .tko file and exit
static void abortAssembly(void) {
    if (g_fout) {
        fclose(g_fout);
        g_fout = NULL;
    }
    // If g_outFilename is non-empty, remove it
    if (g_outFilename[0] != '\0') {
        unlink(g_outFilename);
    }
    exit(1);
}

// ===================================================================
//                     Label Validation
// ===================================================================
/*
 * Checks if a label name is valid: no spaces, must only contain [A-Za-z0-9_],
 * and must not start with a digit.
 */
static int isValidLabelName(const char *label) {
    // Must start with letter or underscore
    if (!isalpha((unsigned char)label[0]) && label[0] != '_') {
        return 0;
    }
    // Check remaining chars
    for (int i = 1; label[i] != '\0'; i++) {
        if (!isalnum((unsigned char)label[i]) && label[i] != '_') {
            return 0;
        }
    }
    return 1;
}

// ===================================================================
//                Add / Find / Free Label
// ===================================================================
LabelAddress *findLabel(const char *label) {
    LabelAddress *entry = NULL;
    HASH_FIND_STR(labelMap, label, entry);
    return entry;
}

/*
 * Add a label to the labelMap during Pass 1.
 * If the label is invalid or duplicate, print error & exit(1).
 */
void addLabel(const char *label, int address) {
    // Duplicate check
    if (findLabel(label)) {
        fprintf(stderr, "Error: Duplicate label \"%s\"\n", label);
        // For Pass 1, we do NOT call abortAssembly() because
        // there's no output file open yet. Just exit(1).
        exit(1);
    }
    // Validate
    if (!isValidLabelName(label)) {
        fprintf(stderr, "Error: Invalid label name \"%s\"\n", label);
        exit(1);
    }
    // Insert
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

void freeLabelMap() {
    LabelAddress *cur, *tmp;
    HASH_ITER(hh, labelMap, cur, tmp) {
        HASH_DEL(labelMap, cur);
        free(cur);
    }
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
//                  Pass 1: Build Label Map & Compute PC
// ===================================================================
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
                pc += 48;  // ld => 12 instructions => 48 bytes
            } else if (!strcmp(temp, "push") || !strcmp(temp, "pop")) {
                pc += 8;   // push/pop => 2 instructions => 8 bytes
            } else {
                pc += 4;   // normal => 4 bytes
            }
        } else if (section == DATA) {
            pc += 8; // each data item => 8 bytes
        }
    }
    fclose(fin);
}

// ===================================================================
// Instruction Table for Standard Instructions
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
    // integer arithmetic
    addInst("add",   0x18, "rd rs rt");
    addInst("addi",  0x19, "rd L");  // unsigned immediate
    addInst("sub",   0x1a, "rd rs rt");
    addInst("subi",  0x1b, "rd L");  // unsigned immediate
    addInst("mul",   0x1c, "rd rs rt");
    addInst("div",   0x1d, "rd rs rt");
    // logic
    addInst("and",   0x0,  "rd rs rt");
    addInst("or",    0x1,  "rd rs rt");
    addInst("xor",   0x2,  "rd rs rt");
    addInst("not",   0x3,  "rd rs");
    addInst("shftr", 0x4,  "rd rs rt");
    addInst("shftri",0x5,  "rd L");  // unsigned immediate
    addInst("shftl", 0x6,  "rd rs rt");
    addInst("shftli",0x7,  "rd L");  // unsigned immediate
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

// ===================================================================
// Assemble "brr", "mov", or standard
// ===================================================================
void assembleBrrOperand(const char *operand, char *binStr) {
    while(isspace((unsigned char)*operand)) operand++;
    int opcode, reg=0, imm=0;
    if(operand[0]=='r'){
        opcode=0x9;
        reg=(int)strtol(operand+1,NULL,0);
    } else{
        opcode=0xa;
        imm=(int)strtol(operand,NULL,0);
    }
    unsigned int inst=(opcode<<27)|(reg<<22)|((imm&0xFFF));
    char tmp[33];
    intToBinaryStr(inst,32,tmp);
    strcpy(binStr,tmp);
}

void assembleMov(const char *line, char *binStr) {
    char mnemonic[10], token1[64], token2[64];
    if(sscanf(line, "%s %63[^,], %63s", mnemonic, token1, token2)<3){
        strcpy(binStr,"ERROR");
        return;
    }
    trim(token1);
    trim(token2);

    int opcode=0, rd=0, rs=0, rt=0, imm=0;

    // "mov (rD)(L), rS"
    if(token1[0]=='('){
        opcode=0x13;
        char *p1=strchr(token1,'r');
        if(!p1){ strcpy(binStr,"ERROR"); return;}
        int rtemp=0;
        sscanf(p1+1,"%d",&rtemp);
        rd=rtemp;

        char *paren2=strstr(token1,")(");
        if(!paren2){
            imm=0;
        } else {
            char offsetBuf[32];
            char *startOffset=paren2+2;
            char *endParen=strrchr(token1,')');
            if(!endParen||endParen<=startOffset){
                strcpy(binStr,"ERROR");
                return;
            }
            size_t length=endParen-startOffset;
            if(length>=sizeof(offsetBuf)){
                strcpy(binStr,"ERROR");
                return;
            }
            strncpy(offsetBuf, startOffset, length);
            offsetBuf[length] = '\0';
            imm=(int)strtol(offsetBuf,NULL,0);
        }
        if(token2[0]!='r'){
            strcpy(binStr,"ERROR");
            return;
        }
        rs=(int)strtol(token2+1,NULL,0);
    }
    else {
        // token1 => "rD"
        if(token1[0]!='r'){ strcpy(binStr,"ERROR"); return;}
        rd=(int)strtol(token1+1,NULL,0);
        if(token2[0]=='('){
            // "mov rD, (rS)(L)"
            opcode=0x10;
            char *p1=strchr(token2,'r');
            if(!p1){ strcpy(binStr,"ERROR"); return;}
            int rtemp=0;
            sscanf(p1+1,"%d",&rtemp);
            rs=rtemp;

            char *paren2=strstr(token2,")(");
            if(!paren2){
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
                strncpy(offsetBuf, startOffset, length);
                offsetBuf[length]='\0';
                imm=(int)strtol(offsetBuf,NULL,0);
            }
        }
        else if(token2[0]=='r'){
            // "mov rD, rS"
            opcode=0x11;
            rs=(int)strtol(token2+1,NULL,0);
        }
        else {
            // "mov rD, L"
            if(token2[0]=='-'){
                fprintf(stderr,"Error: negative immediate not allowed for mov rD, L\n");
                abortAssembly();
            }
            opcode=0x12;
            imm=(int)strtol(token2,NULL,0);
        }
    }
    unsigned int inst=(opcode<<27)|(rd<<22)|(rs<<17)|(rt<<12)|((imm&0xFFF));
    char tmp[33];
    intToBinaryStr(inst,32,tmp);
    strcpy(binStr,tmp);
}

void assembleStandard(const char *line, char *binStr) {
    char mnemonic[16], op1[16], op2[16], op3[16], op4[16];
    int num=sscanf(line, "%15s %15s %15s %15s %15s",
                   mnemonic, op1, op2, op3, op4);

    InstructionEntry *e=NULL;
    HASH_FIND_STR(instMap, mnemonic, e);
    if(!e){
        strcpy(binStr,"ERROR");
        return;
    }
    int opcode=e->opcode, rd=0, rs=0, rt=0, imm=0;

    // If "rd L", check negative
    if(!strcmp(e->format,"rd L") && num>=3){
        if(op2[0]=='-'){
            fprintf(stderr,"Error: negative immediate not allowed for %s\n",mnemonic);
            abortAssembly();
        }
    }

    if(!strcmp(e->format,"rd rs rt") && num>=4){
        rd=(op1[0]=='r')?strtol(op1+1,NULL,0):0;
        rs=(op2[0]=='r')?strtol(op2+1,NULL,0):0;
        rt=(op3[0]=='r')?strtol(op3+1,NULL,0):0;
    }
    else if(!strcmp(e->format,"rd L") && num>=3){
        rd=(op1[0]=='r')?strtol(op1+1,NULL,0):0;
        imm=(int)strtol(op2,NULL,0);
    }
    else if(!strcmp(e->format,"rd rs") && num>=3){
        rd=(op1[0]=='r')?strtol(op1+1,NULL,0):0;
        rs=(op2[0]=='r')?strtol(op2+1,NULL,0):0;
    }
    else if(!strcmp(e->format,"rd rs rt L") && num>=5){
        rd=(op1[0]=='r')?strtol(op1+1,NULL,0):0;
        rs=(op2[0]=='r')?strtol(op2+1,NULL,0):0;
        rt=(op3[0]=='r')?strtol(op3+1,NULL,0):0;
        imm=(int)strtol(op4,NULL,0);
    }
    else if(!strcmp(e->format,"rd") && num>=2){
        rd=(op1[0]=='r')?strtol(op1+1,NULL,0):0;
    }
    else if(strcmp(e->format,"")==0){
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

void assembleInstruction(const char *line, char *binStr) {
    char mnemonic[16];
    mnemonic[0]='\0';
    sscanf(line,"%15s",mnemonic);

    if(!strcmp(mnemonic,"mov")){
        assembleMov(line, binStr);
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

// ===================================================================
//                      Macro Expansion
// ===================================================================
void parseMacro(const char *line, FILE *outStream) {
    regex_t regex;
    regmatch_t matches[3];
    char op[16];
    if (sscanf(line, "%15s", op) != 1) {
        fprintf(stderr,"Error: invalid macro usage -> %s\n", line);
        abortAssembly();
    }

    // --------------------------------------------------
    //    LD
    // --------------------------------------------------
    if(!strcmp(op,"ld")){
        const char *pattern = "^[[:space:]]*ld[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*(\\S+)";
        if(regcomp(&regex, pattern, REG_EXTENDED)!=0){
            fprintf(stderr,"Error: can't compile regex for ld\n");
            abortAssembly();
        }
        if(regexec(&regex,line,3,matches,0)==0){
            // valid usage => do expansion
            char regBuf[16], immBuf[64];
            int rD;
            uint64_t imm;
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line+matches[1].rm_so, len);
            regBuf[len]='\0';
            rD=(int)strtol(regBuf,NULL,0);

            len=matches[2].rm_eo - matches[2].rm_so;
            strncpy(immBuf, line+matches[2].rm_so, len);
            immBuf[len]='\0';

            // check negative
            if(immBuf[0]=='-'){
                fprintf(stderr,"Error: negative immediate not allowed in ld macro\n");
                regfree(&regex);
                abortAssembly();
            }

            // label or numeric
            if(!isdigit((unsigned char)immBuf[0])) {
                LabelAddress *entry=findLabel(immBuf);
                if(!entry){
                    fprintf(stderr,"Error: label '%s' not found (ld macro)\n", immBuf);
                    regfree(&regex);
                    abortAssembly();
                }
                imm=entry->address;
            } else {
                errno=0;
                char*endptr=NULL;
                uint64_t tmpVal=strtoull(immBuf,&endptr,0);
                if(errno==ERANGE){
                    fprintf(stderr,"Error: ld immediate out of range => %s\n",immBuf);
                    regfree(&regex);
                    abortAssembly();
                }
                imm=tmpVal;
            }

            // expand
            fprintf(outStream,"xor r%d r%d r%d\n",rD,rD,rD);
            unsigned long long top12 =(imm>>52)&0xFFF;
            unsigned long long mid12a=(imm>>40)&0xFFF;
            unsigned long long mid12b=(imm>>28)&0xFFF;
            unsigned long long mid12c=(imm>>16)&0xFFF;
            unsigned long long mid4  =(imm>>4)&0xFFF;
            unsigned long long last4 = imm & 0xF;

            fprintf(outStream,"addi r%d %llu\n",rD,top12);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n",rD,mid12a);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n",rD,mid12b);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n",rD,mid12c);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n",rD,mid4);
            fprintf(outStream,"shftli r%d 4\n",rD);
            fprintf(outStream,"addi r%d %llu\n",rD,last4);
        } else {
            // invalid usage => error
            fprintf(stderr,"Error: invalid 'ld' usage => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    // --------------------------------------------------
    //   PUSH
    // --------------------------------------------------
    else if(!strcmp(op,"push")){
        const char*pattern="^[[:space:]]*push[[:space:]]+r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for push\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,2,matches,0)){
            // good usage
            char regBuf[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=(int)strtol(regBuf,NULL,0);

            fprintf(outStream,"mov (r31)(-8), r%d\n",rD);
            fprintf(outStream,"subi r31 8\n");
        } else {
            // invalid usage
            fprintf(stderr,"Error: invalid 'push' usage => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    // --------------------------------------------------
    //   POP
    // --------------------------------------------------
    else if(!strcmp(op,"pop")){
        const char *pattern="^[[:space:]]*pop[[:space:]]+r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for pop\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,2,matches,0)){
            // ok
            char regBuf[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=(int)strtol(regBuf,NULL,0);
            fprintf(outStream,"mov r%d, (r31)(0)\n",rD);
            fprintf(outStream,"addi r31 8\n");
        } else {
            fprintf(stderr,"Error: invalid 'pop' usage => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    // --------------------------------------------------
    //   IN
    // --------------------------------------------------
    else if(!strcmp(op,"in")){
        // in rD, rS => priv rD rS r0 3
        const char*pattern="^[[:space:]]*in[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for in\n");
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
            int rS=(int)strtol(regBuf2,NULL,0);

            fprintf(outStream,"priv r%d r%d r0 3\n",rD,rS);
        } else {
            fprintf(stderr,"Error: invalid 'in' usage => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    // --------------------------------------------------
    //   OUT
    // --------------------------------------------------
    else if(!strcmp(op,"out")){
        // out rD, rS => priv rD rS r0 4
        const char *pattern="^[[:space:]]*out[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for out\n");
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
            int rS=(int)strtol(regBuf2,NULL,0);

            fprintf(outStream,"priv r%d r%d r0 4\n",rD,rS);
        } else {
            fprintf(stderr,"Error: invalid 'out' usage => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    // --------------------------------------------------
    //   CLR
    // --------------------------------------------------
    else if(!strcmp(op,"clr")){
        // clr rD => xor rD, rD, rD
        const char *pattern="^[[:space:]]*clr[[:space:]]+r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for clr\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,2,matches,0)){
            char regBuf[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=(int)strtol(regBuf,NULL,0);

            fprintf(outStream,"xor r%d r%d r%d\n",rD,rD,rD);
        } else {
            fprintf(stderr,"Error: invalid 'clr' usage => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    // --------------------------------------------------
    //   HALT
    // --------------------------------------------------
    else if(!strcmp(op,"halt")){
        const char *pattern="^[[:space:]]*halt[[:space:]]*$";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for halt\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,0,NULL,0)){
            fprintf(outStream,"priv r0 r0 r0 0\n");
        } else {
            fprintf(stderr,"Error: invalid 'halt' usage => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    // --------------------------------------------------
    // if we get here, user typed something else, fallback
    else {
        // We only forcibly error if the line *starts with* one of our macros.
        // So if 'op' is none of these, we do fallback printing
        fprintf(outStream, "%s\n", line);
    }
}

// ===================================================================
//             FinalAssemble: expand + data check
// ===================================================================
void finalAssemble(const char *infile, const char *outfile) {
    FILE *fin = fopen(infile,"r");
    if(!fin){
        perror("finalAssemble fopen");
        exit(1);
    }
    // We set up g_outFilename so abortAssembly can remove partial .tko
    strncpy(g_outFilename, outfile, sizeof(g_outFilename)-1);
    g_outFilename[sizeof(g_outFilename)-1] = '\0';

    g_fout = fopen(outfile,"wb");
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
        if(line[0]=='\0' || line[0]==';'){
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
        // handle "some instr :label"
        char *col=strchr(line,':');
        if(col){
            char lab[50];
            if(sscanf(col+1,"%49s",lab)==1){
                LabelAddress *entry=findLabel(lab);
                if(!entry){
                    // Here in Pass 2, label not found => abort
                    fprintf(stderr,"Error: label '%s' not found\n",lab);
                    fclose(fin);
                    abortAssembly();
                }
                *col='\0';
                char temp[256];
                sprintf(temp,"%s0x%x", line, entry->address);
                strcpy(line,temp);
            }
        }

        // CODE
        if(currentSection==CODE){
            char token[16];
            token[0]='\0';
            sscanf(line,"%15s",token);

            if(!strcmp(token,"ld") ||
               !strcmp(token,"push") ||
               !strcmp(token,"pop")  ||
               !strcmp(token,"in")   ||
               !strcmp(token,"out")  ||
               !strcmp(token,"clr")  ||
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
                        assembleInstruction(exLine, assembled);
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
        // DATA
        else {
            if(line[0]=='-'){
                fprintf(stderr,"Error: Invalid data: %s\n",line);
                fclose(fin);
                abortAssembly();
            }
            errno=0;
            char*endptr=NULL;
            uint64_t val=strtoull(line,&endptr,0);
            if(errno==ERANGE){
                fprintf(stderr,"Error: Invalid data: %s\n",line);
                fclose(fin);
                abortAssembly();
            }
            while(endptr && isspace((unsigned char)*endptr)) endptr++;
            if(!endptr || *endptr!='\0'){
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

// ===================================================================
//                              main
// ===================================================================
int main(int argc, char *argv[]){
    if(argc!=3){
        fprintf(stderr,"Usage: %s <assembly_file> <output_file>\n",argv[0]);
        return 1;
    }

    // Pass 1: any label error => exit(1)
    pass1(argv[1]);

    // Build instruction map
    populateInstMap();

    // Pass 2: final assembly; any error => abortAssembly (removes .tko)
    finalAssemble(argv[1], argv[2]);

    // Cleanup
    freeInstMap();
    freeLabelMap();
    return 0;
}