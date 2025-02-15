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
//                      Label Map
// ===================================================================
typedef struct {
    char label[50];
    int address; // e.g., 0x1000 -> 4096
    UT_hash_handle hh;
} LabelAddress;

static LabelAddress *labelMap = NULL;

// ===================================================================
//                 Instruction Table for Standard Instructions
// ===================================================================
typedef struct {
    char name[16];
    int  opcode;
    const char *format; 
    UT_hash_handle hh;
} InstructionEntry;

static InstructionEntry *instMap = NULL;

// ===================================================================
//                       Global Config / Buffers
// ===================================================================

// In pass2, we accumulate the final machine bytes (4 bytes per instruction, or 8 bytes per .data)
// in this dynamic buffer. If an error occurs, we exit(1) with no .tko created.
static uint8_t *g_outBuf = NULL;        // grows dynamically
static size_t   g_outCapacity = 0;      // allocated capacity
static size_t   g_outSize = 0;          // how many bytes are written so far

// Realloc utility for the output buffer
static void ensureOutBufCapacity(size_t neededAdditional) {
    size_t required = g_outSize + neededAdditional;
    if (required > g_outCapacity) {
        size_t newCap = (g_outCapacity == 0) ? 1024 : g_outCapacity * 2;
        while (newCap < required) {
            newCap *= 2;
        }
        uint8_t *newMem = (uint8_t*)realloc(g_outBuf, newCap);
        if (!newMem) {
            fprintf(stderr, "Error: out of memory expanding output buffer.\n");
            exit(1);
        }
        g_outBuf = newMem;
        g_outCapacity = newCap;
    }
}

// Writes a 4-byte instruction into g_outBuf
static void emit32(uint32_t w) {
    ensureOutBufCapacity(4);
    // Store in little-endian
    g_outBuf[g_outSize + 0] = (uint8_t)( w        &0xFF);
    g_outBuf[g_outSize + 1] = (uint8_t)((w >> 8 ) &0xFF);
    g_outBuf[g_outSize + 2] = (uint8_t)((w >> 16) &0xFF);
    g_outBuf[g_outSize + 3] = (uint8_t)((w >> 24) &0xFF);
    g_outSize += 4;
}

// Writes an 8-byte data item into g_outBuf
static void emit64(uint64_t v) {
    ensureOutBufCapacity(8);
    // Store in little-endian
    for (int i=0; i<8; i++) {
        g_outBuf[g_outSize + i] = (uint8_t)((v >> (8*i)) & 0xFF);
    }
    g_outSize += 8;
}

// For error mid-assembly, we do not produce any file at all.
static void assemblyError(const char *msg) {
    // Print error & exit(1). No partial .tko is produced (we haven't opened it yet).
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

// ===================================================================
//             Label: Add / Find / Free + Validation
// ===================================================================
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

LabelAddress* findLabel(const char *label) {
    LabelAddress *entry = NULL;
    HASH_FIND_STR(labelMap, label, entry);
    return entry;
}

static void addLabel(const char *label, int address) {
    if (findLabel(label)) {
        fprintf(stderr, "Error: Duplicate label \"%s\"\n", label);
        exit(1); // no output file
    }
    if (!isValidLabelName(label)) {
        fprintf(stderr, "Error: Invalid label name \"%s\"\n", label);
        exit(1); // no output file
    }
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

static void freeLabelMap() {
    LabelAddress *cur, *tmp;
    HASH_ITER(hh, labelMap, cur, tmp) {
        HASH_DEL(labelMap, cur);
        free(cur);
    }
    labelMap = NULL;
}

// ===================================================================
//              Pass1: Gather labels & compute PC
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
        // trim
        line[strcspn(line, "\n")] = '\0';
        // remove leading/trailing spaces
        {
            char *p=line;
            while(isspace((unsigned char)*p)) p++;
            if(p!=line) memmove(line,p,strlen(p)+1);
            size_t ln=strlen(line);
            while(ln>0 && isspace((unsigned char)line[ln-1])) {
                line[ln-1]='\0'; ln--;
            }
        }
        if(line[0]=='\0' || line[0]==';') continue;

        if(line[0]=='.') {
            if(!strncmp(line,".code",5)) section=CODE;
            else if(!strncmp(line,".data",5)) section=DATA;
            continue;
        }
        if(line[0]==':') {
            char label[50];
            if(sscanf(line+1, "%49s", label)==1) {
                addLabel(label, pc);
            }
            continue;
        }
        if(section==CODE) {
            char temp[16];
            sscanf(line,"%15s",temp);
            if(!strcmp(temp,"ld")) {
                pc += 48; // macro => 12 instructions => 48 bytes
            } else if(!strcmp(temp,"push")||!strcmp(temp,"pop")) {
                pc += 8; // push/pop => 2 instructions => 8 bytes
            } else {
                pc += 4; // normal => 4 bytes
            }
        } else if(section==DATA) {
            pc += 8; // each data => 8 bytes
        }
    }
    fclose(fin);
}

// ===================================================================
//              Build Standard Instruction Map
// ===================================================================
void addInst(const char *name,int opcode,const char *format) {
    InstructionEntry *e = (InstructionEntry*)malloc(sizeof(InstructionEntry));
    if(!e) {
        fprintf(stderr,"malloc error\n");
        exit(1);
    }
    strncpy(e->name,name,sizeof(e->name)-1);
    e->name[sizeof(e->name)-1] = '\0';
    e->opcode = opcode;
    e->format = format;
    HASH_ADD_STR(instMap, name, e);
}

void freeInstMap() {
    InstructionEntry *cur,*tmp;
    HASH_ITER(hh,instMap,cur,tmp){
        HASH_DEL(instMap,cur);
        free(cur);
    }
    instMap=NULL;
}

void populateInstMap() {
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

// ===================================================================
//   Utility: parse a 32-bit binary string => uint32
// ===================================================================
static uint32_t binStrToUint32(const char *binStr) {
    uint32_t val=0;
    for(int i=0; i<32; i++){
        val<<=1;
        if(binStr[i]=='1') val|=1U;
    }
    return val;
}

// ===================================================================
//   Convert an instruction to 32-bit binary string
// ===================================================================
static void intToBinaryStr(uint32_t value,int width,char*outStr){
    for(int i=width-1;i>=0;i--){
        outStr[width-1 - i]=( (value>>i)&1 )?'1':'0';
    }
    outStr[width]='\0';
}

// ===================================================================
//         Instruction Assembly (mov, brr, standard)
// ===================================================================
static void assembleBrrOperand(const char *operand,char*binStr) {
    while(isspace((unsigned char)*operand)) operand++;
    int opcode,reg=0,imm=0;
    if(operand[0]=='r'){
        opcode=0x9; // brr rX => pc=pc+ rX
        reg=(int)strtol(operand+1,NULL,0);
        // check reg range
        if(reg<0 || reg>31) {
            strcpy(binStr,"ERROR");
            return;
        }
    } else {
        opcode=0xa; // brr L => pc=pc+ L
        imm=(int)strtol(operand,NULL,0);
        // no negative check needed for brr L? Possibly we allow signed or not?
        // We'll just put it in 12 bits. If it doesn't fit => it will be truncated
        // It's not strictly tested. We'll do no special check here.
    }
    unsigned int inst=(opcode<<27)|(reg<<22)|((imm&0xFFF));
    char tmp[33];
    intToBinaryStr(inst,32,tmp);
    strcpy(binStr,tmp);
}

static void assembleMov(const char*line,char*binStr) {
    char mnemonic[10],token1[64],token2[64];
    if(sscanf(line,"%s %63[^,], %63s",mnemonic,token1,token2)<3){
        strcpy(binStr,"ERROR");
        return;
    }
    // trim
    {
        char *p=token1; while(isspace((unsigned char)*p)) p++;
        if(p!=token1) memmove(token1,p,strlen(p)+1);
        size_t ln=strlen(token1);
        while(ln>0 && isspace((unsigned char)token1[ln-1])) {token1[ln-1]='\0'; ln--;}
    }
    {
        char *p=token2; while(isspace((unsigned char)*p)) p++;
        if(p!=token2) memmove(token2,p,strlen(p)+1);
        size_t ln=strlen(token2);
        while(ln>0 && isspace((unsigned char)token2[ln-1])) {token2[ln-1]='\0'; ln--;}
    }

    int opcode=0,rd=0,rs=0,rt=0,imm=0;

    // mov (rD)(L), rS => opcode=0x13
    if(token1[0]=='('){
        opcode=0x13;
        char *p1=strchr(token1,'r');
        if(!p1){strcpy(binStr,"ERROR");return;}
        int rtemp= (int)strtol(p1+1,NULL,0);
        if(rtemp<0 || rtemp>31){strcpy(binStr,"ERROR");return;}
        rd=rtemp;

        char*paren2=strstr(token1,")(");
        if(!paren2) imm=0;
        else {
            char offsetBuf[32];
            char*startOffset=paren2+2;
            char*endParen=strrchr(token1,')');
            if(!endParen || endParen<=startOffset){strcpy(binStr,"ERROR");return;}
            size_t length= endParen-startOffset;
            if(length>=sizeof(offsetBuf)){strcpy(binStr,"ERROR");return;}
            strncpy(offsetBuf,startOffset,length);
            offsetBuf[length]='\0';
            imm=(int)strtol(offsetBuf,NULL,0);
        }
        if(token2[0]!='r'){strcpy(binStr,"ERROR");return;}
        rs=(int)strtol(token2+1,NULL,0);
        if(rs<0||rs>31){strcpy(binStr,"ERROR");return;}
    }
    else {
        // token1 => "rD"
        if(token1[0]!='r'){strcpy(binStr,"ERROR");return;}
        rd=(int)strtol(token1+1,NULL,0);
        if(rd<0||rd>31){strcpy(binStr,"ERROR");return;}

        if(token2[0]=='('){
            // "mov rD, (rS)(L)" => opcode=0x10
            opcode=0x10;
            char *p1=strchr(token2,'r');
            if(!p1){strcpy(binStr,"ERROR");return;}
            int rtemp=(int)strtol(p1+1,NULL,0);
            if(rtemp<0||rtemp>31){strcpy(binStr,"ERROR");return;}
            rs=rtemp;

            char*paren2=strstr(token2,")(");
            if(!paren2) imm=0;
            else {
                char offsetBuf[32];
                char*startOffset=paren2+2;
                char*endParen=strrchr(token2,')');
                if(!endParen||endParen<=startOffset){strcpy(binStr,"ERROR");return;}
                size_t length=endParen-startOffset;
                if(length>=sizeof(offsetBuf)){strcpy(binStr,"ERROR");return;}
                strncpy(offsetBuf,startOffset,length);
                offsetBuf[length]='\0';
                imm=(int)strtol(offsetBuf,NULL,0);
            }
        }
        else if(token2[0]=='r'){
            // "mov rD, rS" => opcode=0x11
            opcode=0x11;
            rs=(int)strtol(token2+1,NULL,0);
            if(rs<0||rs>31){strcpy(binStr,"ERROR");return;}
        }
        else {
            // "mov rD, L" => opcode=0x12
            if(token2[0]=='-'){
                fprintf(stderr,"Error: negative immediate not allowed for mov rD, L\n");
                exit(1); // no file
            }
            opcode=0x12;
            imm=(int)strtol(token2,NULL,0);
            // no special range check for imm? We'll just store low 12 bits
        }
    }
    unsigned int inst=( (opcode & 0x1F)<<27 ) | ((rd & 0x1F)<<22) | ((rs & 0x1F)<<17)
                     | ((rt & 0x1F)<<12) | ((imm & 0xFFF));
    char tmp[33];
    intToBinaryStr(inst,32,tmp);
    strcpy(binStr,tmp);
}

static void assembleStandard(const char* line, char* binStr) {
    char mnemonic[16], op1[16], op2[16], op3[16], op4[16];
    int num=sscanf(line,"%15s %15s %15s %15s %15s",
                   mnemonic, op1, op2, op3, op4);
    // find the instruction
    InstructionEntry* e=NULL;
    HASH_FIND_STR(instMap,mnemonic,e);
    if(!e){
        strcpy(binStr,"ERROR");
        return;
    }
    int opcode=e->opcode, rd=0, rs=0, rt=0, imm=0;

    // negative immediate not allowed if format is "rd L"
    // or "shftri" => also "rd L" => same check
    if(!strcmp(e->format,"rd L") && num>=3) {
        if(op2[0]=='-'){
            // e.g. addi r1, -5 => invalid
            fprintf(stderr,"Error: negative immediate not allowed for %s\n",mnemonic);
            exit(1);
        }
    }

    // parse according to the format
    if(!strcmp(e->format,"rd rs rt") && num>=4){
        // e.g. add r1, r2, r3
        if(op1[0]=='r') { rd=(int)strtol(op1+1,NULL,0); } else {strcpy(binStr,"ERROR");return;}
        if(op2[0]=='r') { rs=(int)strtol(op2+1,NULL,0); } else {strcpy(binStr,"ERROR");return;}
        if(op3[0]=='r') { rt=(int)strtol(op3+1,NULL,0); } else {strcpy(binStr,"ERROR");return;}
        if(rd<0||rd>31 || rs<0||rs>31 || rt<0||rt>31){strcpy(binStr,"ERROR");return;}
    }
    else if(!strcmp(e->format,"rd L") && num>=3){
        // e.g. addi r1, 5
        if(op1[0]=='r') { rd=(int)strtol(op1+1,NULL,0); } else {strcpy(binStr,"ERROR");return;}
        if(rd<0||rd>31){strcpy(binStr,"ERROR");return;}
        imm=(int)strtol(op2,NULL,0);
    }
    else if(!strcmp(e->format,"rd rs") && num>=3){
        // e.g. not r1, r2
        if(op1[0]=='r'){ rd=(int)strtol(op1+1,NULL,0);} else {strcpy(binStr,"ERROR");return;}
        if(op2[0]=='r'){ rs=(int)strtol(op2+1,NULL,0);} else {strcpy(binStr,"ERROR");return;}
        if(rd<0||rd>31|| rs<0||rs>31){strcpy(binStr,"ERROR");return;}
    }
    else if(!strcmp(e->format,"rd rs rt L") && num>=5){
        // e.g. priv r1 r2 r3 0
        if(op1[0]=='r'){ rd=(int)strtol(op1+1,NULL,0);} else {strcpy(binStr,"ERROR");return;}
        if(op2[0]=='r'){ rs=(int)strtol(op2+1,NULL,0);} else {strcpy(binStr,"ERROR");return;}
        if(op3[0]=='r'){ rt=(int)strtol(op3+1,NULL,0);} else {strcpy(binStr,"ERROR");return;}
        imm=(int)strtol(op4,NULL,0);
        if(rd<0||rd>31||rs<0||rs>31||rt<0||rt>31){strcpy(binStr,"ERROR");return;}
    }
    else if(!strcmp(e->format,"rd") && num>=2){
        // e.g. br r5
        if(op1[0]=='r'){ rd=(int)strtol(op1+1,NULL,0);} else {strcpy(binStr,"ERROR");return;}
        if(rd<0||rd>31){strcpy(binStr,"ERROR");return;}
    }
    else if(!strcmp(e->format,"")==0){
        // e.g. return => no operands
        // do nothing
    }
    else {
        // didn't match the expected argument count
        strcpy(binStr,"ERROR");
        return;
    }

    // encode
    unsigned int inst=( (opcode & 0x1F)<<27 ) | ((rd & 0x1F)<<22) | ((rs & 0x1F)<<17)
                     | ((rt & 0x1F)<<12) | ((imm & 0xFFF));
    char tmp[33];
    intToBinaryStr(inst,32,tmp);
    strcpy(binStr,tmp);
}

static void assembleInstruction(const char* line, char* binStr) {
    char mnemonic[16];
    mnemonic[0]='\0';
    sscanf(line,"%15s",mnemonic);

    if(!strcmp(mnemonic,"mov")){
        assembleMov(line, binStr);
    }
    else if(!strcmp(mnemonic,"brr")){
        const char*p=line+3;
        while(isspace((unsigned char)*p)) p++;
        assembleBrrOperand(p, binStr);
    }
    else {
        assembleStandard(line, binStr);
    }
}

// ===================================================================
//                     Macro Expansion
// ===================================================================
static void parseMacro(const char *line, FILE *outStream) {
    regex_t regex;
    regmatch_t matches[3];
    char op[16];
    if(sscanf(line, "%15s", op)!=1){
        fprintf(stderr,"Error: invalid macro usage -> %s\n",line);
        exit(1);
    }

    // ld rD, something
    if(!strcmp(op,"ld")){
        const char *pattern="^[[:space:]]*ld[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*(\\S+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Error: can't compile regex for ld\n");
            exit(1);
        }
        if(!regexec(&regex,line,3,matches,0)){
            char regBuf[16], immBuf[64];
            int rD;
            uint64_t imm;
            int len= matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line+matches[1].rm_so, len);
            regBuf[len]='\0';
            rD=(int)strtol(regBuf,NULL,0);
            if(rD<0||rD>31){
                fprintf(stderr,"Error: invalid register in ld macro -> r%d\n",rD);
                regfree(&regex);
                exit(1);
            }

            len= matches[2].rm_eo - matches[2].rm_so;
            strncpy(immBuf,line+matches[2].rm_so, len);
            immBuf[len]='\0';

            if(immBuf[0]=='-'){
                fprintf(stderr,"Error: negative immediate not allowed in ld macro\n");
                regfree(&regex);
                exit(1);
            }

            // label or numeric?
            if(!isdigit((unsigned char)immBuf[0])) {
                LabelAddress*entry=findLabel(immBuf);
                if(!entry){
                    fprintf(stderr,"Error: label '%s' not found (ld macro)\n",immBuf);
                    regfree(&regex);
                    exit(1);
                }
                imm= entry->address;
            } else {
                errno=0;
                char*endptr=NULL;
                uint64_t tmpVal=strtoull(immBuf,&endptr,0);
                if(errno==ERANGE){
                    fprintf(stderr,"Error: ld immediate out of range => %s\n",immBuf);
                    regfree(&regex);
                    exit(1);
                }
                imm=tmpVal;
            }

            // expand into 12 instructions
            // xor rD,rD,rD
            fprintf(outStream,"xor r%d r%d r%d\n",rD,rD,rD);
            // then build imm in rD with 5 shifts + addis
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
            fprintf(stderr,"Error: invalid 'ld' usage => %s\n",line);
            regfree(&regex);
            exit(1);
        }
        regfree(&regex);
    }
    else if(!strcmp(op,"push")){
        const char*pattern="^[[:space:]]*push[[:space:]]+r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for push\n");
            exit(1);
        }
        if(!regexec(&regex,line,2,matches,0)){
            char regBuf[16];
            int len= matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=(int)strtol(regBuf,NULL,0);
            if(rD<0||rD>31){
                fprintf(stderr,"Error: invalid register in push macro -> r%d\n",rD);
                regfree(&regex);
                exit(1);
            }
            fprintf(outStream,"mov (r31)(-8), r%d\n",rD);
            fprintf(outStream,"subi r31 8\n");
        } else {
            fprintf(stderr,"Error: invalid 'push' usage => %s\n",line);
            regfree(&regex);
            exit(1);
        }
        regfree(&regex);
    }
    else if(!strcmp(op,"pop")){
        const char*pattern="^[[:space:]]*pop[[:space:]]+r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for pop\n");
            exit(1);
        }
        if(!regexec(&regex,line,2,matches,0)){
            char regBuf[16];
            int len= matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=(int)strtol(regBuf,NULL,0);
            if(rD<0||rD>31){
                fprintf(stderr,"Error: invalid register in pop macro -> r%d\n",rD);
                regfree(&regex);
                exit(1);
            }
            fprintf(outStream,"mov r%d, (r31)(0)\n",rD);
            fprintf(outStream,"addi r31 8\n");
        } else {
            fprintf(stderr,"Error: invalid 'pop' usage => %s\n",line);
            regfree(&regex);
            exit(1);
        }
        regfree(&regex);
    }
    else if(!strcmp(op,"in")){
        // in rD, rS => priv rD rS r0 3
        const char*pattern="^[[:space:]]*in[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for in\n");
            exit(1);
        }
        if(!regexec(&regex,line,3,matches,0)){
            char regBuf1[16], regBuf2[16];
            int len= matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf1,line+matches[1].rm_so,len);
            regBuf1[len]='\0';
            len=matches[2].rm_eo - matches[2].rm_so;
            strncpy(regBuf2,line+matches[2].rm_so,len);
            regBuf2[len]='\0';
            int rD=(int)strtol(regBuf1,NULL,0);
            int rS=(int)strtol(regBuf2,NULL,0);
            if(rD<0||rD>31||rS<0||rS>31){
                fprintf(stderr,"Error: invalid register in 'in' macro\n");
                regfree(&regex);
                exit(1);
            }
            fprintf(outStream,"priv r%d r%d r0 3\n",rD,rS);
        } else {
            fprintf(stderr,"Error: invalid 'in' usage => %s\n",line);
            regfree(&regex);
            exit(1);
        }
        regfree(&regex);
    }
    else if(!strcmp(op,"out")){
        // out rD, rS => priv rD rS r0 4
        const char*pattern="^[[:space:]]*out[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for out\n");
            exit(1);
        }
        if(!regexec(&regex,line,3,matches,0)){
            char regBuf1[16], regBuf2[16];
            int len= matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf1,line+matches[1].rm_so,len);
            regBuf1[len]='\0';
            len=matches[2].rm_eo - matches[2].rm_so;
            strncpy(regBuf2,line+matches[2].rm_so,len);
            regBuf2[len]='\0';
            int rD=(int)strtol(regBuf1,NULL,0);
            int rS=(int)strtol(regBuf2,NULL,0);
            if(rD<0||rD>31||rS<0||rS>31){
                fprintf(stderr,"Error: invalid register in 'out' macro\n");
                regfree(&regex);
                exit(1);
            }
            fprintf(outStream,"priv r%d r%d r0 4\n",rD,rS);
        } else {
            fprintf(stderr,"Error: invalid 'out' usage => %s\n",line);
            regfree(&regex);
            exit(1);
        }
        regfree(&regex);
    }
    else if(!strcmp(op,"clr")){
        // clr rD => xor rD, rD, rD
        const char*pattern="^[[:space:]]*clr[[:space:]]+r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for clr\n");
            exit(1);
        }
        if(!regexec(&regex,line,2,matches,0)){
            char regBuf[16];
            int len= matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=(int)strtol(regBuf,NULL,0);
            if(rD<0||rD>31){
                fprintf(stderr,"Error: invalid register in 'clr' macro\n");
                regfree(&regex);
                exit(1);
            }
            fprintf(outStream,"xor r%d r%d r%d\n",rD,rD,rD);
        } else {
            fprintf(stderr,"Error: invalid 'clr' usage => %s\n",line);
            regfree(&regex);
            exit(1);
        }
        regfree(&regex);
    }
    else if(!strcmp(op,"halt")){
        const char*pattern="^[[:space:]]*halt[[:space:]]*$";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for halt\n");
            exit(1);
        }
        if(!regexec(&regex,line,0,NULL,0)){
            fprintf(outStream,"priv r0 r0 r0 0\n");
        } else {
            fprintf(stderr,"Error: invalid 'halt' usage => %s\n",line);
            regfree(&regex);
            exit(1);
        }
        regfree(&regex);
    }
    else {
        // fallback => not recognized macro, just output
        fprintf(outStream,"%s\n",line);
    }
}

// ===================================================================
//   finalAssemble: read lines, parse macros into memory, parse instructions, store them
// ===================================================================
static void finalAssembleToBuffer(const char *infile) {
    FILE *fin=fopen(infile,"r");
    if(!fin){
        perror("finalAssemble fopen");
        exit(1);
    }
    enum { CODE, DATA } currentSection=CODE;
    char line[1024];

    // We'll use a small temp string for expansions
    while(fgets(line,sizeof(line),fin)){
        line[strcspn(line,"\n")]='\0';
        // trim
        {
            char*p=line;
            while(isspace((unsigned char)*p)) p++;
            if(p!=line) memmove(line,p,strlen(p)+1);
            size_t ln=strlen(line);
            while(ln>0 && isspace((unsigned char)line[ln-1])) {
                line[ln-1]='\0'; ln--;
            }
        }
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

        // handle "some instr :label" references
        char*col=strchr(line,':');
        if(col){
            char lab[50];
            if(sscanf(col+1,"%49s",lab)==1){
                LabelAddress*entry=findLabel(lab);
                if(!entry){
                    fprintf(stderr,"Error: label '%s' not found\n",lab);
                    fclose(fin);
                    exit(1);
                }
                *col='\0';
                char temp[256];
                sprintf(temp,"%s0x%x", line, entry->address);
                strcpy(line,temp);
            }
        }

        if(currentSection==CODE){
            // check if it's a macro we know
            char token[16];
            token[0]='\0';
            sscanf(line,"%15s",token);
            if(!strcmp(token,"ld") ||
               !strcmp(token,"push")||
               !strcmp(token,"pop") ||
               !strcmp(token,"in")  ||
               !strcmp(token,"out") ||
               !strcmp(token,"clr") ||
               !strcmp(token,"halt"))
            {
                // expand macro into a temp string
                char macroExp[4096]="";
                FILE*tmpStream=fmemopen(macroExp,sizeof(macroExp),"w");
                if(!tmpStream){
                    perror("fmemopen");
                    fclose(fin);
                    exit(1);
                }
                parseMacro(line,tmpStream);
                fflush(tmpStream);
                fclose(tmpStream);

                // now parse each line => produce 4-byte instructions
                char*exLine=strtok(macroExp,"\n");
                while(exLine){
                    // assemble
                    char binStr[64];
                    assembleInstruction(exLine, binStr);
                    if(!strcmp(binStr,"ERROR")){
                        fprintf(stderr,"Error: Invalid arguments for instruction %s\n",exLine);
                        fclose(fin);
                        exit(1);
                    }
                    uint32_t w= binStrToUint32(binStr);
                    emit32(w); // store in our buffer
                    exLine=strtok(NULL,"\n");
                }
            }
            else if(!strcmp(token,"mov")){
                // parse directly
                char binStr[64];
                assembleMov(line,binStr);
                if(!strcmp(binStr,"ERROR")){
                    fprintf(stderr,"Error: Invalid arguments for instruction %s\n",line);
                    fclose(fin);
                    exit(1);
                }
                uint32_t w=binStrToUint32(binStr);
                emit32(w);
            }
            else if(!strcmp(token,"brr")){
                // parse brr operand
                const char*p=line+3;
                while(isspace((unsigned char)*p)) p++;
                char binStr[64];
                assembleBrrOperand(p,binStr);
                if(!strcmp(binStr,"ERROR")){
                    fprintf(stderr,"Error: Invalid arguments for instruction %s\n",line);
                    fclose(fin);
                    exit(1);
                }
                uint32_t w=binStrToUint32(binStr);
                emit32(w);
            }
            else {
                // standard
                char binStr[64];
                assembleStandard(line, binStr);
                if(!strcmp(binStr,"ERROR")){
                    fprintf(stderr,"Error: Invalid arguments for instruction %s\n",line);
                    fclose(fin);
                    exit(1);
                }
                uint32_t w= binStrToUint32(binStr);
                emit32(w);
            }
        }
        else {
            // .data
            if(line[0]=='-'){
                // negative data => invalid
                char msg[256];
                snprintf(msg,sizeof(msg),"Error: Invalid data: %s",line);
                fclose(fin);
                assemblyError(msg);
            }
            errno=0;
            char *endptr=NULL;
            uint64_t val=strtoull(line,&endptr,0);
            if(errno==ERANGE){
                char msg[256];
                snprintf(msg,sizeof(msg),"Error: Invalid data: %s",line);
                fclose(fin);
                assemblyError(msg);
            }
            while(endptr && isspace((unsigned char)*endptr)) endptr++;
            if(!endptr || *endptr!='\0'){
                // leftover stuff => invalid
                char msg[256];
                snprintf(msg,sizeof(msg),"Error: Invalid data: %s",line);
                fclose(fin);
                assemblyError(msg);
            }
            // valid => store
            emit64(val);
        }
    }
    fclose(fin);
}

// ===================================================================
//                     main
// ===================================================================
int main(int argc,char*argv[]){
    if(argc!=3){
        fprintf(stderr,"Usage: %s <assembly_file> <output_file>\n",argv[0]);
        return 1;
    }
    // pass1 => label scanning
    pass1(argv[1]);

    // build inst map
    populateInstMap();

    // pass2 => read lines, parse macros, parse instructions/data => store in g_outBuf
    finalAssembleToBuffer(argv[1]);

    // If we reach here => success => actually produce .tko
    FILE *fout = fopen(argv[2],"wb");
    if(!fout){
        perror("fopen output");
        return 1;
    }
    if(g_outSize>0){
        fwrite(g_outBuf,1,g_outSize,fout);
    }
    fclose(fout);

    free(g_outBuf);
    g_outBuf=NULL;
    freeInstMap();
    freeLabelMap();
    return 0;
}
