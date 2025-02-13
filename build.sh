#!/bin/bash

# Compiler and flags
CC=gcc
CFLAGS="-Wall -Wextra -std=c11 -O2"
LDFLAGS="-lczmq"  # Link against czmq library

# Output binary name
OUTFILE="tinker_assembler"

# Source files (add more if needed)
SRC="assembler.c"

# Compile the program
echo "Compiling..."
$CC $CFLAGS $SRC -o $OUTFILE $LDFLAGS

# Check if compilation was successful
if [ $? -eq 0 ]; then
    echo "Build successful! Run ./tinker_assembler <input.tk> <output.bin>"
else
    echo "Build failed!"
fi
