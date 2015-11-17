CC        = gcc
CPP	  = g++
INCDIRS = -I./DecodeVars -I./VarInject -I./VarLib/
CFLAGS	= ${INCDIRS} -std=c99
#CFLAGS	= ${INCDIRS}
ENCFILES = ./VarInject/main.c ./VarLib/VarInject.c ./VarLib/VarUtils.c
DECFILES = ./DecodeVars/main.c ./VarLib/VarDecode.c ./VarLib/VarUtils.c


VarEncode: ${ENCFILES}
	echo "Encode Test"
	${CC} ${CFLAGS} ${ENCFILES} -o VarEncode

VarDecode: ${DECFILES}
	echo "Decode Test"
	${CC} ${CFLAGS} ${DECFILES} -o VarDecode


all: VarEncode VarDecode

clean:
	rm -rf *.o
	rm -rf ./VarEncode
	rm -rf ./VarDecode
