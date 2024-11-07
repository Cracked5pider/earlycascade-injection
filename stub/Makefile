CC     := cl.exe
LINK   := link.exe
CFLAGS := /c /GS- /O1 /Os /kernel /Zl /GR- /EHsc /MD
LFLAGS := /NODEFAULTLIB /ENTRY:main /SUBSYSTEM:CONSOLE /MERGE:.rdata=.text /OPT:REF /OPT:ICF /LTCG /ALIGN:16 /DEBUG:NONE

all: 
	@ $(CC) $(CFLAGS) src/Main.cc 
	@ $(LINK) $(LFLAGS) Main.obj
	@ python extract.py -f Main.exe -o cascade-stub.x64.bin
	