CC_x64 := gcc
STRIP := strip
OPTIONS := -O3 -I include -w -ldl
OBJECTS := procmem.o utils.o

all: apollon-all-x64 apollon-selective-x64

apollon-all-x64: $(OBJECTS) apollon-all-x64.o
	$(CC_x64) $^ -o dist/$@ $(OPTIONS)
	$(STRIP) --strip-unneeded dist/$@

apollon-selective-x64: $(OBJECTS) apollon-selective-x64.o
	$(CC_x64) $^ -o dist/$@ $(OPTIONS)
	$(STRIP) --strip-unneeded dist/$@

apollon-selective-x64.o: src/apollon.c shellcode-selective.bin
	$(CC_x64) -c $< -o $@ $(OPTIONS)

apollon-all-x64.o: src/apollon.c shellcode-all.bin
	$(CC_x64) -D FILTER_ALL -c $< -o $@ $(OPTIONS)

shellcode-selective.bin: src/filter-selective.asm
	nasm $< -o $@ -f bin
	python3 generate-header.py $@

shellcode-all.bin: src/filter-all.asm
	nasm $< -o $@ -f bin
	python3 generate-header.py $@

procmem.o: src/procmem.c include/procmem.h
	$(CC_x64) -c $< -o $@ $(OPTIONS)

utils.o: src/utils.c include/utils.h
	$(CC_x64) -c $< -o $@ $(OPTIONS)

clean:
	rm dist/* -f *.o *.bin include/shellcode.h
