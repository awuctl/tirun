CFLAGS=-Os -ffunction-sections -fdata-sections
COPTS=-m32 -Wall -Wno-incompatible-pointer-types
GCC=gcc

WRFLAGS=--codepage=65001 -O coff -F pe-i386
WINDRES=windres

STRIPFLAGS=-s
STRIP=strip

all: tirun.res tirun.exe

tirun.exe: tirun.c tirun.res
	$(GCC) $(COPTS) $^ -o $@ $(CFLAGS) $(LDFLAGS)
	$(STRIP) $(STRIPFLAGS) $@

tirun.res: resource.rc manifest.xml
	$(WINDRES) $(WRFLAGS) $< $@