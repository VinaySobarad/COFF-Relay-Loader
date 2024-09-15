@ECHO OFF
cl.exe /nologo /Ox /MT /W0 /GS- /DNEBUG /Tc COFF_LOADER.c  /link /OUT:COFF_LOADER.exe /SUBSYSTEM:CONSOLE

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc FinalImplant.cpp
move /y FinalImplant.obj FinalImplant.o
dumpbin /disasm FinalImplant.o > FinalImplant.disasm
del *.obj
