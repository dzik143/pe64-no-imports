# Minimal 64-bit PE without imports table
- 268 bytes,
- no sections,
- no imports table and other data directories,
- finds out entry points to [GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) 
  and [LoadLibraryA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) manually.

# What does it do
Code shows the example how to import external modules on-the-fly *WITHOUT* import table.

The code does the following steps:
1. Find the KERNEL32.DLL base using return address passed from OS,
2. find export table at KERNEL32.DLL module space (kernel32!ExportTable),
3. find the entry point of GetProcAddress in kernel32!ExportTable,
4. use GetProcAddress to find entry of kernel32!LoadLibraryA routine,
5. use LoadLibraryA and GetProcAddress to import msvcrt!puts.

# How does it work
- We assume that entry point in our application is called directly by KERNEL32.DLL,
- So the return address on app start-up should points somwhere in-the-middle of KERNEL32.dll module,
- So, we scan memory pointed by return address backward until we find something, which looks like the PE header.

# Limitations:
- Code works on x86-64 only (PE32+),
- Code is size-optimized to fit wihin 268 bytes, string constants are overlapping unused PE parts, which are not
  needed to run, but some disassemblers or debuggers may fail to load the file.

# Links
Based on codes samples from:
- https://stackoverflow.com/a32820799
- https://hero.handmade.network/forums/code-discussion/t/129-howto_-_building_without_import_libraries
- https://stackoverflow.com/a/45528159


