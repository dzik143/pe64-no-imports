# 64-bit PE without imports table

# What does it do
Code shows the example how to import external modules on-the-fly **WITHOUT** import table.

The code does the following steps:
1. Find the KERNEL32.DLL base (see versions below),
2. find export table at KERNEL32.DLL module space (kernel32!ExportTable),
3. find the entry point of [GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) in kernel32!ExportTable directly,
4. use GetProcAddress to find entry of [LoadLibraryA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) routine,
5. use LoadLibraryA and GetProcAddress to import desired module.

# Standard 32+ PE / TEB version (64-bit)
  - 1536 bytes,
  - 2 sections (code and data),
  - **NO** imports table and other data directories,
  - uses **THREAD ENVIRONMENT BLOCK** (TEB) to get kernel32.dll base,
  - reads entry point of GetAddressProc() directly in kernel32 exports,
  - then call it to get entry of LoadLibraryA() routine.

# Standard 32+ PE / stack version (64-bit)
  - 1536 bytes,
  - 2 sections (code and data),
  - **NO** imports table and other data directories,
  - uses **RETURN ADDRESS** to get kernel32.dll base,
  - reads entry point of GetAddressProc() directly in kernel32 exports,
  - then call it to get entry of LoadLibraryA() routine.

# Minimal 32+ PE (64-bit)
  - **268 bytes**,
  - no sections,
  - **NO** imports table and other data directories,
  - **SIZE-OPTIMIZED** to fits within 268 bytes,
  - uses **RETURN ADDRESS to get kernel32.dll base,
  - reads entry point of GetAddressProc() directly in kernel32 exports,
  - then call it to get entry of LoadLibraryA() routine.

# How does stack version work
- We assume that entry point in our application is called directly by KERNEL32.DLL,
- So the return address on app start-up should points somwhere in-the-middle of KERNEL32.dll module,
- So, we scan memory pointed by return address backward until we find something, which looks like the PE header.

# How does TEB version work
  - GS register points to the Thread Environment Block (TEB) on x86-64 Windows
    (https://en.wikipedia.org/wiki/Win32_Thread_Information_Block),

  - We search TEB.PEB.LoaderData.Modules for 'kernel32.dll' entry.

# Limitations:
- Code works on x86-64 only (PE32+),
- Minimal version is size-optimized to fit wihin 268 bytes, due to this literals are overlapping unused PE parts, which are not
  neccesery to run a program, but some disassemblers or debuggers may fail to load the file.

# Links
Based on codes samples from:
- https://stackoverflow.com/a32820799
- https://hero.handmade.network/forums/code-discussion/t/129-howto_-_building_without_import_libraries
- https://stackoverflow.com/a/45528159
