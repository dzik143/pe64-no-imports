# PE32+ (64-bit) - LoadLibrary() without imports table

# What does it do
Code shows the example how to use external modules on-the-fly **WITHOUT** [imports table](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-idata-section).

The code does the following steps:
1. Finds out the KERNEL32.DLL base (see versions below),
2. finds out export table at KERNEL32.DLL module space (kernel32!ExportTable),
3. finds out the entry point of [GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) in kernel32!ExportTable **directly** (in memory),
4. calls GetProcAddress to get entry point of [LoadLibraryA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) routine,
5. calls LoadLibraryA and GetProcAddress to import desired module and symbols.

# Standard PE32+ / TEB version (64-bit)
  - 1536 bytes,
  - 2 sections (code and data),
  - **NO** imports table and other data directories,
  - uses **THREAD ENVIRONMENT BLOCK** (TEB) to get KERNEL32.DLL base,
  - reads entry point of GetAddressProc() directly from KERNEL32 exports,
  - then calls it to get entry of LoadLibraryA() routine.

# Standard PE32+ / stack version (64-bit)
  - 1536 bytes,
  - 2 sections (code and data),
  - **NO** imports table and other data directories,
  - uses **RETURN ADDRESS** to get KERNEL32.DLL base,
  - reads entry point of GetAddressProc() directly from KERNEL32 exports,
  - then calls it to get entry of LoadLibraryA() routine.

# Minimal PE32+ / size-optimized stack version (64-bit)
  - **268 bytes**,
  - no sections,
  - **NO** imports table and other data directories,
  - **SIZE-OPTIMIZED** to fits within 268 bytes,
  - uses **RETURN ADDRESS** to get KERNEL32.DLL base,
  - reads entry point of GetAddressProc() directly from KERNEL32 exports,
  - then calls it to get entry of LoadLibraryA() routine.

# How does stack version work
- We assume that entry point in our application is called directly by KERNEL32.DLL,
- so the return address on app start-up should points somwhere **in-the-middle** of KERNEL32.DLL module,
- we scan memory pointed by return address backward until we found something, which **looks like the PE** header.

# How does TEB version work
  - **GS register** points to the **Thread Environment Block** (TEB) on x86-64 Windows
    (https://en.wikipedia.org/wiki/Win32_Thread_Information_Block),
  - We search TEB.PEB.LoaderData.Modules for 'kernel32.dll' entry.

# Limitations:
- Code works on x86-64 only (PE32+),
- Minimal version is size-optimized to fit wihin 268 bytes, due to this, literals are stored in the unused
  PE parts, which are not neccesery to run a program, but some disassemblers or debuggers may fail to load the file.

# Links
Based on codes samples from:
- https://stackoverflow.com/a/32820799
- https://hero.handmade.network/forums/code-discussion/t/129-howto_-_building_without_import_libraries
- https://stackoverflow.com/a/45528159
