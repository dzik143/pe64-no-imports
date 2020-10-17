;###############################################################################
;#                                                                             #
;# Copyright (C) 2020 by Sylwester Wysocki <sw143@wp.pl>                       #
;#                                                                             #
;# Permission to use, copy, modify, and/or distribute this software for any    #
;# purpose with or without fee is hereby granted.                              #
;#                                                                             #
;# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES    #
;# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF            #
;# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR     #
;# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES      #
;# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN       #
;# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR  #
;# IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.                 #
;#                                                                             #
;###############################################################################

; Created on: 2020-10-12
; Last modified on: 2020-10-17

; Size-optimized version of pe64-no-imports-normal-stack.asm file.
; ================================================================

; Shows how to get entry points to GetProcAddress and LoadLibrary() manually
; *WITHOUT* imports table.

; - 268 bytes,
; - no sections (headers only file),
; - no imports table and other data directories,

; Based on code from posts:
; -------------------------
; - https://stackoverflow.com/a/32820799
; - https://hero.handmade.network/forums/code-discussion/t/129-howto_-_building_without_import_libraries
; - https://stackoverflow.com/a/45528159

; Below code does:
; ----------------
;   1. Find the KERNEL32.DLL base using return address passed from OS,
;   2. find export table at KERNEL32.DLL module space (kernel32!ExportTable),
;   3. find the entry point of GetProcAddress in kernel32!ExportTable,
;   4. use GetProcAddress to find entry of kernel32!LoadLibraryA routine,
;   5. use LoadLibraryA and GetProcAddress to import msvcrt!puts,
;   6. call puts() to show it works.

; How does it work:
; ----------------
; - We assume that entry point in our application is called directly by
;   KERNEL32.DLL,
;
; - So the return address on app start-up should points somwhere in-the-middle
;   of KERNEL32.dll module,
;
; - So, we scan memory pointed by return address backward until we find
;   something, which looks like the PE header.

; Limitations:
; - Code works on x86-64 only (PE32+),
; - Code is size-optimized to fit wihin 268 bytes, string constants are
;   overlapping unused PE parts, which are not needed to run, but some
;   disassemblers or debuggers may fail to load the file.

; Build by command:
; -----------------
; fasm pe64-no-imports-minimal.asm

format binary as 'exe'
use64

__base:

; ##############################################################################
; #
; #                   DOS Stub (overlapped with PE header)
; #
; ##############################################################################

__headerDOS:

  .magic db 'MZ'
         db 90h, 0

; ##############################################################################
; #
; #                                 PE header
; #
; ##############################################################################

__headerPE:

  .magic            db 'PE', 0, 0  ;
  .machine          dw 8664h       ; AMD64 (x86-64)
  .numberOfSections dw 0           ;

; -------------------------------------------------------------------------------

  ; --------------------------------------------------
  ; To keep code small, we store strings in PE fields,
  ; which are not neccesery to run. See LIMITATIONS
  ; note.

  ;.timeDateStamp        dd 0
  ;.pointerToSymbolTable dd 0
  ;.numberOfSymbols      dd 0

                       ; 0........1..
                       ; 123456789012
  .name_LoadLibraryA db 'LoadLibraryA'

; -------------------------------------------------------------------------------

  .sizeOfOptionalHeader dw 0*8
  .characteristics      dw 002fh  ; be bit 1=1 bit 13=0
  .magicPE64            dw 020Bh  ; PE32+ magic

; -------------------------------------------------------------------------------

  ;.majorLinkerVersion      db 0
  ;.minorLinkerVersion      db 0
  ;.sizeOfCode              dd 0
  ;.sizeOfInitializedData   dd 0
  ;.sizeOfUninitializedData dd 0

  .name_GetProcAddress:
      ; 0........1....
      ; 12345678901234
    db 'GetProcAddress'

; -------------------------------------------------------------------------------

  .addressOfEntryPoint dd __entryPoint ; cannot be smaller than SizeOfHeaders
  .baseOfCode          dd 0
  .imageBase           dq 100000000h   ; must be multiple of 64k
  .secionAligment      dd 4            ; overlapped with offset to PE header
  .fileAlignment       dd 4

; -------------------------------------------------------------------------------

  ;.majorOperatingSystemVersion dw 0
  ;.minorOperatingSystemVersion dw 0
  ;.majorImageVersion           dw 0
  ;.minorImageVersion           dw 0

                 ; 123456
  .name_msvcrt db 'msvcrt', 0, 0

; -------------------------------------------------------------------------------

  .majorSubsystemVersion dw 5
  .minorSubsystemVersion dw 0

; -------------------------------------------------------------------------------

  ;.win32VersionValue dd 0

  .name_puts db 'puts'

; -------------------------------------------------------------------------------

  .sizeOfImage        dd 400h     ; must be > 0200h
  .sizeOfHeaders      dd __entryPoint
  .checksum           dd 0        ;
  .subsystem          dw 3        ; 2=GUI, 3=Console
  .dllCharacteristics dw 0        ;

    ; ------------------------------------------------
    ; Below there are four quad-word declarations,
    ; which determine how much memory should be
    ; reserved for our process:
    ; - SizeOfStackReserve (8 bytes)
    ; - SizeOfStackCommit  (8 bytes)
    ; - SizeOfHeapReserve  (8 bytes)
    ; - SizeOfStackCommit  (8 bytes)
    ;                      (32 bytes total)
    ;
    ; We store some code here, but keep high 32-word
    ; of each declaration zeroed to avoid huge values
    ; above 4 GB (which may cause the file unloadable).

    ; -----------------------------------------------
    ; Entry point declared in the PE header.
    ; This is the first code executed after PE header
    ; is loaded into memory.

__entryPoint:

    ; -----------------------------------------------
    ; First 8-bytes chunk: SizeOfStackReserve
    ;
    ; 1. Load return address to parent module (kernel32) into rbx.
    ; 2. Use call 0 instruction to get RIP value into rsi.

    ; We treat the high 32-bit zeres as part of call 0 instruction:
    ; 5b             | pop rbx   (1 byte)
    ; 53             | push rbx  (1 byte)
    ; 90             | nop       (1 byte)
    ; e8 00 00 00 00 | call 0    (5 bytes)
    ;    ^^ ^^ ^^ ^^             (8 bytes total)
    ;    keep high 32-bit
    ;    zeroed

__SizeOfStackReserve:

    pop   rbx     ; rbx = return address to the parent module
    push  rbx     ; keep stack unchanged

    nop           ; fill up to 8 bytes

    db    0e8h    ;
    dd    0       ; call 0 to get RIP value

__getRIP:         ; stack = [..., rip]
                  ; now qword [rsp] contains RIP pushed by call
                  ; 0 instruction

    ; -----------------------------------------------
    ; Second 8-bytes chunk: SizeOfStackCommit
    ;
    ; Load rsi-8 into rax.
    ; After that we can execute 00 00 00 00 fillers
    ; safely (without access violation).
    ; 54    | push rsp           (1 byte)
    ; 58    | pop  rax           (1 byte)
    ; 5e    | pop  rsi           (1 byte)
    ; 90    | nop                (1 byte)
    ; 00 00 | add byte [rax], al (2 bytes)
    ; 00 00 | add byte [rax], al (2 bytes)
    ; ^^ ^^                      (8 bytes total)
    ; keep high 32-bit
    ; zeroed


__sizeOfStackCommit:

    push rsp      ; stack = [..., rip, rsp-8]
    pop  rax      ; stack = [..., rip]
                  ; rax   = rsp-8

                  ; stack = [...]
    pop  rsi      ; rsi   = __getRIP

    nop           ; fill up to 8 bytes

    dd 0          ; zero fillers (high 32-bit of SizeOfStackCommit)

    ; ------------------------------------------------
    ; Third 8-bytes chunk: SizeOfHeapReserve
    ;
    ; Map literals base to rsi to avoid usage
    ; of rip based addresses with 32-bit displacements
    ;
    ; 48 83 xx xx | add rsi, <16-bit imm> (4 bytes)
    ; 00 00       | add byte [rax], al    (2 bytes)
    ; 00 00       | add byte [rax], al    (2 bytes)
    ; ^^ ^^                               (8 bytes total)
    ; keep high 32-bit
    ; zeroed

    __rel8_base EQU __headerPE.name_GetProcAddress

__sizeOfHeapReserve:

    add   rsi, __rel8_base - __getRIP ; rsi = __getRIP
                                      ;     + __rel8_base - __getRIP
                                      ;     = __rel8_base
    dd 0

    ; ------------------------------------------------
    ; Fourth 8-bytes chunk: SizeOfHeapCommit
    ; Not used yet, just jump to next code chunk
    ; stored at unused Data Directories entries.

__sizeOfHeapCommit:

    jmp   __nextCodePiece ; (2 bytes)
    nop                   ; (1 byte)
    nop                   ; (1 byte)
    dd 0                  ; (4 bytes)
                          ; (8 bytes total)

__loaderFlags:
    dd 0

; -------------------------------------------------------------------------------

  .numberOfRvaAndSizes dd 0

    ;
    ; Below we have 128 (16*8) bytes of unused Data Directory entries.
    ; Because we declare PE.numberOfRvaAndSizes equal to zero, we can
    ; put 128 bytes of code here.

__unusedDataDirectoryEntires:

__messageText db 'I have no imports', 0

__nextCodePiece:

    ; ##########################################################################
    ; #
    ; #        Step 1: Find KERNEL32.DLL base via return address
    ; #
    ; ##########################################################################

    ; ----------------------------------------------------------
    ; Find module base address by searching for 'MZ\x90\0' magic

    mov   eax, [rsi - __rel8_base] ; rax = dos magic readed from itself.

.searchForDosHeader:

    dec   rbx                     ; Search backward for MZ magic
    cmp   eax, dword [rbx]        ; 'MZ\x90\0' magic
    jnz   .searchForDosHeader

    ; ##########################################################################
    ; #
    ; #          Step 2: Find ExportTable in KERNEL32.DLL module
    ; #
    ; ##########################################################################

    mov   edx, [rbx + 60]         ; rdx = offset of the PE header in file (RVA)
    add   rdx, rbx                ; rdx = BASE + PE header RVA =
                                  ;     = addres of PE header in memory

    mov   edx, [rdx + 24 + 112]   ; rdx = offset to OptionalHeader (+24)
                                  ;     + ExportTable (+112)
                                  ;     = OptionalHeader.ExportTable RVA

    add   rdx, rbx                ; rdx = BASE + ExportTable RVA =
                                  ;     = address of export table in memory

    ; ##########################################################################
    ; #
    ; #      Step 3: Find GetProcAddress entry in kernel32!ExportTable
    ; #
    ; ##########################################################################

    mov   eax, [rdx + 32]         ; rax = RVA(NamePointerTable)
    add   rax, rbx                ; rax = BASE + RVA(NamePointerTable)
                                  ;     = address of NamePointerTable in memory

    push  -1                      ;
    pop   rbp                     ; rbp = procIdx = index in export table

.scanNextProc:

    ; ----------------------------
    ; Fetch next proc entry

    inc   ebp                     ; rbp = procIdx + 1 = go to next proc entry
    mov   edi, [rax + rbp*4]      ; edi = RVA(NamePointerTable[procIdx])

    add   rdi, rbx                ; rdi = BASE + RVA(NamePointerTable[procIdx])
                                  ;     = address of NamePointerTable[procIdx]
                                  ;       in memory

    ; -------------------------------------------
    ; Match 'GetProcAddress\0
    ; Possible improvement: Match zero terminator

                                  ; rsi = 'GetProcAddress' patern
    push  rsi                     ; rsi = keep pattern text unchanged
    push  14                      ;
    pop   rcx                     ; rcx = 14 = len('GetProcAddress')
    repe  cmpsb                   ; Are strings equal?
    pop   rsi                     ; rsi = keep pattern text unchanged

    jne   .scanNextProc           ; Does 'GetProcAddress' found?

    ; ##########################################################################
    ; #
    ; #         Step 4: Get entry point of GetProcAddress directly
    ; #
    ; ##########################################################################

    ; --------------------------------------------------------------------------
    ; At this place:
    ;   rbx = kernel32 base (HMODULE),
    ;   rcx = procIdx = index of GetProcAddress in exports table,
    ;   rdx = export table of kernel32.

    ; ------------------------------------------
    ; Fetch GetProcAddress ordinal
    ; ... = ExportTable.OrdinalTable[procIdx]

    mov   eax, [rdx + 36]         ; eax = RVA(ExportTable.OrdinalTable)
    add   rax, rbx                ; rax = ExportTable.OrdinalTable

    movzx ecx, word [rax + rbp*2] ; ecx = ExportTable.OrdinalTable[procIdx]
                                  ;     = GetProcAddress ordinal number

    ; -------------------------------------------------------
    ; Fetch GetProcAddress entry point
    ; ... = BASE + ExportTable.ExportAddressTable[ordinal]

    mov   eax, [rdx + 28]         ; eax = RVA(ExportTable.ExportAddressTable)
    add   rax, rbx                ; rax = ExportTable.ExportAddressTable

    mov   edi, [rax + rcx*4]      ; edi = RVA(GetProcAddress)
    add   rdi, rbx                ; rdi = BASE + RVA(GetProcAddress)
                                  ;     = GetProcAddress entry point

    ; ##########################################################################
    ; #
    ; #   Step 5: Use GetProcAddress to find entry of LoadLibraryA routine.
    ; #
    ; ##########################################################################

    ; ----------------------------------------------
    ; ... = GetProcAddress(kernel32, 'LoadLibraryA')

    enter 32+8, 0                 ; Make shadow space (+32) and align stack
                                  ; to 16-bytes before system calls (+8)

    push  rbx                     ;
    pop   rcx                     ; rcx = rbx = moduleBase = kernel32

    lea   rdx, [rsi + __headerPE.name_LoadLibraryA - __rel8_base]

                                  ; rdx = 'LoadLibraryA'
    call  rdi                     ; rax = GetProcAddress(kernel32,
                                  ;                     'LoadLibrary')

    ; ##########################################################################
    ; #
    ; #   Step 6: Load 'msvcrt.dll' module.
    ; #
    ; ##########################################################################

    ; --------------------------------
    ; Import msvcrt.dll
    ; ... = LoadLibraryA('msvcrt.dll')

    lea   rcx, [rsi + __headerPE.name_msvcrt - __rel8_base]
                                  ; rcx = 'msvcrt.dll'
    call  rax                     ; rax = LoadLibrary('msvcrt.dll')

    ; ------------------------------------
    ; Import msvcrt!puts routine
    ; ... = GetProcAddress(msvcrt, 'puts')

    push  rax                     ;
    pop   rcx                     ; rcx = moduleBase = msvcrt

    lea   rdx, [rsi + __headerPE.name_puts - __rel8_base]

                                  ; rdx = 'puts'
    call  rdi                     ; rax = GetProcAddress(msvcrt, 'puts')

    ; ----------------------------
    ; Call puts() to show it works

.printMessage:

    lea   rcx, [rsi + __messageText - __rel8_base]
                                  ; rcx = text to print
    call  rax                     ; call puts(messageText)

    leave                         ; clean up stack frame
    ret                           ; exit process, go back to the parent module

    ; -----------------------------------
    ; Fill up to 268 bytes, because PE32+
    ; file probably cannot be smaller (?)

    nop
    nop
    nop
