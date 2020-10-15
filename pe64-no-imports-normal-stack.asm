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
; Last modified on: 2020-10-15

; PE32+ withouts imports table (stack version)
; ============================================

; Standard PE32+ file (64-bit) showing how to get address to LoadLibraryA()
; and GetProcAddress() *WITHOUT* imports table.

; - 1536 bytes,
; - 2 sections (code and data),
; - *NO* imports table and other data directories,
; - uses *RETURN ADDRESS* to get kernel32.dll base,
; - reads entry point of GetAddressProc() directly in kernel32 exports,
; - then call it to get entry of LoadLibraryA() routine.

; Based on code from posts:
; -------------------------
; - https://stackoverflow.com/a/32820799
; - https://hero.handmade.network/forums/code-discussion/t/129-howto_-_building_without_import_libraries
; - https://stackoverflow.com/a/45528159

; Below code does:
; ----------------
;   1. Find KERNEL32.DLL base via return address,
;   2. Find ExportTable in KERNEL32.DLL module,
;   3. Find GetProcAddress entry in kernel32!ExportTable,
;   4. Get entry point of GetProcAddress directly (from kernel32 exports),
;   5. Use GetProcAddress to find entry of LoadLibraryA routine,
;   6. Import user32!MessageBoxA routine,
;   7. Call MessageBoxA() to show it's work.

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
; - Code works on x86-64 only (PE32+).

; Build by command:
; -----------------
; fasm pe64-no-imports-normal-stack.asm

format PE64

entry __entryPoint

; ##############################################################################
; #
; #                              Code section
; #
; ##############################################################################

__entryPoint:

    ; ##########################################################################
    ; #
    ; #        Step 1: Find KERNEL32.DLL base via return address
    ; #
    ; ##########################################################################

    mov   rbx, [rsp]              ; rbx = retAddr to the parent module,
                                  ;       we assume that it's a kernel32.dll

    xor   bx, bx                  ; rbx = retAddr % 0x10000
                                  ;     = retAddr & 0xffffffffffff0000

    mov   eax, 0x00905a4d         ; rax = dos magic 'MZ\x90\0'

.searchForDosHeader:

    sub   rbx, 10000h / 4         ; Search backward for MZ magic
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

    mov   esi, [rdx + 32]         ; esi = RVA(NamePointerTable)
    add   rsi, rbx                ; rsi = BASE + RVA(NamePointerTable)
                                  ;     = address of NamePointerTable in memory

    push  -1
    pop   rcx                     ; rcx = procIdx = index in export table

.scanNextProc:

    ; ----------------------------
    ; Fetch next proc entry

    inc   ecx                     ; rcx = procIdx + 1 = go to next proc entry
    mov   eax, [rsi + rcx*4]      ; rax = RVA(NamePointerTable[procIdx])

    add   rax, rbx                ; rax = BASE + RVA(NamePointerTable[procIdx])
                                  ;     = address of NamePointerTable[procIdx]
                                  ;       in memory

    ; -------------------------------------------
    ; Match 'GetProcAddress\0
    ; Possible improvement: Match zero terminator

    mov   rdi, 'GetProcA'         ; Compare first 8 bytes
    cmp   rdi, qword [rax]        ;
    jnz   .scanNextProc           ;

    mov   rdi, 'Address'          ; Compare last 8 bytes including zero
    cmp   rdi, qword [rax + 7]    ; terminator. 7-th byte is compared twice
    jnz   .scanNextProc           ; to make code shorter.

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

    movzx ecx, word [rax + rcx*2] ; ecx = ExportTable.OrdinalTable[procIdx]
                                  ;     = GetProcAddress ordinal number

    ; -------------------------------------------------------
    ; Fetch GetProcAddress entry point
    ; ... = BASE + ExportTable.ExportAddressTable[ordinal]

    mov   eax, [rdx + 28]         ; rax = RVA(ExportTable.ExportAddressTable)
    add   rax, rbx                ; rax = ExportTable.ExportAddressTable

    mov   edi, [rax + rcx*4]      ; edi = RVA(GetProcAddress)
    add   rdi, rbx                ; rdi = BASE + RVA(GetProcAddress)
                                  ;     = GetProcAddress entry point

    mov   qword [__imp_GetProcAddress], rdi
                                  ; Save entry GetProcAddress

    ; ##########################################################################
    ; #
    ; #   Step 5: Use GetProcAddress to find entry of LoadLibraryA routine.
    ; #
    ; ##########################################################################

    ; ----------------------------------------------
    ; ... = GetProcAddress(kernel32, 'LoadLibraryA')

    sub   rsp, 32 + 8             ; Make shadow space (+32) and align stack
                                  ; to 16-bytes before system calls (+8)

    mov   rcx, rbx                ; rcx = rbx = moduleBase = kernel32

    lea   rdx, [__name_LoadLibraryA]

                                  ; rdx = 'LoadLibraryA'
    call  [__imp_GetProcAddress]  ; rax = GetProcAddress(kernel32,
                                  ;                     'LoadLibrary')

    mov   [__imp_LoadLibraryA], rax
                                  ; Save entry to LoadLibraryA

    ; ##########################################################################
    ; #
    ; #   Step 6: Import user32!MessageBoxA routine.
    ; #
    ; ##########################################################################

    ; --------------------------------
    ; Import user32.dll
    ; ... = LoadLibraryA('user32.dll')

    lea   rcx, [__name_user32]    ; rcx = 'user32.dll'
    call  rax                     ; rax = LoadLibrary('user32.dll')
    mov   [__imp_User32], rax     ; save user32 module base

    ; -------------------------------------------
    ; Import user32!MessageBox routine
    ; ... = GetProcAddress(user32, 'MessageBoxA')

    mov   rcx, rax                  ; rcx = moduleBase = user32
    lea   rdx, [__name_MessageBoxA] ; rdx = 'MessageBoxA'
    call  [__imp_GetProcAddress]    ; rax = GetProcAddress(msvcrt,
                                    ;                     'MessageBoxA')

    ; ##########################################################################
    ; #
    ; #       Step 7: Call MessageBoxA() to show it's work
    ; #
    ; ##########################################################################

    ; ---------------------------------------
    ; Call MessageBoxA(NULL, msg, caption, 0)

    xor   ecx, ecx                ; rcx = hWnd = NULL = desktop
    lea   rdx, [__messageText]    ; rdx = message text
    lea   r8,  [__messageCaption] ; r8  = message caption
    xor   r9d, r9d                ; r9  = uType = 0 = MB_OK
    call  rax                     ; rax = result of MessageBoxA(...)

.done:

    add   rsp, 32 + 8             ; Clean stack frame
    ret                           ;

; ##############################################################################
; #
; #                                Data section
; #
; ##############################################################################

section '.data' writeable readable

  __name_LoadLibraryA db 'LoadLibraryA', 0
  __name_MessageBoxA  db 'MessageBoxA', 0
  __name_user32       db 'user32.dll', 0

  __messageCaption db 'PE32+ without imports table (stack version).', 0
  __messageText    db 'This executable has no imports table.', 13, 10
                   db 'We found kernel32 base via return address to the parent module.', 0

  __imp_Kernel32       dq ?
  __imp_User32         dq ?
  __imp_LoadLibraryA   dq ?
  __imp_GetProcAddress dq ?
