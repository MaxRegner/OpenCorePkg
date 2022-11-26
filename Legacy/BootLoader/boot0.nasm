; Copyright (c) 1999-2003 Apple Computer, Inc. All rights reserved.
;
; @APPLE_LICENSE_HEADER_START@
;
; Portions Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights
; Reserved.  This file contains Original Code and/or Modifications of
; Original Code as defined in and that are subject to the Apple Public
; Source License Version 2.0 (the "License").  You may not use this file
; except in compliance with the License.  Please obtain a copy of the
; License at http://www.apple.com/publicsource and read it before using
; this file.
;
; The Original Code and all software distributed under the License are
; distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
; EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
; INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE OR NON- INFRINGEMENT.  Please see the
; License for the specific language governing rights and limitations
; under the License.
;
; @APPLE_LICENSE_HEADER_END@
;
; Boot Loader: boot0
;
; A small boot sector program written in x86 assembly whose only
; responsibility is to locate the active partition, load the
; partition booter into memory, and jump to the booter's entry point.
; It leaves the boot drive in DL and a pointer to the partition entry in SI.
; This version of boot0 implements hybrid GUID/MBR partition scheme support.
;
; This boot loader must be placed in the Master Boot Record.
;
; In order to coexist with a fdisk partition table (64 bytes), and
; leave room for a two byte signature (0xAA55) in the end, boot0 is
; restricted to 446 bytes (512 - 64 - 2). If boot0 did not have to
; live in the MBR, then we would have 510 bytes to work with.
;
; boot0 is always loaded by the BIOS or another booter to 0:7C00h.
;
; This code is written for the NASM assembler.
;   nasm boot0.s -o boot0
;
; Written by Tamás Kosárszky on 2008-03-10 and JrCs on 2013-05-08.
; With additions by Turbo for EFI System Partition boot support.
;

;
; Set to 1 to enable obscure debug messages.
;
DEBUG               EQU  0

;
; Set to 1 to enable verbose mode
;
VERBOSE             EQU  0

;
; Various constants.
;
kBoot0Segment       EQU  0x0000
kBoot0Stack         EQU  0xFFF0         ; boot0 stack pointer
kBoot0LoadAddr      EQU  0x7C00         ; boot0 load address
kBoot1LoadAddr      EQU  0xE000         ; boot1 load address

kMBRBuffer          EQU  0x1000         ; MBR buffer address
kLBA1Buffer         EQU  0x1200         ; LBA1 - GPT Partition Table Header buffer address
kGPTABuffer         EQU  0x1400         ; GUID Partition Entry Array buffer address

kPartTableOffset    EQU  0x1be
kMBRPartTable       EQU  kMBRBuffer + kPartTableOffset

kSectorBytes        EQU  512            ; sector size in bytes
kBootSignature      EQU  0xAA55         ; boot sector signature
kFAT32BootCodeOffset EQU  0x5a          ; offset of boot code in FAT32 boot sector
kBoot1FAT32Magic    EQU  'BO'           ; Magic string to detect our boot1f32 code


kGPTSignatureLow    EQU  'EFI '         ; GUID Partition Table Header Signature
kGPTSignatureHigh   EQU  'PART'
kGUIDLastDwordOffs  EQU  12             ; last 4 byte offset of a GUID

kPartCount          EQU  4              ; number of paritions per table
kPartTypeFAT32      EQU  0x0c           ; FAT32 Filesystem type
kPartTypePMBR       EQU  0xee           ; On all GUID Partition Table disks a Protective MBR (PMBR)
                                        ; in LBA 0 (that is, the first block) precedes the
                                        ; GUID Partition Table Header to maintain compatibility
                                        ; with existing tools that do not understand GPT partition structures.
                                        ; The Protective MBR has the same format as a legacy MBR
                                        ; and contains one partition entry with an OSType set to 0xEE
                                        ; reserving the entire space used on the disk by the GPT partitions,
                                        ; including all headers.

kPartActive         EQU  0x80           ; active flag enabled
kPartInactive       EQU  0x00           ; active flag disabled
kEFISystemGUID      EQU  0x3BC93EC9     ; last 4 bytes of EFI System Partition Type GUID:
                                        ; C12A7328-F81F-11D2-BA4B-00A0C93EC93B
kBasicDataGUID      EQU  0xC79926B7     ; last 4 bytes of Basic Data System Partition Type GUID:
                                        ; EBD0A0A2-B9E5-4433-87C0-68B6B72699C7

;
; Format of fdisk partition entry.
;
; The symbol 'part_size' is automatically defined as an `EQU'
; giving the size of the structure.
;
           struc part
.bootid    resb 1      ; bootable or not
.head      resb 1      ; starting head, sector, cylinder
.sect      resb 1      ;
.cyl       resb 1      ;
.type      resb 1      ; partition type
.endhead   resb 1      ; ending head, sector, cylinder
.endsect   resb 1      ;
.endcyl    resb 1      ;
.lba       resd 1      ; starting lba
.sectors   resd 1      ; size in sectors
           endstruc

;
; Format of GPT Partition Table Header
;
                            struc   gpth
.Signature                  resb    8
.Revision                   resb    4
.HeaderSize                 resb    4
.HeaderCRC32                resb    4
.Reserved                   resb    4
.MyLBA                      resb    8
.AlternateLBA               resb    8
.FirstUsableLBA             resb    8
.LastUsableLBA              resb    8
.DiskGUID                   resb    16
.PartitionEntryLBA          resb    8
.NumberOfPartitionEntries   resb    4
.SizeOfPartitionEntry       resb    4
.PartitionEntryArrayCRC32   resb    4
                            endstruc

;
; Format of GUID Partition Entry Array
;
                            struc   gpta
.PartitionTypeGUID          resb    16
.UniquePartitionGUID        resb    16
.StartingLBA                resb    8
.EndingLBA                  resb    8
.Attributes                 resb    8
.PartitionName              resb    72
                            endstruc

;
; Macros.
;
%macro DebugCharMacro 1
    mov   al, %1
    call  print_char
%endmacro

%macro LogString 1
    mov   di, %1
    call  log_string
%endmacro

%if DEBUG
%define DebugChar(x)  DebugCharMacro x
%else
%define DebugChar(x)
%endif

;--------------------------------------------------------------------------
; Start of text segment.

    SEGMENT .text

    ORG     kBoot0LoadAddr

;--------------------------------------------------------------------------
; Boot code is loaded at 0:7C00h.
;
start:
    ;
    ; Set up the stack to grow down from kBoot0Segment:kBoot0Stack.
    ; Interrupts should be off while the stack is being manipulated.
    ;
    cli                             ; interrupts off
    xor     ax, ax                  ; zero ax
    mov     ss, ax                  ; ss <- 0
    mov     sp, kBoot0Stack         ; sp <- top of stack
    sti                             ; reenable interrupts

    mov     es, ax                  ; es <- 0
    mov     ds, ax                  ; ds <- 0

    DebugChar('>')

%if DEBUG
    mov     al, dl
    call    print_hex
%endif

    ;
    ; Since this code may not always reside in the MBR, always start by
    ; loading the MBR to kMBRBuffer and LBA1 to kGPTBuffer.
    ;

    xor     eax, eax
    mov     [my_lba], eax           ; store LBA sector 0 for read_lba function
    mov     al, 2                   ; load two sectors: MBR and LBA1
    mov     bx, kMBRBuffer          ; MBR load address
    call    load
    jc      error                   ; MBR load error

    ;
    ; Look for the booter partition in the MBR partition table,
    ; which is at offset kMBRPartTable.
    ;
    mov     si, kMBRPartTable       ; pointer to partition table
    call    find_boot               ; will not return on success

error:
    LogString(boot_error_str)

hang:
    hlt
    jmp     hang


;--------------------------------------------------------------------------
; Find the booter partition in the MBR partition table.
;
; Input:
;   si = pointer to partition table
;
; Output:
;   dl = partition number
;   es:bx = partition table entry
;
; On success, the booter partition is loaded into memory and control
; is transferred to the booter.
;
find_boot:
    mov     dl, 0                   ; partition number
    mov     cx, kPartCount          ; number of partitions to check
    mov     bx, si                  ; pointer to partition table

find_boot_loop:
    cmp     [bx], kPartActive       ; active flag
    jne     find_boot_next          ; not active

    mov     al, [bx+kPartType]      ; partition type
    cmp     al, kPartTypeFAT32      ; FAT32 partition type
    je      find_boot_found         ; found it

find_boot_next:
    add     bx, kPartSize           ; next partition table entry
    inc     dl                      ; next partition number
    loop    find_boot_loop          ; loop until all partitions checked

    LogString(boot_error_str)
    jmp     hang

find_boot_found:
    mov     es, bx                  ; es:bx = partition table entry
    mov     bx, kBoot0LoadAddr      ; load address
    mov     al, 1                   ; load one sector
    call    load
    jc      error                   ; load error

    mov     ax, kBoot0LoadAddr      ; booter load address
    jmp     ax                      ; transfer control to booter

;--------------------------------------------------------------------------
; Load a sector or sectors from the disk.
;
; Input:
;   al = number of sectors to load
;   bx = load address
;   [my_lba] = LBA sector number
;
; Output:
;   al = 0 on success, 1 on error
;
load:
    push    ds                      ; save ds
    mov     ds, bx                  ; ds:bx = load address
    mov     cx, kSectorSize         ; sector size
    mov     dx, kDiskPort           ; disk port
    mov     ah, kDiskRead           ; read command
    mov     ch, [my_lba+3]          ; high byte of LBA
    mov     cl, [my_lba+2]          ; middle byte of LBA
    mov     dh, [my_lba+1]          ; head
    mov     dl, [my_lba]            ; sector
    and     dl, kSectorMask         ; mask off high bits
    inc     dl                      ; sector number is 1-based
    mov     bl, kDiskDrive          ; disk drive
    mov     al, 0                   ; clear carry flag
    int     kDiskInt                ; read sector
    jc      load_error              ; error

    mov     al, 1                   ; number of sectors to read
    cmp     al, dl                  ; compare to sector number
    jbe     load_done               ; done if sector number <= 1

    mov     al, 0                   ; clear carry flag
    int     kDiskInt                ; read next sector
    jc      load_error              ; error

load_done:
    xor     al, al                  ; success
    pop     ds                      ; restore ds
    ret

load_error:
    mov     al, 1                   ; error
    pop     ds                      ; restore ds
    ret

;--------------------------------------------------------------------------
; Print a character.
;
; Input:
;   al = character to print
;
print_char:
    mov     ah, kPrintChar          ; print character
    int     kPrintInt               ; print character
    ret

;--------------------------------------------------------------------------
; Print a hex digit.
;
; Input:
;   al = digit to print
;
print_hex:
    cmp     al, 10                  ; compare to 10
    jb      print_hex_1             ; branch if less than 10
    add     al, 'A' - 10            ; convert to ASCII
    jmp     print_hex_2             ; print character

print_hex_1:
    add     al, '0'                 ; convert to ASCII

print_hex_2:
    call    print_char              ; print character
    ret

;--------------------------------------------------------------------------
; Print a string.
;
; Input:
;   es:di = pointer to string
;
print_string:
    mov     al, [es:di]             ; get character
    or      al, al                  ; check for end of string
    jz      print_string_done       ; done if end of string
    call    print_char              ; print character
    inc     di                      ; next character
    jmp     print_string            ; loop until end of string

print_string_done:
    ret

;--------------------------------------------------------------------------
