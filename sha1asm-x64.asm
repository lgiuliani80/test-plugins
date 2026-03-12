; =============================================================================
; SHA-1 plugin – pure x64-64 NASM implementation
;
; Exposes the four plugin functions entirely in assembly:
;   int  sha1_get_plugin_name(char *name, int max_length)
;   void sha1_init(void)
;   void sha1_update(const uint8_t *data, uint32_t size)
;   int  sha1_get(uint8_t *sha1_buffer)
;
; Calling conventions (selected at assemble time via output format):
;   elf64  / macho64  →  System V AMD64 ABI
;       args : rdi, rsi, rdx, rcx, r8, r9
;       callee-saved : rbx, rbp, r12-r15
;   win64             →  Microsoft x64 ABI
;       args : rcx, rdx, r8, r9
;       callee-saved : rbx, rbp, rdi, rsi, r12-r15
;       shadow space : 32 bytes must be reserved by CALLER (already there for
;                      external callers); when we call nothing we don't need it.
;
; Build (Linux):
;   nasm -f elf64 sha1asm-x64.asm -o sha1asm-x64.o
;   gcc  -shared -fPIC -o sha1asm-x64.so sha1asm-x64.o
;
; Build (Windows – MSVC link):
;   nasm -f win64 sha1asm-x64.asm -o sha1asm-x64.obj
;   link /DLL /OUT:sha1asm-x64.dll sha1asm-x64.obj
; =============================================================================

; ── Calling-convention abstraction ──────────────────────────────────────────
; ARG1..ARG2: first two integer/pointer arguments
; RETREG     : return-value register (always rax on both ABIs)
; sv_extra   : registers that are callee-saved on Win64 but NOT on SysV
;              (rdi, rsi) – we only need to save them when targeting win64.

%ifidn __OUTPUT_FORMAT__, win64
    %define ARG1   rcx
    %define ARG1d  ecx
    %define ARG2   rdx
    %define ARG2d  edx
    %define WIN64  1
%else
    %define ARG1   rdi
    %define ARG1d  edi
    %define ARG2   rsi
    %define ARG2d  esi
    %undef  WIN64
%endif

; ── Section / symbol visibility ─────────────────────────────────────────────
%ifidn __OUTPUT_FORMAT__, win64
    %macro EXPORT 1
        global %1
    %endmacro
    section .data  align=16
    section .bss   align=16
    section .text
%else
    %macro EXPORT 1
        global %1:function
    %endmacro
    section .data
    section .bss
    section .text
%endif

; ── Context layout (BSS) ────────────────────────────────────────────────────
;
;  off  0 : h0        dd
;  off  4 : h1        dd
;  off  8 : h2        dd
;  off 12 : h3        dd
;  off 16 : h4        dd
;  off 20 : (pad)     dd   ← keeps bit_count 8-byte aligned
;  off 24 : bit_count dq
;  off 32 : buf_len   dd
;  off 36 : finished  dd
;  off 40 : buf       resb 64
;  total  = 104 bytes

%define CTX_H0        0
%define CTX_H1        4
%define CTX_H2        8
%define CTX_H3       12
%define CTX_H4       16
%define CTX_BITCOUNT 24
%define CTX_BUFLEN   32
%define CTX_FINISHED 36
%define CTX_BUF      40

section .bss
ctx: resb 104

; ── Read-only data ───────────────────────────────────────────────────────────
section .data
plugin_name_str: db "sha1asm-x64", 0
plugin_name_len  equ $ - plugin_name_str   ; includes NUL → length with NUL

; ── Text ─────────────────────────────────────────────────────────────────────
section .text

; =============================================================================
; int sha1_get_plugin_name(char *name /*ARG1*/, int max_length /*ARG2d*/)
;
; Copies "sha1asm-x64\0" into name, truncating to max_length bytes.
; Always NUL-terminates.  Returns 0 on success, -1 on bad args.
; =============================================================================
EXPORT sha1_get_plugin_name
sha1_get_plugin_name:
    test   ARG1, ARG1
    jz     .bad
    test   ARG2d, ARG2d
    jle    .bad

    ; Save registers that rep movsb will clobber (rdi, rsi, rcx).
    ; On Win64 rdi/rsi are callee-saved so we must preserve them;
    ; on SysV they are argument registers – we save them anyway for
    ; clarity and to keep a single code path.
%ifdef WIN64
    push   rdi
    push   rsi
%endif
    push   rbx

    ; rbx = dst (name),  r8d = max_length  (both survive rep movsb)
    mov    rbx,  ARG1
    mov    r8d,  ARG2d

    ; copy_len = min(max_length, plugin_name_len)
    mov    ecx, plugin_name_len
    cmp    r8d, ecx
    cmovl  ecx, r8d            ; ecx = min(max_length, plugin_name_len)

    lea    rsi, [rel plugin_name_str]
    mov    rdi, rbx
    rep    movsb                ; clobbers rdi, rsi, rcx → all saved/disposable

    ; Force NUL at name[max_length - 1]  (rbx and r8d are intact)
    lea    rax, [rbx + r8 - 1]
    mov    byte [rax], 0

    pop    rbx
%ifdef WIN64
    pop    rsi
    pop    rdi
%endif
    xor    eax, eax
    ret

.bad:
    mov    eax, -1
    ret

; =============================================================================
; void sha1_init(void)
;
; Initialises the static context with the SHA-1 magic constants.
; =============================================================================
EXPORT sha1_init
sha1_init:
    lea    rax, [rel ctx]
    mov    dword [rax + CTX_H0], 0x67452301
    mov    dword [rax + CTX_H1], 0xEFCDAB89
    mov    dword [rax + CTX_H2], 0x98BADCFE
    mov    dword [rax + CTX_H3], 0x10325476
    mov    dword [rax + CTX_H4], 0xC3D2E1F0
    mov    qword [rax + CTX_BITCOUNT], 0
    mov    dword [rax + CTX_BUFLEN],   0
    mov    dword [rax + CTX_FINISHED], 0
    ret

; =============================================================================
; void sha1_update(const uint8_t *data /*ARG1*/, uint32_t size /*ARG2d*/)
; =============================================================================
EXPORT sha1_update
sha1_update:
    ; Bail if finished, null pointer, or zero size
    lea    r10, [rel ctx]
    cmp    dword [r10 + CTX_FINISHED], 0
    jne    .done
    test   ARG1, ARG1
    jz     .done
    test   ARG2d, ARG2d
    jz     .done

%ifdef WIN64
    push   rdi
    push   rsi
%endif
    push   rbx
    push   r12
    push   r13
    push   r14
    push   r15
    push   rbp

    ; Update bit count:  bit_count += size * 8
    mov    eax, ARG2d
    shl    rax, 3
    add    [r10 + CTX_BITCOUNT], rax

    mov    r12, ARG1            ; src pointer
    mov    r13d, ARG2d          ; remaining bytes
    mov    rbp, r10             ; ctx pointer

    ; -- Fill partial block first --
    mov    ebx, [rbp + CTX_BUFLEN]
    test   ebx, ebx
    jz     .full_blocks

    ; space = 64 - buf_len
    mov    ecx, 64
    sub    ecx, ebx             ; ecx = space
    ; copy = min(remaining, space)
    cmp    r13d, ecx
    cmovl  ecx, r13d
    ; memcpy(ctx.buf + buf_len, src, copy)
    lea    rdi, [rbp + CTX_BUF]
    add    rdi, rbx             ; dst = buf + buf_len
    mov    rsi, r12
    mov    eax, ecx
    rep    movsb
    ; advance src, decrease remaining, increase buf_len
    add    r12, rax
    sub    r13d, eax
    add    ebx, eax
    mov    [rbp + CTX_BUFLEN], ebx

    cmp    ebx, 64
    jne    .full_blocks         ; partial block still not full

    ; block is full → compress it
    lea    rdi, [rbp + CTX_BUF]
    call   sha1_compress        ; sha1_compress(h_ptr=rbp, block_ptr=rdi) – see below
    mov    dword [rbp + CTX_BUFLEN], 0

.full_blocks:
    cmp    r13d, 64
    jl     .tail

    ; compress directly from caller buffer, no copy
    mov    rdi, r12
    call   sha1_compress
    add    r12, 64
    sub    r13d, 64
    jmp    .full_blocks

.tail:
    ; buffer leftover bytes
    test   r13d, r13d
    jz     .update_done
    lea    rdi, [rbp + CTX_BUF]
    mov    rsi, r12
    mov    ecx, r13d
    rep    movsb
    mov    [rbp + CTX_BUFLEN], r13d

.update_done:
    pop    rbp
    pop    r15
    pop    r14
    pop    r13
    pop    r12
    pop    rbx
%ifdef WIN64
    pop    rsi
    pop    rdi
%endif
.done:
    ret

; =============================================================================
; int sha1_get(uint8_t *sha1_buffer /*ARG1*/)
;
; Returns 0 on success, -1 if sha1_buffer is NULL.
; =============================================================================
EXPORT sha1_get
sha1_get:
    test   ARG1, ARG1
    jz     .bad

%ifdef WIN64
    push   rdi
    push   rsi
%endif
    push   rbx
    push   r12
    push   r13
    push   r14
    push   rbp
    sub    rsp, 128             ; 128-byte padding block on stack (16-byte aligned)

    mov    rbx, ARG1            ; save output pointer
    lea    rbp, [rel ctx]

    cmp    dword [rbp + CTX_FINISHED], 0
    jne    .already_done

    ; ── Padding ─────────────────────────────────────────────────────────
    ; Build pad[] on the stack (up to 128 bytes):
    ;   copy ctx.buf → pad
    ;   append 0x80
    ;   zero-fill to position 56 or 120
    ;   append 64-bit big-endian bit_count

    mov    ecx, [rbp + CTX_BUFLEN]
    mov    r12d, ecx            ; r12d = buf_len / pad_len counter

    ; copy buf → stack pad area (rsp already points there)
    lea    rsi, [rbp + CTX_BUF]
    mov    rdi, rsp
    rep    movsb                ; ecx bytes

    ; append 0x80
    mov    byte [rsp + r12], 0x80
    inc    r12d

    ; zero fill
    ; if pad_len <= 56 → fill to 56, total = 1 block
    ; else             → fill to 120, total = 2 blocks
    cmp    r12d, 57             ; pad_len (after 0x80) > 56?
    jg     .need_two_blocks

    ; fill [pad_len .. 55] with zero
    lea    rdi, [rsp + r12]
    mov    ecx, 56
    sub    ecx, r12d
    xor    al, al
    rep    stosb
    mov    r12d, 56
    mov    r13d, 64             ; total pad bytes = 1 block
    jmp    .append_length

.need_two_blocks:
    lea    rdi, [rsp + r12]
    mov    ecx, 120
    sub    ecx, r12d
    xor    al, al
    rep    stosb
    mov    r12d, 120
    mov    r13d, 128

.append_length:
    ; store big-endian 64-bit bit_count at [rsp + r12]
    mov    rax, [rbp + CTX_BITCOUNT]
    bswap  rax
    mov    [rsp + r12], rax

    ; compress block(s)
    mov    rdi, rsp
    call   sha1_compress
    cmp    r13d, 128
    jne    .mark_done
    lea    rdi, [rsp + 64]
    call   sha1_compress

.mark_done:
    mov    dword [rbp + CTX_FINISHED], 1

.already_done:
    ; emit digest: 5 × big-endian uint32 → sha1_buffer
    mov    r14, rbx             ; output pointer
    lea    rsi, [rbp + CTX_H0]
    mov    ecx, 5
.emit_loop:
    mov    eax, [rsi]
    bswap  eax
    mov    [r14], eax
    add    rsi, 4
    add    r14, 4
    dec    ecx
    jnz    .emit_loop

    add    rsp, 128
    pop    rbp
    pop    r14
    pop    r13
    pop    r12
    pop    rbx
%ifdef WIN64
    pop    rsi
    pop    rdi
%endif
    xor    eax, eax
    ret

.bad:
    mov    eax, -1
    ret

; =============================================================================
; Internal: sha1_compress(block_ptr: rdi)
;
; Compresses the 64-byte block pointed to by rdi into the hash state
; rooted at rbp (caller sets rbp = &ctx before calling).
;
; Uses registers: eax, ebx, ecx, edx, r8d-r11d, r14, r15
; Preserves     : rbp, rbx, r12, r13, rdi, rsi (and the Win64 extras
;                 already saved by the outer function)
;
; The message schedule W[0..79] is kept on the stack (80 × 4 = 320 bytes).
; Stack frame on entry: sha1_compress is called via `call` (pushes 8-byte
; return address → rsp is 8 mod 16). Five pushes follow (40 bytes, so rsp
; becomes 0 mod 16). sub 320 keeps rsp 0 mod 16.  Correct.
;   [rsp +   0 .. 319] : W[0..79]
; =============================================================================
sha1_compress:
    push   r15
    push   r14
    push   r13
    push   r12
    push   rbx
    sub    rsp, 320             ; W[80] on stack

    ; ── Build message schedule ────────────────────────────────────────
    ; W[0..15] = big-endian words from the input block
    xor    rcx, rcx
.sched_load:
    mov    eax, [rdi + rcx*4]
    bswap  eax
    mov    [rsp + rcx*4], eax
    inc    rcx
    cmp    rcx, 16
    jl     .sched_load

    ; W[i] = ROL1(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]),  i = 16..79
    mov    rcx, 16
.sched_expand:
    ; rcx is 64-bit throughout so [rsp + rcx*4 - n] is a valid EA
    mov    eax, [rsp + rcx*4 - 3*4]
    xor    eax, [rsp + rcx*4 - 8*4]
    xor    eax, [rsp + rcx*4 - 14*4]
    xor    eax, [rsp + rcx*4 - 16*4]
    rol    eax, 1
    mov    [rsp + rcx*4], eax
    inc    rcx
    cmp    rcx, 80
    jl     .sched_expand

    ; ── Load initial state ────────────────────────────────────────────
    ; a=r8d  b=r9d  c=r10d  d=r11d  e=r12d   temp=eax  f=ebx  i=ecx
    mov    r8d,  [rbp + CTX_H0]
    mov    r9d,  [rbp + CTX_H1]
    mov    r10d, [rbp + CTX_H2]
    mov    r11d, [rbp + CTX_H3]
    mov    r12d, [rbp + CTX_H4]

    xor    rcx, rcx             ; i = 0

    ; ── 80 rounds ─────────────────────────────────────────────────────
    ;
    ; Round structure (SHA-1):
    ;   temp = ROL5(a) + f(b,c,d) + e + K[i] + W[i]
    ;   e = d;  d = c;  c = ROL30(b);  b = a;  a = temp
    ;
    ; f and K change every 20 rounds:
    ;   0-19:  f = (b & c) | (~b & d)            K = 0x5A827999
    ;  20-39:  f = b ^ c ^ d                     K = 0x6ED9EBA1
    ;  40-59:  f = (b & c) | (b & d) | (c & d)   K = 0x8F1BBCDC
    ;  60-79:  f = b ^ c ^ d                     K = 0xCA62C1D6

.round_loop:
    ; Compute f and pick K based on i (rcx)
    cmp    rcx, 20
    jge    .r20

    ; rounds 0-19: f = (b & c) | (~b & d)  [Ch]
    mov    ebx, r9d
    and    ebx, r10d
    mov    edx, r9d
    not    edx
    and    edx, r11d
    or     ebx, edx
    mov    r14d, 0x5A827999
    jmp    .do_round

.r20:
    cmp    rcx, 40
    jge    .r40
    ; rounds 20-39: f = b ^ c ^ d  [Parity]
    mov    ebx, r9d
    xor    ebx, r10d
    xor    ebx, r11d
    mov    r14d, 0x6ED9EBA1
    jmp    .do_round

.r40:
    cmp    rcx, 60
    jge    .r60
    ; rounds 40-59: f = (b & c) | (b & d) | (c & d)  [Maj]
    mov    ebx, r9d
    and    ebx, r10d
    mov    edx, r9d
    and    edx, r11d
    or     ebx, edx
    mov    edx, r10d
    and    edx, r11d
    or     ebx, edx
    mov    r14d, 0x8F1BBCDC
    jmp    .do_round

.r60:
    ; rounds 60-79: f = b ^ c ^ d  [Parity]
    mov    ebx, r9d
    xor    ebx, r10d
    xor    ebx, r11d
    mov    r14d, 0xCA62C1D6

.do_round:
    ; temp = ROL5(a) + f + e + K + W[i]
    mov    eax, r8d
    rol    eax, 5
    add    eax, ebx            ; + f
    add    eax, r12d           ; + e
    add    eax, r14d           ; + K
    add    eax, [rsp + rcx*4]  ; + W[i]

    ; rotate state: e=d, d=c, c=ROL30(b), b=a, a=temp
    mov    r12d, r11d          ; e = d
    mov    r11d, r10d          ; d = c
    mov    r10d, r9d
    rol    r10d, 30            ; c = ROL30(b)
    mov    r9d,  r8d           ; b = a
    mov    r8d,  eax           ; a = temp

    inc    rcx
    cmp    rcx, 80
    jl     .round_loop

    ; ── Feed-forward ─────────────────────────────────────────────────
    add    [rbp + CTX_H0], r8d
    add    [rbp + CTX_H1], r9d
    add    [rbp + CTX_H2], r10d
    add    [rbp + CTX_H3], r11d
    add    [rbp + CTX_H4], r12d

    add    rsp, 320
    pop    rbx
    pop    r12
    pop    r13
    pop    r14
    pop    r15
    ret
