.data

spoof_info STRUCT

    set_fpreg_frame DQ 1
    set_fpreg_frame_size DQ 1
    set_fpreg_frame_random_offset DQ 1

    push_rbp_frame DQ 1
    push_rbp_offset DQ 1
    push_rbp_frame_size DQ 1
    push_rbp_frame_random_offset DQ 1

    jmp_rbx_gadget DQ 1
    jmp_rbx_gadget_ref DQ 1
    jmp_rbx_gadget_frame_size DQ 1

    add_rsp_gadget DQ 1
    add_rsp_gadget_frame_size DQ 1

    arbitrary_frame DQ 1
	arbitrary_frame_size DQ 1

    target_function DQ 1
    return_address DQ 1

    num_args DQ 1
    arg1 DQ 1
    arg2 DQ 1
    arg3 DQ 1
    arg4 DQ 1
    arg5 DQ 1
    arg6 DQ 1
    arg7 DQ 1
    arg8 DQ 1

spoof_info ENDS

.code

experimental_spoof proc

    mov rax, [rsp]
    mov [rsp+10h], rsi
    mov [rsp+08h], rbp
    mov rbp, rsp

    lea     rax, restore_experimental
    push    rax
    lea     rsi, [rsp]

; -------------------------------------------------------------
; mov rbp, rsp
; -------------------------------------------------------------
    push [rcx].spoof_info.set_fpreg_frame
    add qword ptr [rsp], 100

; -------------------------------------------------------------
; push rbp
; -------------------------------------------------------------
    mov rax, [rcx].spoof_info.return_address
	sub rax, [rcx].spoof_info.set_fpreg_frame_size
    
    sub rsp, [rcx].spoof_info.push_rbp_frame_size
    mov r10, [rcx].spoof_info.push_rbp_offset
	mov [rsp+r10], rax
    push [rcx].spoof_info.push_rbp_frame
    add qword ptr [rsp], 100

; -------------------------------------------------------------
; arbitrary frame for example
; -------------------------------------------------------------
    sub rsp, [rcx].spoof_info.add_rsp_gadget_frame_size
    push [rcx].spoof_info.add_rsp_gadget

; -------------------------------------------------------------
; jmp rbx
; -------------------------------------------------------------
	sub rsp, [rcx].spoof_info.jmp_rbx_gadget_frame_size
	push [rcx].spoof_info.jmp_rbx_gadget

; -------------------------------------------------------------
; arbitrary frame(s) for example
; -------------------------------------------------------------
    sub rsp, [rcx].spoof_info.add_rsp_gadget_frame_size
    push [rcx].spoof_info.add_rsp_gadget

    sub rsp, [rcx].spoof_info.arbitrary_frame_size
    push [rcx].spoof_info.arbitrary_frame

; -------------------------------------------------------------

    mov rax, [rcx].spoof_info.target_function

    ; handle function param(s)
    mov r9, [rcx].spoof_info.arg4
    mov r8, [rcx].spoof_info.arg3
    mov rdx, [rcx].spoof_info.arg2
    mov rcx, [rcx].spoof_info.arg1

    jmp qword ptr rax

experimental_spoof endp

restore_experimental proc

mov rsp, rbp
mov rbp, [rsp+08h]
mov rsi, [rsp+10h]
ret

restore_experimental endp

end