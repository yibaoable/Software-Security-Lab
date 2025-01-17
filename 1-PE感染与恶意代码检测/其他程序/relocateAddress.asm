.586	; Relocate Address Homework 2024,
;using ml with /link to get the relocateAddress.exe, with the .text section writeable 
;to store the address into addressVal. 
;ml /coff /Cp relocateAddress.asm /link /subsystem:windows /section:.text,rwe
;重定位
.model flat, stdcall
option casemap :none   ; case sensitive
include c:\masm32\include\windows.inc 
include c:\masm32\include\comctl32.inc 
includelib c:\masm32\lib\comctl32.lib 
include c:\masm32\include\kernel32.inc 
includelib c:\masm32\lib\kernel32.lib 
include c:\masm32\include\user32.inc 
includelib c:\masm32\lib\user32.lib 

.code
    Msg	db  "2024 Name 郭靖宜 UID:U202211883,Address value =",0   ;真实地址与预期地址的差值   delta
    addressVal  db  "abcdefgh",0
; -----Store Eax into val-----------
binToAscii proc near	; change al into Ascii
   push eax
	and eax,0fh
	add al,30h
	cmp al,39h
	jbe @f
	add al,7
@@:
	stosb   ;save ax into [edi]
   pop eax
	ret
binToAscii endp

saveEax proc near   ;save eax to val in Ascii mode
	mov ecx,8
	cld
	lea edi,addressVal
saveEaxL1:	
	rol eax,4
	call binToAscii
	loop saveEaxL1
	ret
saveEax endp
;----------------------------------

Relocate	proc             
;------Relocate proc return value: ebx, ebx= VA_of_delta - Offset_delta-------
	call delta
delta:
	pop ebx
	sub ebx,offset delta
	ret
Relocate	endp


_start:
	 call localLable1
localLable1:
    pop eax
    call saveEax
    invoke MessageBox, NULL, addr addressVal, addr Msg, MB_OK
    
    call	Relocate
    mov 	eax,ebx
    call saveEax		
    invoke MessageBox, NULL, addr addressVal, addr Msg, MB_OK
    	
    invoke ExitProcess, NULL 

end	_start