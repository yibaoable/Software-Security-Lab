.586p
.model flat,stdcall
option casemap:none;
include    c:\masm32\include\windows.inc
include    c:\masm32\include\kernel32.inc
includelib c:\masm32\lib\kernel32.lib
include    c:\masm32\include\user32.inc
includelib c:\masm32\lib\user32.lib

GetApiAddress PROTO:DWORD,:DWORD

.data
    Kernel32Addr dd ?
    ExportKernel dd ?
    GetProcAddr dd ?
    LoadLibraryAddr dd ?
    aGetProcAddr db "GetProcAddress", 0 
    GetProcAddLen equ  $-aGetProcAddr-1
    aLoadLibrary db "LoadLibraryA" , 0
    LoadLibraryLen equ $-aLoadLibrary-1
    strMessageBoxA db "MessageBoxA",0
    strUser32  db "User32.dll",0
    strShow    db "��̬messagebox��ʾ",0
    szTitle db "�����", 0
    szShow db "Good Job!", 0
    temp1 db "Kernel32.dll ������ַ��%8x" ,0dh, 0ah
    db       "LoadLibrary ��ַ��     %8x" ,0dh, 0ah
    db       "GetProcAddress ��ַ��  %8x" ,0dh, 0ah , 0
    temp2 db 0 dup(100)     
.code
main:
Start:
       mov  esi,[esp]
       and  esi,0fffff000h
LoopFindKernel32:
       sub  esi,1000h
       cmp  word ptr[esi], 'ZM'
       jnz  short LoopFindKernel32
GetPeHeader:
       mov edi,dword ptr[esi+3ch]  
       add edi, ESI 
       cmp word ptr[edi],4550h  
       jnz short LoopFindKernel32 
       mov Kernel32Addr,ESI  
     
       invoke GetApiAddress,Kernel32Addr,addr aLoadLibrary
       mov LoadLibraryAddr,EAX  
     
       invoke GetApiAddress , Kernel32Addr, addr aGetProcAddr
       mov GetProcAddr , EAX  
     
       invoke wsprintf,addr temp2,addr temp1,Kernel32Addr,LoadLibraryAddr,GetProcAddr
       invoke MessageBoxA,0,addr temp2,addr szTitle,0
     
     lea eax,strUser32
     push eax
     call LoadLibraryAddr
     lea edx,strMessageBoxA
     push edx
     push eax
     call GetProcAddr
     lea edx,szShow
     LEA ECX,strShow
     PUSH 0
     PUSH ECX
     PUSH EDX
     PUSH 0
     CALL eax

     invoke ExitProcess,0
         
         

GetApiAddress proc uses ecx ebx edx esi edi hModule:DWORD ,szApiName:DWORD
   LOCAL dwReturn:DWORD
   LOCAL dwApiLength:DWORD
   mov dwReturn,0
   mov esi,szApiName
   mov edx,esi
 Continue_Searching_Null:
   cmp byte ptr[esi],0
   jz  We_Got_The_Length
   inc esi
   jmp Continue_Searching_Null
 We_Got_The_Length:
   inc esi
   sub esi,edx
   mov dwApiLength ,ESI  ;����Ϊ����szApiName�ַ����Ĵ�С�����������0��Ϊ0x0D���ֽ�

   mov esi,hModule  ;��mzͷ�������ַ���浽esi��
   add esi,[esi+3ch]  ;��mzͷ�������ַ����0x3ch���浽esi�У���esi��peͷ�������ַ
   assume esi:ptr IMAGE_NT_HEADERS  ;ָ��esi��ָ�ĵ�ַ����һ��MAGE_NT_HEADERS���͵Ľṹ��
   mov esi,[esi].OptionalHeader.DataDirectory.VirtualAddress  ;��ȡEXPORT Table��Ҳ��֮ΪIMAGE_EXPORT_DIRECTORY��������ƫ�Ƶ�ַ
   add esi,hModule  ;����mzͷ�������ַ����ȡEXPORT Table��Ҳ��֮ΪIMAGE_EXPORT_DIRECTORY���������ַ
   assume esi:ptr IMAGE_EXPORT_DIRECTORY  ;ָ��esi��ָ�ĵ�ַ����һ�����͵�IMAGE_EXPORT_DIRECTORY�ṹ��

   mov ebx,[esi].AddressOfNames  ;��ȡName Pointer Table������ƫ�Ƶ�ַ
   add ebx,hModule  ;����mzͷ�������ַ����ȡName Pointer Table�������ַ
   xor edx,EDX  ;��edx�Ĵ�����0
   .repeat
      push ESI  ;esi��ָ����һ�����͵�IMAGE_EXPORT_DIRECTORY�ṹ��,��esiѹջ
      mov edi,[ebx]  ;[ebx]����Name Pointer Table����ĵ�һ������,Ҳ���ǵ�һ��������������ƫ�Ƶ�ַ
      add edi,hModule  ;����mzͷ�������ַ����ȡ��һ���������������ַ����ֵ��edi
      mov esi,szApiName  ;szApiNameΪָ����ҪѰ�ҵĺ������������ַ������ָ�ҪѰ�ҵĺ������������ַ��ֵ��esi�Ĵ���
      mov ecx,dwApiLength  ;dwApiLengthΪ�ַ����Ĵ�С�����������β��\0�ַ���
      CLD  ;�����־λ��edi��esi���Զ���1
      repz cmpsb  ;��Ա�edi��esi��ָ������ݣ����������ȣ���zf��־λ��Ϊ1�������ҵ���һ��������������ƫ�Ƶ�ַ
      .if ZERO?     ;���zf��־Ϊ1�������ҵ��� ��ָ����������ȵ��ַ��� �������ַ������������ebx��
          pop esi
          jmp _Find_Index
      .endif
      pop esi
      add ebx,4
      inc edx
      .until edx >= [esi].NumberOfNames
      jmp _Exit
      
      _Find_Index:
         sub ebx,[esi].AddressOfNames  ;ebx��ʾName Pointer Table���� ���������������ֵ������ַ ����������ַ
         ;[esi].AddressOfNames��ʾName Pointer Table������ƫ�Ƶ�ַ��ebx��ȥ[esi].AddressOfNames��Ȼ���ڼ�ȥhModule���͵õ��� �� �����Name Pointer Table������ƫ�Ƶ�ַ
         sub ebx,hModule
         shr ebx,1  ;ebx����2����Ϊ��Name Pointer Table��һ����ռ�ĸ��ֽڶ���EXPORT Ordnal Table��һ����ռ�����ֽ�
         add ebx, [esi].AddressOfNameOrdinals  ;[esi].AddressOfNameOrdinals ��ʾ EXPORT Ordnal Table������ƫ�Ƶ�ַ������ebx���͵õ��������EXPORT Ordnal Table������ƫ�Ƶ�ַ
         
         add ebx,hModule
         movzx eax,word ptr [ebx]  ;ȡebxָ���ֵ��Ҳ���Ǻ�������EXPORT Ordnal Table����š�
         shl eax,2  ;�������4������ΪExport Address Table�е�һ��ռ�ĸ��ֽ�
         add eax,[esi].AddressOfFunctions  ;����Export Address Table�������ƫ�Ƶ�ַ
         add eax,hModule  ;eax��ʾ����Export Address table���е�һ����������ַ ��
         
         mov eax,[eax]  ;������������Ҳ������������RVA���Ƶ�eax�Ĵ���
         add eax,hModule
         mov dwReturn,eax
        _Exit:
         mov eax,dwReturn
         ret
       GetApiAddress    endp
       end main
  