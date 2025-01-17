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
    strShow    db "动态messagebox演示",0
    szTitle db "检测结果", 0
    szShow db "Good Job!", 0
    temp1 db "Kernel32.dll 基本地址：%8x" ,0dh, 0ah
    db       "LoadLibrary 地址：     %8x" ,0dh, 0ah
    db       "GetProcAddress 地址：  %8x" ,0dh, 0ah , 0
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
   mov dwApiLength ,ESI  ;以上为计算szApiName字符串的大小，包括后面的0，为0x0D个字节

   mov esi,hModule  ;将mz头的虚拟地址保存到esi中
   add esi,[esi+3ch]  ;将mz头的虚拟地址加上0x3ch保存到esi中，即esi是pe头的虚拟地址
   assume esi:ptr IMAGE_NT_HEADERS  ;指定esi所指的地址的是一个MAGE_NT_HEADERS类型的结构体
   mov esi,[esi].OptionalHeader.DataDirectory.VirtualAddress  ;获取EXPORT Table表（也称之为IMAGE_EXPORT_DIRECTORY）的虚拟偏移地址
   add esi,hModule  ;加上mz头的虚拟地址，获取EXPORT Table表（也称之为IMAGE_EXPORT_DIRECTORY）的虚拟地址
   assume esi:ptr IMAGE_EXPORT_DIRECTORY  ;指定esi所指的地址的是一个类型的IMAGE_EXPORT_DIRECTORY结构体

   mov ebx,[esi].AddressOfNames  ;获取Name Pointer Table的虚拟偏移地址
   add ebx,hModule  ;加上mz头的虚拟地址，获取Name Pointer Table的虚拟地址
   xor edx,EDX  ;将edx寄存器清0
   .repeat
      push ESI  ;esi所指的是一个类型的IMAGE_EXPORT_DIRECTORY结构体,将esi压栈
      mov edi,[ebx]  ;[ebx]代表Name Pointer Table表项的第一项内容,也就是第一个函数名的虚拟偏移地址
      add edi,hModule  ;加上mz头的虚拟地址，获取第一个函数名的虚拟地址并赋值给edi
      mov esi,szApiName  ;szApiName为指定的要寻找的函数名的虚拟地址，这条指令将要寻找的函数名的虚拟地址赋值给esi寄存器
      mov ecx,dwApiLength  ;dwApiLength为字符串的大小，包括后面结尾的\0字符串
      CLD  ;方向标志位，edi和esi会自动加1
      repz cmpsb  ;会对比edi和esi所指向的内容，如果内容相等，则zf标志位设为1，代表找到第一个函数名的虚拟偏移地址
      .if ZERO?     ;如果zf标志为1，代表找到了 和指定函数名相等的字符串 的虚拟地址，并将其存放在ebx中
          pop esi
          jmp _Find_Index
      .endif
      pop esi
      add ebx,4
      inc edx
      .until edx >= [esi].NumberOfNames
      jmp _Exit
      
      _Find_Index:
         sub ebx,[esi].AddressOfNames  ;ebx表示Name Pointer Table表中 包含所求函数的名字的虚拟地址 的项的虚拟地址
         ;[esi].AddressOfNames表示Name Pointer Table的虚拟偏移地址，ebx减去[esi].AddressOfNames，然后在减去hModule，就得到了 项 相对于Name Pointer Table的虚拟偏移地址
         sub ebx,hModule
         shr ebx,1  ;ebx除以2，因为在Name Pointer Table中一个项占四个字节而在EXPORT Ordnal Table中一个项占两个字节
         add ebx, [esi].AddressOfNameOrdinals  ;[esi].AddressOfNameOrdinals 表示 EXPORT Ordnal Table的虚拟偏移地址，加上ebx，就得到了相对于EXPORT Ordnal Table的虚拟偏移地址
         
         add ebx,hModule
         movzx eax,word ptr [ebx]  ;取ebx指向的值，也就是函数名在EXPORT Ordnal Table中序号。
         shl eax,2  ;序号扩大4倍，因为Export Address Table中的一项占四个字节
         add eax,[esi].AddressOfFunctions  ;加上Export Address Table表的虚拟偏移地址
         add eax,hModule  ;eax表示的是Export Address table表中的一个项的虚拟地址 。
         
         mov eax,[eax]  ;将这个项的内容也就是所求函数的RVA复制到eax寄存器
         add eax,hModule
         mov dwReturn,eax
        _Exit:
         mov eax,dwReturn
         ret
       GetApiAddress    endp
       end main
  