import ctypes
from ctypes import Structure,sizeof, windll, addressof, c_wchar, create_string_buffer
from ctypes.wintypes import DWORD, HANDLE, LPVOID, HMODULE 
import argparse
import win32api
import win32con
import win32security
import win32process
import sys

class MODULEINFO(Structure):
    _fields_ = [("lpBaseOfDll",LPVOID),
                ("SizeOfImage",DWORD),
                ("EntryPoint",LPVOID)]


def EnablePriv(privName):
    new_priv = ((win32security.LookupPrivilegeValue('',win32security.SE_DEBUG_NAME),win32con.SE_PRIVILEGE_ENABLED),)
    hCurrProc = win32process.GetCurrentProcess()
    hToken = win32security.OpenProcessToken(hCurrProc,win32security.TOKEN_ALL_ACCESS)
    res = win32security.AdjustTokenPrivileges(hToken,0,new_priv)
    win32api.CloseHandle(hToken)
    return res

def EnumModules(hProcess):
    BIG_HANDLE_ARRAY = HMODULE * 1024
    #BIG_HANDLE_ARRAY = DWORD * 1024
    arrHandle = BIG_HANDLE_ARRAY()
    needed = DWORD()
    res = windll.psapi.EnumProcessModulesEx(hProcess.__int__(),addressof(arrHandle),sizeof(arrHandle),addressof(needed),0x03)
    if res:
        numofmod = needed.value / sizeof(HMODULE)
        for i in range(numofmod):
            hMod = HMODULE(arrHandle[i])
            ModName = create_string_buffer(1024)
            windll.psapi.GetModuleBaseNameA(hProcess.__int__(),hMod,ModName,len(ModName))
            ModInfo = MODULEINFO()
            windll.psapi.GetModuleInformation(hProcess.__int__(),hMod,addressof(ModInfo),sizeof(ModInfo))
            print "Module name:%s    Base address:%x" % (ModName.value,ModInfo.lpBaseOfDll)
            windll.kernel32.CloseHandle(hMod)

if __name__ == '__main__':
    argparser=argparse.ArgumentParser(description='Enumerate process modules')
    argparser.add_argument('pid',type=int)
    args=argparser.parse_args()
    if not EnablePriv(win32security.SE_DEBUG_NAME):
        print "[-] Failed to enable DEBUG privilege."
        sys.exit(-1)
    else:
        print "[+] Debug privilege enabled."
    
    hProcess = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS,0,args.pid)
    # todo fix success test
    if not hProcess.__nonzero__ :
        print "[-] Failed to open process"
        sys.exit(-1)
        
    EnumModules(hProcess)
    
    hProcess.Close()