import os
import sys

if os.name != 'nt':
    raise Exception("IMPORTANT: I need the Windows version.") 
_verbose = ((len(sys.argv) > 1) and bool(sys.argv[1]))


from ctypes import (
    WinDLL, POINTER, create_string_buffer, create_unicode_buffer,
    c_int32, c_uint, c_uint, c_char, c_wchar, c_int, c_uint, c_void_p
    )
_ToUnicodeEx = WinDLL('user32').ToUnicodeEx
_ToUnicodeEx.argtypes = [
        c_uint,           # wVirtKey   virtual-key code to be translated
        c_uint,           # wScanCode  hardware scan code of ˙wVirtKey˙
        POINTER(c_char),  # lpKeyState current keyboard state (256-byte array)
        POINTER(c_wchar), # pwszBuff   buffer that receives translated chars
        c_int,            # cchBuff    size of the `pwszBuff` buffer (in chars)
        c_uint,           # wFlags     behavior of the function
        c_void_p          # dwhkl      input locale identifier
]
_ToUnicodeEx.restype = c_int


output_file_path = "keyboard_output.txt"

def write_to_file(data):
    with open(output_file_path, "a", encoding="utf-8") as file:
        file.write(data + "\n")

def ToUn(vk,sc,wfl,hkid):
    kst = create_string_buffer(256)
    b = create_unicode_buffer(5)
    if _ToUnicodeEx(vk,sc,kst,b,5,wfl,hkid):
        return b.value
    else:
        return chr( 0xFFFD) # Replacement Character




from ctypes import WinDLL
user32 = WinDLL('user32', use_last_error=True)


def list_parents(pid, proclist):
    '''For verbose output'''
    aux = [_ for _ in proclist if _[0] == pid]
    if len( aux) > 0:
        auxcon = [x for x in proclist if (
                x[1] == aux[0][0] and x[2] == "conhost.exe")]
        list_parents(aux[0][1], proclist)
        print('parent', aux[0], auxcon if (len(auxcon) == 0) else auxcon[0])

def get_servant_conhost(pid, proclist):
    """Find “attendant” host process (conhost.exe)"""
    aux = [_ for _ in proclist if _[0] == pid]
    if len( aux) > 0:
        auxcon = [x for x in proclist if (
                x[1] == aux[0][0] and x[2] == "conhost.exe")]
        if len( auxcon) == 0:
            auxconret = get_servant_conhost(aux[0][1], proclist)
            return auxconret
        else:
            auxconret = auxcon[0]
            auxconret.append( aux[0][2])
            return auxconret
    else:
        return []


def get_conhost_threads():
    if sys.executable.lower().endswith('\\pythonw.exe'):
        return []
    import wmi
    c = wmi.WMI()
    w_where = ' or '.join([
        'Name like "p%.exe"',  # py.exe|python.exe|pwsh.exe|powershell.exe 
        'Name = "conhost.exe"',
        'Name = "cmd.exe"'
    ])
    w_properties = 'ProcessId, ParentProcessId, Name'
    w_wql = f'SELECT {w_properties} FROM Win32_Process where {w_where}'
    w_wqlaux = c.query(w_wql)
    proc_list = [[wqlitem.__getattr__('ProcessId'),
          wqlitem.__getattr__('ParentProcessId'),
          wqlitem.__getattr__('Name')] for wqlitem in w_wqlaux] 
    if _verbose:
        list_parents(os.getpid(), proc_list)
    servant_conhost = get_servant_conhost(os.getpid(), proc_list)
    if len( servant_conhost) == 0:
        return []
    else:
        try:
            w_where = f'ProcessHandle = {servant_conhost[0]}'
            w_wql = f'SELECT Handle FROM Win32_Thread WHERE {w_where}'
            w_wqlHandle = c.query(w_wql)
            wqlthreads = [x.__getattr__('Handle') for x in w_wqlHandle]
        except:
            wqlthreads = []
    return wqlthreads


# required if run from `cmd` or from the `Run` dialog box (`<WinKey>+R`) 
conhost_threads = get_conhost_threads()
if _verbose:
    print( 'threads', conhost_threads)
                                    

def get_current_keyboard_layout():
    foregroundWindow  = user32.GetForegroundWindow();
    foregroundProcess = user32.GetWindowThreadProcessId(int(foregroundWindow), 0);
    keyboardLayout    = user32.GetKeyboardLayout(int(foregroundProcess));
    keyboardLayout0   = user32.GetKeyboardLayout(int(0));
    if keyboardLayout == 0  or len(conhost_threads):                 
        if keyboardLayout == 0:
            keyboardLayout = keyboardLayout0
        for thread in conhost_threads:
            aux = user32.GetKeyboardLayout( int(thread))
            if aux != 0 and aux != keyboardLayout0:
                if _verbose:
                    print('thread', thread)
                keyboardLayout = aux
                break
    return keyboardLayout


### improved original code
#   Detect keyboard input with support of other languages from English

###

import unicodedata
from pynput import keyboard
last_key = keyboard.Key.media_next  # improbable last key pressed



pressed_keys = set()

def on_press(key):
    global last_key, pressed_keys
    try:
        if isinstance(key, keyboard.Key):
            if key == keyboard.Key.space:
                c_hkl = get_current_keyboard_layout()
                chklp = f'{(c_hkl & 0xFFFFFFFF):08x}'
                print_output(key.value.char, key.value.vk, 0x39, c_hkl, chklp, unicodedata.name(key.value.char, '?'))
            else:
                if last_key != key:
                    print(key.name)
                    write_to_file(key.name)
                    last_key = key
        else:
            c_hkl = get_current_keyboard_layout()
            chklp = f'{(c_hkl & 0xFFFFFFFF):08x}'
            c_char = ToUn(key.vk, key._scan, 0, c_hkl)
            print_output(c_char[0], key.vk, key._scan, c_hkl, chklp, unicodedata.name(c_char[0], '?'))
    except KeyboardInterrupt:
        listener.stop()


def print_output(char, vk, scan, c_hkl, chklp, char_name):
    output_data = f'{char}  {vk}  {scan} {c_hkl} {chklp} {char_name}'
    print(output_data)
    write_to_file(output_data)

def on_release(key):
    if key == keyboard.Key.esc:    
        return False             # Stop listener
    


print('\n  vk_code scancode   HKL dec (HKL hexa) character name')
with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()