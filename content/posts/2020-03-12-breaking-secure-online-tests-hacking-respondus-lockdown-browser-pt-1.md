---
title: Breaking Secure Online Tests – Hacking Respondus’ “Lockdown” Browser – Pt. 1
author: Justin
date: 2020-03-12T17:18:45+00:00
url: /2020/03/breaking-secure-online-tests-hacking-respondus-lockdown-browser-pt-1/
draft: false
---
_If you want to skip right to the code, it&#8217;s available on GitHub:_ <https://github.com/melotic/ThreateningYeti> 

_This is a series on hacking the Lockdown Browser._

The recent outbreak of Coronavirus has many colleges and universities switching their in-person classes to 100%. With this, many colleges are turning to software like Lockdown Browser to secure their online tests to prevent cheating.

If you&#8217;re a college student, you&#8217;ve more than likely had to use Respondus&#8217; Lockdown Browser, a software application that is essentially a _secure_ web browser. On launch, the web browser will navigate to your universities learning management system (Canvas, Blackboard, D2L, etc.)<figure class="wp-block-image size-large">

![](/wp-content/uploads/2020/03/EiHN87o.jpg)

Lockdown Browser boasts itself as &#8220;the gold standard for securing online exams in classrooms or proctored environments&#8221;, and advertises these features:

  * Assessments are displayed full-screen and cannot be minimized
  * Browser menu and toolbar options are removed, except for Back, Forward, Refresh and Stop
  * Prevents access to other applications including messaging, screen-sharing, virtual machines, and remote desktops
  * Printing and screen capture functions are disabled
  * Copying and pasting anything to or from an assessment is prevented
  * Right-click menu options, function keys, keyboard shortcuts and task switching are disabled
  * An assessment cannot be exited until the student submits it for grading
  * Assessments that are set up for use with LockDown Browser cannot be accessed with other browsers 

Circumventing these measures is super trivial, lets reverse engineer the application using IDA, and build a DLL we can inject to hook APIs!

## Hiding Processes from Lockdown

On startup, Lockdown will force you to close &#8220;bad&#8221; processes. <figure class="wp-block-image size-large">

![](/wp-content/uploads/2020/03/4bUzRpv.png)

Our plan to defeat this is with DLL Injection and function hooking. We can inject a DLL into lockdown browser, which will allow us to execute our code in the context of lockdown browser. This allows us to modify the functionality of system calls and APIs, essentially serving as a man-in-the-middle for function calls. We can modify arguments, return values, and functionalities.

To counter this, we could cross-reference calls to `EnumProcesses`, and see where they are enumerating the processes on the system.

Interestingly, there is no import table entry for `EnumProcesses`, instead, Lockdown will dynamically import it using `LoadLibrary`and `GetProcAddress`, and store the function address in memory.<figure class="wp-block-image size-large">

![](/wp-content/uploads/2020/03/SsKp3pe.png) <figcaption>Lockdown dynamically resolving APIs</figcaption></figure> 

I wanted to see how Lockdown was using these APIs, and annotating the structure in IDA would be very painstaking as it was over 13,000 bytes. Instead, I decided to cross-reference calls to `TerminateProcess`. Maybe we could find a reference that shows a message box, opens the process, then terminates it.

Sure enough, I found one.

``` C
BOOL __usercall ldb::KillBlacklistedProcess@<eax>(DWORD dwProcessId@<ecx>, int show_msgbox@<edx>, char *a3, char *processName, int *errorStatus)
{
  DWORD pid; // edi
  const char *v6; // esi
  const char *v7; // eax
  HANDLE hProcess; // eax
  void *v10; // edi
  BOOL result; // esi
  int err; // eax
  int err_1; // eax
  char *v14; // [esp-Ch] [ebp-628h]
  CHAR Caption; // [esp+10h] [ebp-60Ch]
  char v16; // [esp+410h] [ebp-20Ch]

  *errorStatus = 0;
  pid = dwProcessId;
  if ( show_msgbox )
  {
    if ( *(_DWORD *)(dword_522C98 + 0xB81C) )
    {
      v6 = ldb::GetEncryptedString(2);
    }
    else
    {
      v14 = processName ? processName : a3;
      v7 = ldb::GetEncryptedString(7);
      sprintf((int)&v16, (int)v7, (int)v14);
      v6 = &v16;
    }
    strcpy_s(&Caption, 0x400u, "LockDown Browser");
    strcat_s(&Caption, 0x400u, " (2.0.6.01)");
    if ( MessageBoxA(0, v6, &Caption, 0x52004u) == 7 )
      return 0;
  }
  hProcess = OpenProcess(0x100001u, FALSE, pid);// PROCESS_TERMINATE | SYNCHRONIZE 
  v10 = hProcess;
  if ( hProcess )
  {
    result = TerminateProcess(hProcess, 0);
    if ( !result )
    {
      err = GetLastError();
      if ( !err )
        err = 0x1092;
      *errorStatus = err;
    }
    CloseHandle(v10);
  }
  else
  {
    err_1 = GetLastError();
    if ( !err_1 )
      err_1 = 0x1092;
    result = 0;
    *errorStatus = err_1;
  }
  if ( processName )
  {
    if ( !_strnicmp(processName, "outloo", 6u) )
      result = 1;
  }
  return result;
}
```

Interestingly, Lockdown encrypts some of these _sensitive_ strings, such as the above text in the message box, and also all of the names of the blacklisted processes. Let&#8217;s see what Lockdown has blacklisted.

## Decrypting Blacklisted Processes

My first thought is that Lockdown is more than likely storing these encrypted processes in the binary&#8217;s resources. This should include process names, and also process modules as evident by their dynamically resolved functions (`EnumProcesses`, `EnumProcessModules`). Lockdown includes modules as some software like Fraps injects into the process and has the ability to record the screen.

Popping the binary into PE-bear, a RBINARY resource raises immediate suspicion.<figure class="wp-block-image size-large">

![](/wp-content/uploads/2020/03/UB7mcvz.png)<figcaption>The resource in question in PE-bear</figcaption></figure> 

To find out how they use these resources, we can cross-reference calls to `FindResource`. Luckily, there was one x-ref.<figure class="wp-block-image size-large">

![](/wp-content/uploads/2020/03/DEIBL8L.png) 

I determined their encryption to be blowfish based on [findcrypt-yara][1], an IDA plugin that searches for common cryptographic constants with yara.

With this information, I&#8217;ve written a quick and dirty python script to automatically dump the decrypted RBINARY resource and create a nice C array to import into our tool. 

``` python
import pefile
import blowfish
import sys

if len(sys.argv) != 2:
    print ("[-] usage: decrypt_rsrc.py <lockdown_path>")
    sys.exit(-1)

print("[*] Loading Lockdown PE File")
pe = pefile.PE(sys.argv[1])
enc_resource = None

for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    if str(entry.name) == str("RBINARY"):
        enc_resource = entry.directory.entries[0].directory.entries[0]

if enc_resource == None:
    print("[-] Couldn't find RBINARY")
    sys.exit(-1)

size = enc_resource.data.struct.Size
offset = enc_resource.data.struct.OffsetToData

print("[*] Found RBINARY resource, size={} offset={}".format(size, offset))

# extract data, first 4 bytes is the length of data
data = pe.get_memory_mapped_image()[offset+4:offset+size]

print("[*] Decrypting data")
bf_cipher = blowfish.Cipher(b"nQ6sSow6w5plZ72t")
data_decrypted = b"".join(bf_cipher.decrypt_ecb(data))

print("[*] Saving decrypted data")
with open('ldb_strings.bin', 'wb') as f:
    f.write(data_decrypted)

print("[*] Generating C Array with blacklisted exe's\n")
# process data in 2.06.01 is [0x1C341:0x4172b], lets generalize
data_process = data_decrypted[0x1C000:]

index=0
length=len(data_process)
blacklisted = []

while index < length:
    i = data_process.find(b'.exe', index)
    if i == -1:
        break
    
    chars = ""
    j = i
    while True:
        curr_char = data_process[j]
        if curr_char == 0:
            break
        chars = chr(curr_char) + chars
        j = j - 1

    chars = chars + "exe"
    blacklisted.append(chars)
    index = i + 1

# https://stackoverflow.com/questions/53808694/how-do-i-format-a-python-list-as-an-initialized-c-array
def to_c_array(values, ctype="char", name="blacklisted_exe", colcount=8):
    values = ['"' + v + '"' for v in values]
    rows = [values[i:i+colcount] for i in range(0, len(values), colcount)]
    body = ',\n    '.join([', '.join(r) for r in rows])
    return '{} {}[] = {{\n    {}}};'.format(ctype, name, body)

print(to_c_array(blacklisted) + "\n")
```

Running this script gives an output similar to this. I&#8217;ve truncated the full results of the array for brevity.

```
PS E:\melotic\Documents\ld_ida\scripts> python .\decrypt_rsrc.py 'C:\Program Files (x86)\Respondus\LockDown Browser\LockDownBrowser.exe'
[*] Loading Lockdown PE File
[*] Found RBINARY resource, size=274876 offset=2567544
[*] Decrypting data
[*] Saving decrypted data
[*] Generating C Array with blacklisted exe's

char blacklisted_exe[] = {
    "livecomm.exe", "twitter-win8.exe", "hcontrol.exe", "kem.exe", "setpoint.exe", "type32.exe", "msmsgs.exe", "msnmsgr.exe",
    "wlcomm.exe", "deskpins.exe", "wwahost.exe", "displayfusion.exe", "displayfusionhookappwin6064.exe", "displayfusionhookappwin6032.exe", "displayfusionservice.exe", "desktops.exe", "ctlvcentral.exe", ... };
```

With these processes, we can now hide all of the banned processes from Lockdown. We want to fully hide these processes. Under the hood, `EnumProcess`is a wrapper over `NtQuerySystemInformation`. So we can hook this function, and mask our blacklisted processes from Lockdown. Heres our hooked `NtQuerySystemInformation`

``` C
NTSTATUS WINAPI ty::hooks::nt_query_system_information(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength) {
  const auto status =
      og_nt_query_system_information(SystemInformationClass, SystemInformation,
                                     SystemInformationLength, ReturnLength);

  if (SystemProcessInformation == SystemInformationClass &&
      status == ERROR_SUCCESS) {
    auto previous = P_SYSTEM_PROCESS_INFORMATION(SystemInformation);
    auto current = P_SYSTEM_PROCESS_INFORMATION((PUCHAR)previous +
                                                previous->NextEntryOffset);

    while (previous->NextEntryOffset != NULL) {
      for (auto& exe : globals::blacklisted_exes) {
        if (_wcsicmp(exe, current->ImageName.Buffer) == 0) {
          // bad boi detected
          if (current->NextEntryOffset == 0) {
            previous->NextEntryOffset = 0;
          } else {
            previous->NextEntryOffset += current->NextEntryOffset;
          }

          current = previous;
          break;
        }
      }

      previous = current;
      current = P_SYSTEM_PROCESS_INFORMATION((PUCHAR)current +
                                             current->NextEntryOffset);
    }
  }

  return status;
}
```

With this, our blacklisted processes are now invisible to Lockdown. Stay tuned for part 2.

 [1]: https://github.com/polymorf/findcrypt-yara