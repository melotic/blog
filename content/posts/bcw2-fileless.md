---
title: "Best Cyber Warrior 22 - Fileless Writeup"
date: 2022-10-19T18:47:54-04:00
author: Justin
---

# Best Cyber Warrior '22 CTF

The Best Cyber Warrior (BCW) '22 was a CTF that was available to U.S. Army cyber personnel, hosted by the Army's Central Command. Our team, *PWN@VT*, comprised of ROTC cadets came in 2nd place!

## Best Cyber Warrior 22 - Fileless Writeup

`fileless` was a hard reverse engineering challenge. The binary to reverse engineer was an ELF executable, that dynamically decrypted another ELF file and executed it with `memfd_create` and `fexecve`. The decrypted ELF simply decrypted a flag, without doing anything else.

### Initial Recon

The first step was running `file` on the binary the challenge provided, called `final`.

```text
$ file final

final: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0c4dc88c6da0c4dd02beff916952a24699164317, stripped
```

From this, it was an ELF file, so it was time to pop this into [Ghidra](https://ghidra-sre.org).

### Ghidra Reverse Engineering

After analysis, and finding the main function, we're granted with the following disassembly:

```c
int main(int argc,char **argv,char **env)

{
  int __fd;
  void *pvVar1;
  long i;
  undefined8 *puVar2;
  undefined8 *puVar3;
  long in_FS_OFFSET;
  byte bVar4;
  undefined8 local_17f8 [765];
  long stack_cookie;
  
  bVar4 = 0;
  stack_cookie = *(long *)(in_FS_OFFSET + 0x28);
  pvVar1 = malloc(0x5fa0);
  puVar2 = &DAT_00100ec0;
  puVar3 = local_17f8;
  for (i = 0x2fd; i != 0; i = i + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + (ulong)bVar4 * -2 + 1;
    puVar3 = puVar3 + (ulong)bVar4 * -2 + 1;
  }
  FUN_00100b0c("joezid",(long)local_17f8,(long)pvVar1);
  __fd = memfd_create("[kworker/1:1]",0);
  if (__fd == -1) {
    FUN_00100b8f(-1,"cannot create in-memory fd for code");
  }
  FUN_00100bc0(__fd,(long)pvVar1,0x17e7);
  *argv = "[kworker/1:1]";
  fexecve(__fd,argv,env);
  close(__fd);
  if (stack_cookie != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

From this disassembly, we can first see that we're allocating 0x5fa0 (24,480) bytes of (memory with `malloc`, doing some initial copying with some bad obfuscation. Then `memfd_create` is called, which creates a new file descriptor, that can be written into with `write`.

Expanding on the "bad obfuscation`:

```c
uVar2 = puVar2 + (ulong)bVar4 * -2 + 1;
puVar3 = puVar3 + (ulong)bVar4 * -2 + 1;
```

Can be simplified, since `bVar2` is always 0.

`DAT_00100ec0` seems to be the location of the encrypted data. Let's clean up this disassembly by renaming and correctly setting types in Ghidra.

```c
int main(int argc, char **argv, char **env)

{
  int __fd;
  byte *mem;
  long i;
  undefined8 *enc_data;
  undefined8 *buffer;
  byte _0;
  byte stack_enc_data [765];
  
  _0 = 0;

  mem = (byte *)malloc(0x5fa0);
  enc_data = &g_encrypted_data;
  buffer = (undefined8 *)stack_enc_data;

  for (i = 0x2fd; i != 0; i = i + -1) {
    *buffer = *enc_data;
    enc_data = enc_data + (ulong)_0 * -2 + 1;
    buffer = buffer + (ulong)_0 * -2 + 1;
  }

  FUN_00100b0c("joezid",stack_enc_data,mem);

  __fd = memfd_create("[kworker/1:1]",0);
  if (__fd == -1) {
    print_err(-1,"cannot create in-memory fd for code");
  }

  FUN_00100bc0(__fd,(long)mem,0x17e7);
  *argv = "[kworker/1:1]";
  fexecve(__fd,argv,env);

  close(__fd);

  return 0;
}
```

Now, all that's left is to reverse engineer the following calls:

```c
FUN_00100b0c("joezid", stack_enc_data, mem);
...
FUN_00100bc0(__fd,(long)mem,0x17e7);
```

### What's that Decryption?

Let's take a look at the first function, `FUN_00100b0c`, and first rename some parameters based on our above reverse engineering work. I'm guessing that the string `"joezid"` is some decryption key.

```c
undefined8 maybe_decrypt(char *key, byte *enc_data, byte *mem)
{
  undefined local_118 [264];
  
  FUN_0010091e(key,(long)local_118);
  FUN_001009f7((long)local_118,(long)enc_data,(long)mem);
}
```

That's not very helpful, lets dive into the first call, `FUN_0010091e(key,(long)local_118);`. This wasn't too hard to reverse engineer, so I've renamed types and annotated a simple `swap` function, that swaps two bytes, given two byte pointers.

```c
undefined8 FUN_0010091e(char *key, byte *param_2)

{
  uint _0;
  size_t key_len;
  int j;
  int equiv_j;
  int i;
  int k;
  
  key_len = strlen(key);
  equiv_j = 0;

  for (i = 0; i < 256; i = i + 1) {
    param_2[i] = (byte)i;
  }

  for (k = 0; k < 256; k = k + 1) {
    j = (uint)param_2[k] + equiv_j + (int)key[k % (int)key_len];
    _0 = (uint)(j >> 31) >> 24;
    equiv_j = (j + _0 & 0xff) - _0;
    swap(param_2 + k,param_2 + equiv_j);
  }
  return 0;
}
```

We can see that this "equivalent to zero" trick from the main function appears again. `(j >> 31) >> 24 == j >> (31+24)` on a 32 bit type always results in zero.

From this function, its clear that this is the [Key Schedule Algorithmn (KSA) for RC4](https://en.wikipedia.org/wiki/RC4#Key-scheduling_algorithm_(KSA)). The Wikipedia psuedocode for the KSA is:

```python
for i from 0 to 255
    S[i] := i
endfor
j := 0
for i from 0 to 255
    j := (j + S[i] + key[i mod keylength]) mod 256
    swap values of S[i] and S[j]
endfor
```

Which matches exactly to the decompiled code.

Lets see if the other function call, `FUN_001009f7` is in fact RC4 decryption.

```c
int rc4_dec(byte *rc4_s, byte *enc_data, byte *out)

{
  int rc4_i;
  int j;
  ulong i;
  
  rc4_i = 0;
  j = 0;

  for (i = 0; i < 0x17e8; i = i + 1) {
    rc4_i = rc4_i + 1U & 0xff;
    j = (uint)rc4_s[rc4_i] + j & 0xff;
    swap(rc4_s + rc4_i,rc4_s + j);

    out[i] = enc_data[i] ^ rc4_s[(rc4_s[j] + rc4_s[rc4_i])];
  }
  return 0;
}
```

Yep! This is RC4!

There's still one more function call to reverse, `FUN_00100bc0(__fd,(long)mem,0x17e7);`. But since this call is after the RC4 decryption, and before `memexec_fd`, we can probably guess this is some `write` call.

```c
void FUN_00100bc0(int fd, byte *data, long size)
{
  ssize_t bytes_out;
  size_t __n;
  long written_sz;
  
  written_sz = 0;
  do {
    __n = 0x7ffff000;

    if ((ulong)(size - written_sz) < 0x7ffff001) {
      __n = size - written_sz;
    }

    bytes_out = write(fd,data + written_sz,__n);
    if (bytes_out == -1) {
      print_err(-1,"writing to memfd failed\n");
    }

    written_sz = written_sz + bytes_out;

  } while (written_sz != size);

  return;
}
```

This is a `write` with some funny business going on. Give this a closer look, and you'll see that since `written_sz` is zero, then`__n == size - 0`, so only 1 write will occur.

Of course in theory. The call to `write` may not write all of the available data, so this will look until all of the data has been written into the file descriptor.

### Extracting the ELF

If you've been paying attention, numerous sizes have been used to decrypt and write the data. So, to make our lives easier, and prevent mistakes, we'll go with the following approach:

1. Set a breakpoint on `fexecve`
2. Determine what File Descriptor is being used
3. Dump the data from the file descriptor, using `/proc/xxx/fd/y`
4. Reverse engineer the ELF

So, lets launch gdb!

#### $ gdb fileless

First, we'll set a breakpoint on `fexecve`:

```bash
gef➤  break fexecve
Breakpoint 1 at 0x7a0
```

Run the program until we hit our breakpoint:

![](/bcw22-fileless/gdb-break-execve.png)

From the screenshot, we can see that the file descriptor is passed in through `rdi`, so our file descriptor is 3.

Running `info proc`, we get the process ID:

```bash
gef➤  info proc
process 10787
cmdline = '/home/justin/ctf/bcw22/final'
cwd = '/home/justin/ctf/bcw22'
exe = '/home/justin/ctf/bcw22/final'
```

So, lets pipe that data written into a file for analysis:

```bash
$ cat /proc/10787/fd/3 > final_dumped 
```

Lets run file on this and ensure that it's an ELF:

```bash
$ file final_dumped 

final_dumped: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, missing section headers at 6056
```

Uh-oh. **`missing section headers at 6056`** The section headers are stripped! These aren't needed for proper execution of the binary however. Running `readelf -S final_dumped` should confirm this:

```bash
$ readelf -S final_dumped

There are 27 section headers, starting at offset 0x1128:
readelf: Error: Reading 1728 bytes extends past end of file for section headers
```

Yikes. Luckily, we can still *somewhat* disassemble this with Ghidra.

![](/bcw22-fileless/gdb-break-execve.png)

Not good. We can import this manually, and manually disassembly the program by finding the entry point. Load this into Ghidra as a *raw* file.

![](/bcw22-fileless/ghidra-raw-import.png)

Next, let's use the "Aggressive Instruction Finder" to find the instructions:

![](/bcw22-fileless/ghidra-aggressive.png)

Scrolling down, we find a long block of move instructions, that looks like a decryption routine:

```asm
    PUSH               RBP
    MOV                RBP,RSP
    SUB                RSP,0x70
    MOV                RAX,qword ptr FS:[0x28]
    MOV                qword ptr [RBP + local_10],RAX
    XOR                EAX,EAX
    MOV                byte ptr [RBP + local_68],0xcc
    MOV                byte ptr [RBP + local_67],0x8d
    MOV                byte ptr [RBP + local_66],0x2c
    MOV                byte ptr [RBP + local_65],0xec
    MOV                byte ptr [RBP + local_64],0x6f
    MOV                byte ptr [RBP + local_63],0xcc
    MOV                byte ptr [RBP + local_62],0x26
    MOV                byte ptr [RBP + local_61],0x89
    MOV                byte ptr [RBP + local_60],0x66
    MOV                byte ptr [RBP + local_5f],0x89
    MOV                byte ptr [RBP + local_5e],0x66
    MOV                byte ptr [RBP + local_5d],0x6e
    MOV                byte ptr [RBP + local_5c],0x6e
    MOV                byte ptr [RBP + local_5b],0xeb
    MOV                byte ptr [RBP + local_5a],0xad
    MOV                byte ptr [RBP + local_59],0x86
    MOV                byte ptr [RBP + local_58],0x89
    MOV                byte ptr [RBP + local_57],0xee
    MOV                byte ptr [RBP + local_56],0x86
    MOV                byte ptr [RBP + local_55],0x4e
    MOV                byte ptr [RBP + local_54],0x66
    MOV                byte ptr [RBP + local_53],0xeb
    MOV                byte ptr [RBP + local_52],0x4d
    MOV                byte ptr [RBP + local_51],0xae
    MOV                byte ptr [RBP + local_50],0x6e
    MOV                byte ptr [RBP + local_4f],0x8e
    MOV                byte ptr [RBP + local_4e],0xeb
    MOV                byte ptr [RBP + local_4d],0xcc
    MOV                byte ptr [RBP + local_4c],0x6
    MOV                byte ptr [RBP + local_4b],0x4e
    MOV                byte ptr [RBP + local_4a],0xeb
    MOV                byte ptr [RBP + local_49],0x2f
    MOV                byte ptr [RBP + local_48],0x6
    MOV                byte ptr [RBP + local_47],0xae
    MOV                byte ptr [RBP + local_46],0xaf
    MOV                qword ptr [RBP + local_38],0x0
    MOV                qword ptr [RBP + local_30],0x0
    MOV                qword ptr [RBP + local_28],0x0
    MOV                qword ptr [RBP + local_20],0x0
    MOV                word ptr [RBP + local_18],0x0
    MOV                byte ptr [RBP + local_16],0x0
    MOV                dword ptr [RBP + local_6c],0x0
    JMP                LAB_00000799
LAB_00000771                                    XREF[1]:     0000079d(j)  
    MOV                EAX,dword ptr [RBP + local_6c]
    CDQE
    MOVZX              EAX,byte ptr [RBP + RAX*0x1 + -0x60]
    MOVZX              EAX,AL
    MOV                ESI,0x3
    MOV                EDI,EAX
    CALL               FUN_0000066a   ; decryption functioon           undefined FUN_0000066a()
    MOV                EDX,EAX
    MOV                EAX,dword ptr [RBP + local_6c]
    CDQE
    MOV                byte ptr [RBP + RAX*0x1 + -0x30],DL
    ADD                dword ptr [RBP + local_6c],0x1
LAB_00000799                                    XREF[1]:     0000076f(j)  
    CMP                dword ptr [RBP + local_6c],0x19
    JLE                LAB_00000771
    MOV                EAX,0x0
    MOV                RCX,qword ptr [RBP + local_10]
    XOR                RCX,qword ptr FS:[0x28]
    JZ                 LAB_000007b8
    CALL               FUN_00000540                                     undefined FUN_00000540()
```

I decided to manually analyze this assembly because Ghidra incorrectly computed the length of the array in the disassembly.

The function at `FUN_0000066a` is a simple decryption routine:

```c
uint decrypt(byte data, byte key)
{
  return (int)(uint)data >> (-key & 7) | (uint)data << (key & 0x1f);
}
```

Armed with this information, we can craft a simple program in C to decrypt this data:

```c
#include <stdint.h>
#include <string.h>
#include <stdio.h>

typedef unsigned char byte;
typedef unsigned int uint;

#define SZ (35)

byte decrypt(byte x, int key)
{
    return (uint)x >> (-key & 7) | (uint)x << (key & 0x1f);
}

int main()
{
    int i;
    byte local_68[35];
    byte local_38[35];

    local_68[0] = 0xcc;
    local_68[1] = 0x8d;
    local_68[2] = 0x2c;
    local_68[3] = 0xec;
    local_68[4] = 0x6f;
    local_68[5] = 0xcc;
    local_68[6] = 0x26;
    local_68[7] = 0x89;
    local_68[8] = 0x66;
    local_68[9] = 0x89;
    local_68[10] = 0x66;
    local_68[11] = 0x6e;
    local_68[12] = 0x6e;
    local_68[13] = 0xeb;
    local_68[14] = 0xad;
    local_68[15] = 0x86;
    local_68[16] = 0x89;
    local_68[17] = 0xee;
    local_68[18] = 0x86;
    local_68[19] = 0x4e;
    local_68[20] = 0x66;
    local_68[21] = 0xeb;
    local_68[22] = 0x4d;
    local_68[23] = 0xae;
    local_68[24] = 0x6e;
    local_68[25] = 0x8e;
    local_68[26] = 0xeb;
    local_68[27] = 0xcc;
    local_68[28] = 6;
    local_68[29] = 0x4e;
    local_68[30] = 0xeb;
    local_68[31] = 0x2f;
    local_68[32] = 6;
    local_68[33] = 0xae;
    local_68[34] = 0xaf;
    memset(local_38, 0, SZ);

    byte uVar1;
    for (i = 0; i < SZ; i = i + 1)
    {
        uVar1 = decrypt(local_68[i], 3);
        local_38[i] = (byte)uVar1;
    }

    printf("%s\n", local_38);
}
```

Running this, we get the flag: `flag{f1L3L3ss_m4Lw4r3_just_f0r_y0u}`