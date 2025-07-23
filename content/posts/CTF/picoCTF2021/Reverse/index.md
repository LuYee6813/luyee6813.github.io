---
title: "picoCTF 2021 reverse write-up"
date: 2024-01-30
categories: [CTF]
tags: [picoCTF2021]
ShowToc: true
TocOpen: false
---

```javascript
''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])
```

寫一個程式把它解密

```javascript
encode_flag = open("enc").read()
flag = ""
for i in range(0, len(encode_flag)):
    character1 = chr((ord(encode_flag[i]) >> 8))
    character2 = chr(encode_flag[i].encode('utf-16be')[-1])
    flag += character1
    flag += character2
print(flag)
```

`Flag: picoCTF{16_bits_inst34d_of_8_26684c20}`

## keygenme-py \[30 points\]

從 source code 中看到已經有一部分 flag，看起來是要找出 key_part_dynamic1_trial

```javascript
key_part_static1_trial = "picoCTF{1n_7h3_|<3y_of_";
key_part_dynamic1_trial = "xxxxxxxx";
key_part_static2_trial = "}";
key_full_template_trial =
  key_part_static1_trial + key_part_dynamic1_trial + key_part_static2_trial;
```

把 username 拿去 sha256 後取 4,5,3,6,2,7,1,8

```javascript
import hashlib
flag_part1 = "picoCTF{1n_7h3_|<3y_of_"
flag_part2 = "".join([hashlib.sha256(b"GOUGH").hexdigest()[x] for x in [4,5,3,6,2,7,1,8]])
flag_part3 = "}"
flag = flag_part1 + flag_part2 + flag_part3
print(flag)
```

`Flag: picoCTF{1n_7h3_|<3y_of_f911a486}`

## crackme-py \[30 points\]

這題看完 source code 後發現他已經有寫好的 function 只是沒有使用

```python
def decode_secret(secret):
    """ROT47 decode

    NOTE: encode and decode are the same operation in the ROT cipher family.
    """

    # Encryption key
    rotate_const = 47

    # Storage for decoded secret
    decoded = ""

    # decode loop
    for c in secret:
        index = alphabet.find(c)
        original_index = (index + rotate_const) % len(alphabet)
        decoded = decoded + alphabet[original_index]

    print(decoded)
```

```line-numbers
┌──(luyee㉿DESKTOP-KADOGNG)-[~/picoCTF]
└─$ /bin/python3 /home/luyee/picoCTF/2021/reverse/crackme-py/crackme.py
What's your first number? 123
What's your second number? 123
The number with largest positive magnitude is 123
picoCTF{1|\/|_4_p34|\|ut_4593da8a}
```

所以直接拿來用，Flag 就出來了＠＠

`Flag: picoCTF{1|\/|_4_p34|\|ut_4593da8a}`

## ARMssembly 0 \[40 points\]

這題就是看 ASM 發現在比大小，傳入兩個參數後，回傳最大者，故如果`182476535`和`3742084308`，會回傳`3742084308`

```shell
func1:
    sub sp, sp, #16
    str w0, [sp, 12]
    str w1, [sp, 8]
    ldr w1, [sp, 12]
    ldr w0, [sp, 8]
    cmp w1, w0
    bls .L2
    ldr w0, [sp, 12]
    b   .L3
```

把`3742084308`轉成 hex 去除 0x 就得到 flag 了

```python
flag = hex(3742084308)
print('picoCTF{'+flag[2::]+'}')
```

`Flag: picoCTF{df0bacd4}`

## speeds and feeds \[50 points\]

nc 過去後發現印出類似座標的東西，先把他存起來

```line-numbers
nc mercury.picoctf.net 59953 > flag.txt
```

google 了一下發現這東西是 Gcode -\> CNC 在使用的

把他丟到這網站就跑出 flag 了

`Flag: picoCTF{num3r1ca1_cOntrO1_f3fea95b}`

## Shop \[50 points\]

丟到 IDA 分析，從 main 開始追

接著看到 main_openShop，可以看到 monery = main_menu 的返回值，所以繼續追到 main_menu

到 main_menu 看到 v15 = wallet - \*num \* 選擇價格，是值運算，代表可以輸入負數讓錢越來越多

直接 nc 過去實作

得到加密的 flag，看起來是 ASCII 碼，使用 python 轉碼，得到 flag

```line-numbers
arr = [112, 105, 99, 111, 67, 84, 70, 123, 98, 52, 100, 95, 98, 114, 111, 103, 114, 97, 109, 109, 101, 114, 95, 55, 57, 55, 98, 50, 57, 50, 99, 125]

# 使用列表生成式將ASCII碼轉換為對應的字母
result = [chr(i) for i in arr]

# 將結果串聯成字串
result_string = ''.join(result)

# 印出轉換後字的
print(result_string)
```

`Flag: picoCTF{b4d_brogrammer_797b292c}`

## ARMssembly 1 \[70 points\]

先把檔案載下來，發現是 armv8-a 架構，屬於 AArch64，因為自己的系統是 x86_64 所以嘗試 Cross-Compile and Link，跑起來時發現要輸入正確的數字才會對，所以使用 shell script 去暴力解

```line-numbers
#!/bin/bash

# Cross-Compile and Link
$(aarch64-linux-gnu-as -o chall_1.o chall_1.S)
$(aarch64-linux-gnu-gcc -o chall_1.elf chall_1.o)
$(chmod +x chall_1.elf)

counter=0
while true; do
    echo "Running with input: $counter"
    # 透過 $() 捕捉執行後的輸出
    output=$(qemu-aarch64 ./chall_1.elf $counter)
    # 檢查輸出是否不等於 "You Lose :(" 字串
    if [[ $output != *"You Lose :("* ]]; then
        echo "Found the correct input: $counter"
        # 格式要為picoCTF{XXXXXXXX} -> (hex, lowercase, no 0x, and 32 bits. ex. 5614267 would be picoCTF{0055aabb})
        echo "Flag: picoCTF{$(printf "%08x" $counter)}"
        break
    fi
    counter=$((counter + 1))
done
```

## ARMssembly 2 \[90 points\]

把題目給的數字丟進去，轉進制就出來了

```line-numbers
#!/bin/bash

# Cross-Compile and Link
$(aarch64-linux-gnu-as -o chall_2.o chall_2.S)
$(aarch64-linux-gnu-gcc -o chall_2.elf chall_2.o)
$(chmod +x chall_2.elf)

# 執行結果: Result: 3979085410
# 只取數值部分
output=$(qemu-aarch64 ./chall_2.elf 4189673334 | grep -o '[0-9]*')
echo "Flag: picoCTF{$(printf "%08x" $output)}"
```

## Hurry up! Wait! \[100 points\]

載下來後先 file 發現這檔案其實是 elf，雖然檔名是 exe

```line-numbers
┌──(luyee㉿DESKTOP-KADOGNG)-[~/picoCTF/2021/reverse/Hurry up! Wait!]
└─$ file svchost.exe
svchost.exe: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c083b0f6ecaeb1517082fb6ed0cd9e3f295ec2cc, stripped
```

gdb 執行的時候噴錯：`error while loading shared libraries: libgnat-7.so.1`  
所以去載一下需要的 libraries，用 gdb 跑起來發現會卡住，感覺就有貓膩，丟到 IDA 去分析  
從 main 開始分析，看到會 call `sub_1D7C` `sub_298A` `sub_1D52`

```line-numbers
main proc near
...忽略
mov     rdi, rax
call    ___gnat_initialize
call    sub_1D7C
call    sub_298A
call    sub_1D52
call    ___gnat_finalize
...忽略
```

每個 functio 都點進去看一下後發現 `sub_298A`裡面有一個 delay function，delay 1000000000000000 秒難怪執行後會卡住，所以推測底下就是 print flag 的 function

```line-numbers
sub_298A proc near
; __unwind {
push    rbp
mov     rbp, rsp
mov     rdi, 1000000000000000
call    _ada__calendar__delays__delay_for
...忽略
```

> 思路：在 rdi 賦值後把數值改成 0

`Flag: picoCTF{d15a5m_ftw_eab78e4}`

## gogo \[110 points\]

先丟到 IDA 反編譯，從`main_main`中可看出使用*scanf*去讀密碼`_currPasswd`然後傳入`checkPasswd`，所以接著去看`checkPasswd`

```line-numbers
_currPasswd = (string *)runtime_newobject((runtime__type *)&RTYPE_string_0);
typ[0].array = (interface_ *)"Enter Password: ";
typ[0].len = 16;
memset(&typ[0].cap, 0, sizeof(_slice_interface_));
fmt_Printf(*(string *)&typ[0].array, *(_slice_interface_ *)&typ[0].cap);
v6[0] = &RTYPE__ptr_string;
v6[1] = _currPasswd;
typ[0].array = (interface_ *)"%s\n";
typ[0].len = 3;
typ[0].cap = (int)v6;
*(_QWORD *)&typ[1].array = 0x100000001LL;
fmt_Scanf(*(string *)&typ[0].array, *(_slice_interface_ *)&typ[0].cap);
main_checkPassword(*_currPasswd);
```

```line-numbers
// main.checkPassword
unsigned int __usercall main_checkPassword@(string input)
{
  unsigned int result; // eax
  int v2; // ebx
  uint8 key[32]; // [esp+4h] [ebp-40h] BYREF
  char v4[32]; // [esp+24h] [ebp-20h]

  if ( input.len < 32 )
    os_Exit(0);
  ((void (*)(void))loc_8090B18)();
  qmemcpy(key, "861836f13e3d627dfa375bdb8389214e", sizeof(key));
  ((void (*)(void))loc_8090FE0)();
  result = 0;
  v2 = 0;
  while ( (int)result < 32 )
  {
    if ( result >= input.len || result >= 0x20 )
      runtime_panicindex();
    if ( (key[result] ^ input.str[result]) == v4[result] )
      ++v2;
    ++result;
  }
  return result;
}
```

條件:`input.len`要大於 32 且 `key[result]`^`input.str[result]`要等於`v4[result]`

思路: 把`key[result]`和`input.str[result]`找出來後 xor 就拿到密碼了

`key[result]` 記憶體位址：`$esp+$eax*1+0x4`

```line-numbers
gef➤ hexdump byte $esp+$eax*1+0x4 -s 32
0x1844ff28     38 36 31 38 33 36 66 31 33 65 33 64 36 32 37 64    861836f13e3d627d
0x1844ff38     66 61 33 37 35 62 64 62 38 33 38 39 32 31 34 65    fa375bdb8389214e
```

`input.str[result]` 記憶體位址：\$esp+\$eax\*1+0x24

```line-numbers
gef➤  hexdump byte $esp+$eax*1+0x24 -s 32
0x1844ff48     4a 53 47 5d 41 45 03 54 5d 02 5a 0a 53 57 45 0d    JSG]AE.T].Z.SWE.
0x1844ff58     05 00 5d 55 54 10 01 0e 41 55 57 4b 45 50 46 01    ..]UT...AUWKEPF.
```

寫成 pwn script 如下：

```line-numbers
from pwn import *
# password = key[result] ^ input.str[result]
key = unhex("3836313833366631336533643632376466613337356264623833383932313465")
input = unhex("4a53475d414503545d025a0a5357450d05005d555410010e4155574b45504601")
password = xor(key, input)
# 印出 password 但不要有 b'
# print(f'password:{password.decode()}')

# 指令 nc 過去輸入 password 和 goldfish
r = remote('mercury.picoctf.net', 48728)
r.recvuntil('Enter Password:')
r.sendline(password)
r.recvuntil('What is the unhashed key?')
r.sendline('goldfish')
#接收輸出
print(r.recvall().decode())
```

`Flag: picoCTF{p1kap1ka_p1c0b187f1db}`

## ARMssembly 3 \[130 points\]

和 ARMssembly 2 一樣，編譯起來把數字帶入 Flag 就出來了

```line-numbers
#!/bin/bash

# Cross-Compile and Link
$(aarch64-linux-gnu-as -o chall_3.o chall_3.S)
$(aarch64-linux-gnu-gcc -o chall_3.elf chall_3.o)
$(chmod +x chall_3.elf)

# Run
output=$(qemu-aarch64 ./chall_3.elf 2541039191 | grep -o '[0-9]*')
echo "Flag: picoCTF{$(printf "%08x" $output)}"
```

`Flag: picoCTF{00000039}`

## Let’s get dynamic \[150 points\]

先編譯並跑起來隨邊塞值測試

```line-numbers
┌──(luyee㉿DESKTOP-KADOGNG)-[~/picoCTF/2021/reverse/Let's get dynamic]
└─$ gcc chall.S -o chall.o

┌──(luyee㉿DESKTOP-KADOGNG)-[~/picoCTF/2021/reverse/Let's get dynamic]
└─$ ./chall.o
123
Correct! You entered the flag.
```

看到題目說 Let’s get dynamic，可以想到應該是要動態偵錯

`x/96i main` -\> 看一下 main 在幹嘛

看到\時呼叫 memcmp，所以下斷點在\ -\> `b *(main+385)` -\> `run`

之後可以看到 flag 已經傳到 `$rsi` ，而剛剛輸入隨便輸入的測值放在`$rdi`

```line-numbers
memcmp@plt (
   $rdi = 0x00007fffffffe080 → 0x0000000a66647361 ("asdf\n"?),
   $rsi = 0x00007fffffffe040 → "picoCTF{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_14bfa700}",
   $rdx = 0x0000000000000031,
   $rcx = 0x00007fffffffe040 → "picoCTF{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_14bfa700}"
)
```

使用 `x/s $rsi`看`$rsi`的值

`Flag: picoCTF{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_14bfa700}`

## Easy as GDB \[160 points\]

可以看到這個 function 會返回正確的字母數

```line-numbers
gef➤  r
input the flag: p
gef➤  x/x $ebp-0x14
0xffffd294: 0x00000001
gef➤  r
input the flag: pi
gef➤  x/x $ebp-0x14
0xffffd294: 0x00000002
gef➤  r
input the flag: picoCTF{
gef➤  x/x $ebp-0x14
0xffffd294: 0x00000008
```

用 pwntool 寫一個暴力破解程式：

```line-numbers
# /usr/bin/env python3
from pwn import *
from string import *

p = process("gdb-gef")
p.sendline("file ./brute")
p.sendline("start")
p.recvuntil("gef")
p.sendline("b *0x565559a7")
print(p.recvuntil("gef"))
alphabet = string.printable
flag = "picoCTF"
while "}" not in flag:
    for c in alphabet:
        p.sendline("run")
        p.recvuntil("Starting program")
        print("trying " + flag + c)
        p.sendline(flag + c)
        p.recvuntil("flag")
        p.recvuntil("gef")
        p.sendline("x/x $ebp-0x14")
        p.recvuntil("0xffff")
        count = int(p.recvline().split()[1], 16)
        if count > len(flag):
            flag += c
            print(flag)
            break
```

## ARMssembly 4 \[170 points\]

和前面幾題都一樣，跑起來傳值就完事，~~已經變 template 了~~

```line-numbers
#!/bin/bash

# Cross-Compile and Link
$(aarch64-linux-gnu-as -o chall_4.o chall_4.S)
$(aarch64-linux-gnu-gcc -o chall_4.elf chall_4.o)
$(chmod +x chall_4.elf)

# Run
output=$(qemu-aarch64 ./chall_4.elf 2907278761 | grep -o '[0-9]*')
echo "Flag: picoCTF{$(printf "%08x" $output)}"
```

`Flag: picoCTF{ad498e1c}`

## Powershelly \[180 points\]

這題有點通靈 BJ4 了

## Rolling My Own \[300 points\]

先用 IDA 反編譯看 main:

```line-numbers
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int v3; // eax
  __int64 v4; // rdx
  int i; // [rsp+8h] [rbp-F8h]
  int j; // [rsp+8h] [rbp-F8h]
  int k; // [rsp+Ch] [rbp-F4h]
  void (__fastcall *v9)(__int64 (__fastcall *)()); // [rsp+10h] [rbp-F0h]
  _BYTE *ptr; // [rsp+18h] [rbp-E8h]
  int v11[4]; // [rsp+20h] [rbp-E0h]
  __int64 v12[2]; // [rsp+30h] [rbp-D0h]
  char v13[48]; // [rsp+40h] [rbp-C0h] BYREF
  char s[64]; // [rsp+70h] [rbp-90h] BYREF
  char dest[72]; // [rsp+B0h] [rbp-50h] BYREF
  unsigned __int64 v16; // [rsp+F8h] [rbp-8h]

  v16 = __readfsqword(0x28u);
  setbuf(stdout, 0LL);
  strcpy(v13, "GpLaMjEWpVOjnnmkRGiledp6Mvcezxls");
  v11[0] = 8;
  v11[1] = 2;
  v11[2] = 7;
  v11[3] = 1;
  memset(s, 0, sizeof(s));
  memset(dest, 0, 0x40uLL);
  printf("Password: ");
  fgets(s, 64, stdin);
  s[strlen(s) - 1] = 0;
  for ( i = 0; i <= 3; ++i )
  {
    strncat(dest, &s[4 * i], 4uLL);
    strncat(dest, &v13[8 * i], 8uLL);
  }
  ptr = malloc(0x40uLL);
  v3 = strlen(dest);
  sub_E3E(ptr, dest, v3);
  for ( j = 0; j <= 3; ++j )
  {
    for ( k = 0; k <= 3; ++k )
      *((_BYTE *)v12 + 4 * k + j) = ptr[16 * k + j + v11[k]];
  }
  v9 = (void (__fastcall *)(__int64 (__fastcall *)()))mmap(0LL, 0x10uLL, 7, 34, -1, 0LL);
  v4 = v12[1];
  *(_QWORD *)v9 = v12[0];
  *((_QWORD *)v9 + 1) = v4;
  v9(sub_102B);
  free(ptr);
  return 0LL;
}
```

從 main 中可以看到輸入被存到變數 s 中

```line-numbers
printf("Password: ");
fgets(s, 64, stdin);
```

```line-numbers
import hashlib

requiredBytes = ["4889fe48", "bff126dc", "b3070000", "00ffd6"]
offsets = [8,2,7,1]
requiredString = ["GpLaMjEW", "pVOjnnmk", "RGiledp6", "Mvcezxls"]
found = False
password = []
for x in range(0, len(requiredString), 1):
    found = False
    #Generate 4 characters per iteration
    for a in range(33, 123, 1):
        for b in range(33, 123, 1):
            for c in range(33, 123, 1):
                for d in range(33, 123, 1):
                    hashThis = chr(a) + chr(b) + chr(c) + chr(d) + requiredString[x]
                    result = hashlib.md5(hashThis.encode()).hexdigest()
                    #print(result)
                    if (result[offsets[x]*2:offsets[x]*2+len(requiredBytes[x])] == requiredBytes[x]):
                        password.append(hashThis)
                        print("Found smth!")
                        print(hashThis[:4])
                        found = True
                        break

                if found:
                    break
            if found:
                break
        if found:
            break
print(password)
```

`Flag: picoCTF{r011ing_y0ur_0wn_crypt0_15_h4rd!_3c22f4e9}`

## Checkpass \[375 points\]

```line-numbers
from pwn import *

flag_try_char = string.digits+string.ascii_letters+"_"

context.log_level = "error"
def count_instrucations(flag):
    valgrind_stderr = process([    "valgrind", "--tool=cachegrind", "./checkpass", "picoCTF{"+flag+"}"])
    valgrind_stderr.recvuntil("I   refs:")
    answer = int(valgrind_stderr.recvline().strip().decode().replace(",", ""))
    valgrind_stderr.close()
    return answer

def find_pass_index(base_chr):
    global best_count;
    search_indexs = [i for i in range(32) if collect_pass[i] == "*"]
    for i in search_indexs:
        try_pass = collect_pass[:i] + base_chr + collect_pass[i + 1:]
        print(try_pass)
        count = count_instrucations(try_pass)
        if count > best_count:
            best_count = count
            print("found an index: "+str(i))
            return try_pass

collect_pass = "********************************"
best_count = count_instrucations(collect_pass)
print("searching for necessary characters for verification...")
while any(c == "*" for c in collect_pass):
    for c in flag_try_char:
        count = count_instrucations(collect_pass.replace("*", c))
        if count > best_count:
            print(c+" is necessary for the next verification, searching for an index...")
            collect_pass = find_pass_index(c)
            print("approximate password: " + collect_pass + ", continuing the search...")
            break


print("finished.")
```
