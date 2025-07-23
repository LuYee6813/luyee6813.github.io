---
title: "picoCTF 2024 Forensic - endianness-v2"
date:  2024-02-16
categories: [CTF]
tags:       [forensic]
---
 /mnt/c/Users/LuYee6813/OneDrive - gapps.ntust.edu.tw/OneDrive/筆記/blog/LuYee6813.github.io/source/\_posts/CTF/picoCTF2024/Forensic/endianness-v2 ❯ exiftool challengefile ExifTool Version Number : 12.40 File Name : challengefile Directory : . File Size : 3.3 KiB File Modification Date/Time : 2024:03:12 08:36:50+08:00 File Access Date/Time : 2024:09:06 02:45:15+08:00 File Inode Change Date/Time : 2024:09:06 02:45:17+08:00 File Permissions : -rwxrwxrwx Warning : Processing JPEG-like data after unknown 1-byte header \[02:52\]  zsh  main ↑1 ↓1  ?83 ~50 -40 

``` line-numbers
00000000   E0 FF D8 FF  46 4A 10 00  01 00 46 49  01 00 00 01  00 00 01 00  43 00 DB FF  ....FJ....FI........C...
00000018   06 06 08 00  08 05 06 07  09 07 07 07  0C 0A 08 09  0B 0C 0D 14  12 19 0C 0B  ........................
00000030   1D 14 0F 13  1D 1E 1F 1A  20 1C 1C 1A  20 27 2E 24  1C 23 2C 22  29 37 28 1C  ........ ... '.$.#,")7(.
00000048   34 31 30 2C  27 1F 34 34  32 38 3D 39  34 33 2E 3C  00 DB FF 32  09 09 01 43  410,'.4428=943.<...2...C
00000060   0C 0B 0C 09  18 0D 0D 18  21 1C 21 32  32 32 32 32  32 32 32 32  32 32 32 32  ........!.!2222222222222
```

``` line-numbers
def reverse_every_four_bytes(data):
    # Split the data into chunks of 4 bytes
    chunks = [data[i:i+4] for i in range(0, len(data), 4)]
    
    # Reverse the order of each chunk
    reversed_chunks = [chunk[::-1] for chunk in chunks]
    
    # Join the reversed chunks back together
    reversed_data = b''.join(reversed_chunks)
    
    return reversed_data

def repair_flipped_jpeg(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()

    # Reverse every 4 bytes in the file
    repaired_data = reverse_every_four_bytes(data)

    # Save the repaired data as a new JPEG file
    repaired_file_path = '/mnt/data/reversed_repaired_image.jpg'
    with open(repaired_file_path, 'wb') as repaired_file:
        repaired_file.write(repaired_data)

    return repaired_file_path

repaired_file_path = repair_flipped_jpeg(file_path)
repaired_file_path
```

flag=`picoCTF{cert!f1Ed_iNd!4n_s0rrY_3nDian_6d3ad08e}`
