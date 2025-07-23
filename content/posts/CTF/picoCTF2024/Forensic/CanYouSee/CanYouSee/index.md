---
title: "picoCTF 2024 Forensic - CanYouSee"
date:  2024-02-16
categories: [CTF]
tags:       [forensic]
---
\> unzip unknown.zip Archive: unknown.zip inflating: ukn_reality.jpg ~/CTF/picoCTF2024/forensic/CanYouSee 00:24:48 \> ls ukn_reality.jpg unknown.zip ~/CTF/picoCTF2024/forensic/CanYouSee 00:24:51 \> exiftool ukn_reality.jpg ExifTool Version Number : 12.40 File Name : ukn_reality.jpg Directory : . File Size : 2.2 MiB File Modification Date/Time : 2024:02:16 06:40:14+08:00 File Access Date/Time : 2024:02:16 06:40:14+08:00 File Inode Change Date/Time : 2024:09:04 00:24:48+08:00 File Permissions : -rw-r--r-- File Type : JPEG File Type Extension : jpg MIME Type : image/jpeg JFIF Version : 1.01 Resolution Unit : inches X Resolution : 72 Y Resolution : 72 XMP Toolkit : Image::ExifTool 11.88 Attribution URL : cGljb0NURntNRTc0RDQ3QV9ISUREM05fZGVjYTA2ZmJ9Cg== Image Width : 4308 Image Height : 2875 Encoding Process : Baseline DCT, Huffman coding Bits Per Sample : 8 Color Components : 3 Y Cb Cr Sub Sampling : YCbCr4:2:0 (2 2) Image Size : 4308x2875 Megapixels : 12.4 ~/CTF/picoCTF2024/forensic/CanYouSee 00:25:01 \> base64 -d "cGljb0NURntNRTc0RDQ3QV9ISUREM05fZGVjYTA2ZmJ9Cg==" base64: 'cGljb0NURntNRTc0RDQ3QV9ISUREM05fZGVjYTA2ZmJ9Cg==': No such file or directory ~/CTF/picoCTF2024/forensic/CanYouSee 00:25:17 \> echo "cGljb0NURntNRTc0RDQ3QV9ISUREM05fZGVjYTA2ZmJ9Cg==" \| base64 -d
