---
title: "picoCTF 2024 reverse write-up"
date:  2024-01-30
categories: [CTF]
tags:       [picoCTF2024]
---
❯ strings bin \| grep "pico" picoCTF{wELF_d0N3_mate\_

gdb ./bin  
b main  
r  
ni(直到flag跑出來)
