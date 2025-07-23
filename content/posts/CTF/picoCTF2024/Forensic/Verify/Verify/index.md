---
title: "picoCTF 2024 Forensic - Verify"
date:  2024-02-16
categories: [CTF]
tags:       [forensic]
---
\> sha256sum files/\* \| grep "467a10447deb3d4e17634cacc2a68ba6c2bb62a6637dad9145ea673bf0be5e02" 467a10447deb3d4e17634cacc2a68ba6c2bb62a6637dad9145ea673bf0be5e02 files/c6c8b911

使用解密腳本

``` line-numbers
~/CTF/picoCTF2024/forensic/Verify/challenge/home/ctf-player/drop-in                                              23:40:43
> sudo ./decrypt.sh files/c6c8b911
Error: 'files/c6c8b911' is not a valid file. Look inside the 'files' folder with 'ls -R'!
```

看一下解密腳本發現是路徑問題

``` line-numbers
 ~/CTF/picoCTF2024/forensic/Verify/challenge/home/ctf-player/drop-in                                              23:41:54
> cat decrypt.sh

        #!/bin/bash

        # Check if the user provided a file name as an argument
        if [ $# -eq 0 ]; then
            echo "Expected usage: decrypt.sh "
            exit 1
        fi

        # Store the provided filename in a variable
        file_name="$1"

        # Check if the provided argument is a file and not a folder
        if [ ! -f "/home/ctf-player/drop-in/$file_name" ]; then
            echo "Error: '$file_name' is not a valid file. Look inside the 'files' folder with 'ls -R'!"
            exit 1
        fi

        # If there's an error reading the file, print an error message
        if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -salt -in "/home/ctf-player/drop-in/$file_name" -k picoCTF; then
            echo "Error: Failed to decrypt '$file_name'. This flag is fake! Keep looking!"
        fi
        %
```

是可以解決路徑問題，但我懶所以偷來用XD 就解出來了

``` line-numbers
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -salt -in  files/c6c8b911 -k picoCTF
picoCTF{trust_but_verify_c6c8b911}
```

flag: `picoCTF{trust_but_verify_c6c8b911}`
