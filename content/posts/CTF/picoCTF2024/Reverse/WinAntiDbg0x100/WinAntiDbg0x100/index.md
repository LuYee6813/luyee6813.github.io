---
title: "picoCTF 2024 Reverse - WinAntiDbg0x100"
date:  2024-02-15
categories: [CTF]
tags:       [picoCTF2024]
---
``` line-numbers
 /mnt/c/Users/LuYee6813/OneDrive - gapps.ntust.edu.tw/OneDrive/筆記/blog/LuYee6813.github.io/source/_posts/CTF/picoCTF2024/Reverse/WinAntiDbg0x100/WinAntiDbg0x100
❯ file WinAntiDbg0x100.exe
WinAntiDbg0x100.exe: PE32 executable (console) Intel 80386, for MS Windows
```

發現是PE32-\>所以不用IDA去看-\>改用Ghidra

用Ghidra看function，發現印flag的function在FUN_00401580-\>對應到x32dbg的006C1580

``` line-numbers
undefined4 FUN_00401580(void)

{
  uint uVar1;
  int iVar2;
  BOOL BVar3;
  LPWSTR lpOutputString;
  undefined in_stack_fffffff4;
  
  uVar1 = FUN_00401130();
  if ((uVar1 & 0xff) == 0) {
    FUN_00401060(PTR_s________________________(_)_/_____00405020,in_stack_fffffff4);
    FUN_00401060("### To start the challenge, you\'ll need to first launch this program using a debu gger!\n"
                 ,in_stack_fffffff4);
  }
  else {
    OutputDebugStringW(L"\n");
    OutputDebugStringW(L"\n");
    FUN_004011b0();
    iVar2 = FUN_00401200();
    if (iVar2 == 0) {
      OutputDebugStringW(L"### Error reading the \'config.bin\' file... Challenge aborted.\n");
    }
    else {
      OutputDebugStringW(
                        L"### Level 1: Why did the clever programmer become a gardener? Because they  discovered their talent for growing a \'patch\' of roses!\n"
                        );
      FUN_00401440(7);
      BVar3 = IsDebuggerPresent();
      if (BVar3 == 0) {
        FUN_00401440(0xb);
        FUN_00401530(DAT_00405404);
        lpOutputString = FUN_004013b0(DAT_00405408);
        if (lpOutputString == (LPWSTR)0x0) {
          OutputDebugStringW(L"### Something went wrong...\n");
        }
        else {
          OutputDebugStringW(L"### Good job! Here\'s your flag:\n");
          OutputDebugStringW(L"### ~~~ ");
          OutputDebugStringW(lpOutputString);
          OutputDebugStringW(L"\n");
          OutputDebugStringW(
                            L"### (Note: The flag could become corrupted if the process state is tam pered with in any way.)\n\n"
                            );
          free(lpOutputString);
        }
      }
      else {
        OutputDebugStringW(
                          L"### Oops! The debugger was detected. Try to bypass this check to get the  flag!\n"
                          );
      }
    }
    free(DAT_00405410);
  }
  OutputDebugStringW(L"\n");
  OutputDebugStringW(L"\n");
  return 0;
}
```

然後設斷點在006C1602然後執行



把EAX的值改成0再執行



到日誌畫面就看到flag了



flag:`picoCTF{d3bug_f0r_th3_Win_0x100_17712291}`
