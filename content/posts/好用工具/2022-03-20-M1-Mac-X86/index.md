---
title: "M1 Mac 運行x86機器的簡單方法"
date:  2022-03-20
categories: [好用工具]
tags:       [架構]
---
# Lima-VM

是一個可以使用qemu模擬x86的開源軟體且非常輕量

Lima Github Repo

使用brew安裝

``` line-numbers
brew install lima
```

## 撰寫config檔案(yaml格式)

這邊直接上我的配置,新增檔案 ubuntu-22_04.yaml

``` bash
# if using specific environment, add `arch` here to specify the architecture
arch: "x86_64"

# ubuntu-22.04.yaml example from lima official (here is all the same as the official example)
images:
# Try to use release-yyyyMMdd image if available. Note that release-yyyyMMdd will be removed after several months.
- location: "https://cloud-images.ubuntu.com/releases/22.04/release-20221214/ubuntu-22.04-server-cloudimg-amd64.img"
arch: "x86_64"
digest: "sha256:b9a5a216901c34742ffe662b691db114269aaa25c90eb77f3ef4dd4f818e78a3"
- location: "https://cloud-images.ubuntu.com/releases/22.04/release-20221214/ubuntu-22.04-server-cloudimg-arm64.img"
arch: "aarch64"
digest: "sha256:b27163374c834c770e8db023fb21205529cea494257bf5ba866b8b1ae5969164"
# Fallback to the latest release image.
# Hint: run `limactl prune` to invalidate the cache
- location: "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img"
arch: "x86_64"
- location: "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-arm64.img"
arch: "aarch64"

# mount the host's $HOME directory to the guest's /home/ubuntu
# if need writable, add `writable: true` under the mount
mounts:
- location: "~"
- location: "/tmp/lima"
  writable: true
```

## 啟動Lima與配置

``` line-numbers
limactl start ubuntu-22_04.yaml --name ubuntu-22_04-amd64
```

看到 INFO\[xxxx\] READY. Run lima to open the shell 就代表成功了
