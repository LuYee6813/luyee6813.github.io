---
title: "Modbus TCP 深度解析 (一)：協議基礎與封包結構"
date: 2025-07-01
categories: [工控資安]
tags: [modbus]
slug: "modbus-tcp-series-01-basics"
---

## 0x00 前言

Modbus TCP 作為工業控制系統中最重要的通訊協議之一，在現代工廠自動化、SCADA 系統和物聯網設備中扮演關鍵角色。本系列教學將帶領大家從零開始，深入理解 Modbus TCP 的方方面面。

**系列文章規劃：**

1. **協議基礎與封包結構** ← 本篇
2. 功能碼詳解與實戰範例
3. 資料模型與地址空間
4. 錯誤處理與異常診斷
5. 安全威脅與攻擊分析
6. 防護策略與最佳實務

## 0x01 Modbus TCP 協議概述

### 什麼是 Modbus TCP？

Modbus TCP 是基於乙太網的 Modbus 協議變體，它在傳統的 Modbus 協議基礎上增加了 TCP/IP 網路支援。相比於 Modbus RTU/ASCII，Modbus TCP 具有以下特點：

- **傳輸層**：使用 TCP 協議，預設埠號 502
- **無需校驗**：TCP 本身提供可靠傳輸，無需額外的 CRC 校驗
- **網路化**：支援多個客戶端同時連接
- **更大的資料量**：支援更大的資料封包
- **跨平台**：可在不同作業系統間通訊

### 協議棧結構

```
┌─────────────────────────┐
│    Modbus Application   │  應用層
├─────────────────────────┤
│         TCP             │  傳輸層 (Port 502)
├─────────────────────────┤
│         IP              │  網路層
├─────────────────────────┤
│      Ethernet           │  資料鏈結層
└─────────────────────────┘
```

## 0x02 TCP 連線建立過程

### 三次握手過程

在 Modbus 通訊開始前，首先需要建立 TCP 連線：

```
客戶端                    伺服器 (Port 502)
   |                          |
   |------> SYN ------------->|  (1) 客戶端發起連線請求
   |                          |
   |<--- SYN + ACK ----------|  (2) 伺服器回應並確認
   |                          |
   |------> ACK ------------->|  (3) 客戶端確認連線建立
   |                          |
   |==== TCP 連線建立 ====|
```

### Modbus 會話建立

TCP 連線建立後，就可以開始 Modbus 通訊：

```
客戶端                    伺服器
   |                          |
   |--- Modbus Request ------>|  讀取/寫入請求
   |                          |
   |<-- Modbus Response ------|  回應資料或錯誤
   |                          |
   |--- Modbus Request ------>|  可持續多次請求
   |                          |
   |<-- Modbus Response ------|
```

## 0x03 Modbus TCP 封包結構詳解

### 完整封包格式

Modbus TCP 封包由兩部分組成：

```
+---+---+---+---+---+---+---+---+---+---+---+---+
| MBAP Header (7 bytes)     | PDU (1-253 bytes) |
+---+---+---+---+---+---+---+---+---+---+---+---+
```

- **MBAP Header**：Modbus Application Protocol Header，固定 7 個位元組
- **PDU**：Protocol Data Unit，包含功能碼和資料

### MBAP Header 深度解析

MBAP Header 是 Modbus TCP 的核心，固定為 7 個位元組：

```
+--------+--------+--------+--------+--------+--------+--------+
| Transaction ID | Protocol ID    | Length         | Unit ID|
|   (2 bytes)    |   (2 bytes)    |   (2 bytes)    |(1 byte)|
+--------+--------+--------+--------+--------+--------+--------+
   0-1        2-3        4-5          6
```

#### 欄位詳細說明

| 欄位               | 長度    | 說明                                     | 範例值 |
| ------------------ | ------- | ---------------------------------------- | ------ |
| **Transaction ID** | 2 bytes | 交易識別碼，用於配對請求和回應           | 0x0001 |
| **Protocol ID**    | 2 bytes | 協議識別碼，Modbus TCP 固定為 0x0000     | 0x0000 |
| **Length**         | 2 bytes | 後續位元組數量 (Unit ID + PDU 長度)      | 0x0006 |
| **Unit ID**        | 1 byte  | 單元識別碼，在 TCP 中通常為 0x01 或 0xFF | 0x01   |

#### Transaction ID 的重要性

Transaction ID 是 Modbus TCP 中最重要的欄位之一：

- **請求配對**：每個請求都有唯一的 Transaction ID
- **並發處理**：支援多個同時進行的請求
- **錯誤檢測**：不匹配的 Transaction ID 表示回應錯誤

```
請求:  Transaction ID = 0x0001 → 功能執行
回應:  Transaction ID = 0x0001 ← 對應的結果

請求:  Transaction ID = 0x0002 → 另一個功能
回應:  Transaction ID = 0x0002 ← 對應的結果
```

#### Length 欄位計算

Length 欄位表示從 Unit ID 開始的所有後續位元組數：

```
Length = Unit ID (1 byte) + Function Code (1 byte) + Data (N bytes)

範例：
- Unit ID: 1 byte
- Function Code: 1 byte
- Data: 4 bytes
- Length = 1 + 1 + 4 = 6 bytes
```

### PDU (Protocol Data Unit) 結構

PDU 包含實際的 Modbus 指令和資料：

```
+--------+--------+--------+--------+
|Function|     Data Fields         |
| Code   |                         |
|(1 byte)|    (0-252 bytes)        |
+--------+--------+--------+--------+
```

## 0x04 實際封包範例

讓我們通過一個具體的封包來理解結構：

### 讀取保持暫存器範例

**請求封包** (讀取從地址 0x0000 開始的 2 個保持暫存器)：

```
Hex: 00 01 00 00 00 06 01 03 00 00 00 02

視覺化解析：
┌────────┬────────┬────────┬────────┬────────┬────────┬────────┐
│ 00 01  │ 00 00  │ 00 06  │   01   │   03   │ 00 00  │ 00 02  │
└────────┴────────┴────────┴────────┴────────┴────────┴────────┘
   Trans    Proto    Length   Unit    Func    Start     Qty
    ID       ID                ID     Code    Addr
```

**詳細解析：**

- `00 01`: Transaction ID = 1 (第一個交易)
- `00 00`: Protocol ID = 0 (確認是 Modbus TCP)
- `00 06`: Length = 6 (Unit ID + Function Code + Address + Quantity = 1+1+2+2)
- `01`: Unit ID = 1 (目標設備編號)
- `03`: Function Code = 0x03 (讀取保持暫存器)
- `00 00`: Starting Address = 0 (從地址 0 開始)
- `00 02`: Quantity = 2 (讀取 2 個暫存器)

**回應封包**：

```
Hex: 00 01 00 00 00 07 01 03 04 00 64 00 C8

視覺化解析：
┌────────┬────────┬────────┬────────┬────────┬────────┬────────────────┐
│ 00 01  │ 00 00  │ 00 07  │   01   │   03   │   04   │   00 64 00 C8  │
└────────┴────────┴────────┴────────┴────────┴────────┴────────────────┘
   Trans    Proto    Length   Unit    Func    Byte     Register Data
    ID       ID                ID     Code    Count      (4 bytes)
```

**回應解析：**

- `00 01`: Transaction ID = 1 (對應請求)
- `00 00`: Protocol ID = 0
- `00 07`: Length = 7 (Unit ID + Function Code + Byte Count + Data = 1+1+1+4)
- `01`: Unit ID = 1
- `03`: Function Code = 0x03 (確認是讀取暫存器回應)
- `04`: Byte Count = 4 (2 個暫存器 × 2 bytes each)
- `00 64`: Register 0 = 100 (decimal)
- `00 C8`: Register 1 = 200 (decimal)

## 0x05 常見問題與注意事項

### 1. 位元組序 (Byte Order)

Modbus TCP 使用**大端序** (Big-Endian)：

```
數值 300 (0x012C) 在 Modbus 中表示為：
- 高位元組在前：01
- 低位元組在後：2C
- 完整表示：01 2C
```

### 2. Transaction ID 管理策略

```python
# 簡單遞增策略
transaction_id = 1
def get_next_tid():
    global transaction_id
    tid = transaction_id
    transaction_id = (transaction_id + 1) % 65536  # 避免溢位
    return tid

# 隨機策略
import random
def get_random_tid():
    return random.randint(1, 65535)
```

### 3. 連線超時處理

- **建議超時時間**：5-10 秒
- **重試機制**：最多 3 次重試
- **連線保持**：適用於頻繁通訊的場景

## 0x06 下集預告

在下一集《功能碼詳解與實戰範例》中，我們將深入探討：

- 常用功能碼的詳細說明
- 讀寫操作的實際範例
- 多種資料類型的處理方式
- 批次操作的最佳化技巧

## 0x07 實作練習

嘗試分析以下封包：

```
Hex: 00 05 00 00 00 06 01 06 00 0A 03 E8
```

**練習題：**

1. 這是請求還是回應？
2. Transaction ID 是多少？
3. 使用了什麼功能碼？
4. 目標地址和數值是什麼？

**答案將在下一集公布！**

---

_本文為 Modbus TCP 深度解析系列第一篇，歡迎關注後續文章。如有疑問歡迎交流討論！_
