---
title: "Modbus TCP 深度解析 (二)：功能碼詳解與實戰範例"
date: 2025-07-02
categories: [工控資安]
tags: [modbus, 工控協議, 功能碼]
slug: "modbus-tcp-series-02-function-codes"
---

## 0x00 前情提要

在[上一集](/posts/modbus-tcp-series-01-basics/)中，我們深入了解了 Modbus TCP 的基本概念和封包結構。今天我們將聚焦於功能碼 (Function Code)，這是 Modbus 協議的核心，決定了每個請求要執行什麼操作。

**上集練習題答案：**

```
Hex: 00 05 00 00 00 06 01 06 00 0A 03 E8

解析：
- Transaction ID: 0x0005 (5)
- 這是一個請求封包
- 功能碼: 0x06 (寫入單個暫存器)
- 目標地址: 0x000A (10)
- 寫入數值: 0x03E8 (1000)
```

## 0x01 功能碼總覽

Modbus TCP 支援多種功能碼，可分為以下幾類：

### 標準功能碼分類

| 類別     | 功能碼範圍 | 說明             |
| -------- | ---------- | ---------------- |
| 讀取功能 | 0x01-0x04  | 讀取各種資料型別 |
| 寫入功能 | 0x05-0x06  | 寫入單一數值     |
| 批次寫入 | 0x0F-0x10  | 批次寫入操作     |
| 診斷功能 | 0x08       | 診斷和測試       |
| 其他功能 | 0x2B       | 設備識別等       |

### 常用功能碼對照表

| 功能碼 | 名稱                     | 資料型別           | 操作類型 |
| ------ | ------------------------ | ------------------ | -------- |
| 0x01   | Read Coils               | 線圈 (1bit)        | 讀取     |
| 0x02   | Read Discrete Inputs     | 離散輸入 (1bit)    | 讀取     |
| 0x03   | Read Holding Registers   | 保持暫存器 (16bit) | 讀取     |
| 0x04   | Read Input Registers     | 輸入暫存器 (16bit) | 讀取     |
| 0x05   | Write Single Coil        | 線圈 (1bit)        | 寫入     |
| 0x06   | Write Single Register    | 保持暫存器 (16bit) | 寫入     |
| 0x0F   | Write Multiple Coils     | 線圈 (1bit)        | 批次寫入 |
| 0x10   | Write Multiple Registers | 保持暫存器 (16bit) | 批次寫入 |

## 0x02 讀取功能碼詳解

### 0x01 - Read Coils (讀取線圈)

線圈是 1 位元的離散輸出，通常用於控制開關、閥門、指示燈等。

**請求格式：**

```
功能碼 (1) + 起始地址 (2) + 數量 (2) = 5 bytes
```

**範例：讀取從地址 0x0000 開始的 8 個線圈**

```
請求: 00 01 00 00 00 06 01 01 00 00 00 08

解析：
┌─────────────── MBAP Header ──────────────┬─────── PDU ────────┐
│ TID  │ PID  │ Len  │ UID │ FC │ Addr │ Qty │
│ 0001 │ 0000 │ 0006 │ 01  │ 01 │ 0000 │ 08  │
└──────┴──────┴──────┴─────┴────┴──────┴─────┘
```

**回應：假設線圈狀態為 10110100 (從右到左)**

```
回應: 00 01 00 00 00 04 01 01 01 2D

解析：
- Byte Count: 0x01 (1 byte，因為 8 個線圈需要 1 個位元組)
- Data: 0x2D (二進位: 00101101)

線圈狀態對應：
位置: 7 6 5 4 3 2 1 0
狀態: 0 0 1 0 1 1 0 1
地址: - - - - 3 2 1 0  (只有前 8 個線圈有效)
```

### 0x03 - Read Holding Registers (讀取保持暫存器)

保持暫存器是 16 位元的讀寫暫存器，用於儲存數值資料。

**範例：讀取溫度和壓力資料**

```
請求: 00 02 00 00 00 06 01 03 00 64 00 02

解析：
- Transaction ID: 0x0002
- 功能碼: 0x03 (讀取保持暫存器)
- 起始地址: 0x0064 (100) - 溫度暫存器
- 數量: 0x0002 (2 個暫存器) - 溫度和壓力

回應: 00 02 00 00 00 07 01 03 04 00 FA 01 90

解析：
- Byte Count: 0x04 (4 bytes = 2 registers × 2 bytes)
- Register 100: 0x00FA = 250 (25.0°C)
- Register 101: 0x0190 = 400 (4.00 bar)
```

### 0x04 - Read Input Registers (讀取輸入暫存器)

輸入暫存器是唯讀的 16 位元暫存器，通常用於感測器資料。

**範例：讀取多個感測器數值**

```
請求: 00 03 00 00 00 06 01 04 00 00 00 04

回應: 00 03 00 00 00 0B 01 04 08 01 2C 02 58 03 84 04 B0

解析：
- 8 bytes 資料 = 4 個輸入暫存器
- Register 0: 0x012C = 300 (光度感測器)
- Register 1: 0x0258 = 600 (濕度感測器)
- Register 2: 0x0384 = 900 (壓力感測器)
- Register 3: 0x04B0 = 1200 (流量感測器)
```

## 0x03 寫入功能碼詳解

### 0x05 - Write Single Coil (寫入單個線圈)

用於控制單一的數位輸出。

**特殊值說明：**

- `0xFF00`: 設定線圈為 ON
- `0x0000`: 設定線圈為 OFF

**範例：開啟警報燈**

```
請求: 00 04 00 00 00 06 01 05 00 0A FF 00

解析：
- Transaction ID: 0x0004
- 功能碼: 0x05 (寫入單個線圈)
- 線圈地址: 0x000A (10) - 警報燈控制
- 數值: 0xFF00 (開啟)

正常回應: 00 04 00 00 00 06 01 05 00 0A FF 00
(回應與請求相同，表示操作成功)
```

### 0x06 - Write Single Register (寫入單個暫存器)

用於設定單一的數值參數。

**範例：設定溫度設定點**

```
請求: 00 05 00 00 00 06 01 06 00 C8 00 DC

解析：
- Transaction ID: 0x0005
- 功能碼: 0x06 (寫入單個暫存器)
- 暫存器地址: 0x00C8 (200) - 溫度設定點
- 數值: 0x00DC = 220 (22.0°C)

正常回應: 00 05 00 00 00 06 01 06 00 C8 00 DC
```

## 0x04 批次操作功能碼

### 0x0F - Write Multiple Coils (批次寫入線圈)

一次設定多個線圈狀態，提高效率。

**範例：設定 8 個輸出線圈**

```
請求: 00 06 00 00 00 08 01 0F 00 00 00 08 01 A5

解析：
- 功能碼: 0x0F (批次寫入線圈)
- 起始地址: 0x0000
- 數量: 0x0008 (8 個線圈)
- Byte Count: 0x01 (1 個位元組的資料)
- Data: 0xA5 (二進位: 10100101)

線圈設定：
位置: 7 6 5 4 3 2 1 0
狀態: 1 0 1 0 0 1 0 1
地址: - - - - 3 2 1 0

回應: 00 06 00 00 00 06 01 0F 00 00 00 08
(確認寫入了 8 個線圈)
```

### 0x10 - Write Multiple Registers (批次寫入暫存器)

一次設定多個暫存器數值。

**範例：設定生產參數**

```
請求: 00 07 00 00 00 0D 01 10 00 64 00 03 06 01 2C 02 58 03 84

解析：
- 功能碼: 0x10 (批次寫入暫存器)
- 起始地址: 0x0064 (100)
- 數量: 0x0003 (3 個暫存器)
- Byte Count: 0x06 (6 bytes = 3 registers × 2 bytes)
- Register 100: 0x012C = 300 (速度設定)
- Register 101: 0x0258 = 600 (溫度設定)
- Register 102: 0x0384 = 900 (壓力設定)

回應: 00 07 00 00 00 06 01 10 00 64 00 03
```

## 0x05 實用程式碼範例

### Python 實作範例

```python
import struct
import socket

class ModbusTCPClient:
    def __init__(self, host, port=502):
        self.host = host
        self.port = port
        self.sock = None
        self.transaction_id = 1

    def connect(self):
        """建立 TCP 連線"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5)  # 5 秒超時
        self.sock.connect((self.host, self.port))

    def _build_mbap_header(self, length, unit_id=1):
        """建立 MBAP Header"""
        tid = self.transaction_id
        self.transaction_id = (self.transaction_id + 1) % 65536

        return struct.pack('>HHHB',
                          tid,      # Transaction ID
                          0,        # Protocol ID
                          length,   # Length
                          unit_id)  # Unit ID

    def read_holding_registers(self, address, count, unit_id=1):
        """讀取保持暫存器"""
        # PDU: Function Code (1) + Address (2) + Count (2)
        pdu = struct.pack('>BHH', 0x03, address, count)

        # MBAP Header: Unit ID (1) + PDU length
        mbap = self._build_mbap_header(len(pdu) + 1, unit_id)

        # 發送請求
        request = mbap + pdu
        self.sock.send(request)

        # 接收回應
        response = self.sock.recv(1024)

        # 解析回應
        if len(response) < 9:  # 最小回應長度
            raise Exception("回應太短")

        # 解析 MBAP Header
        tid, pid, length, uid = struct.unpack('>HHHB', response[:7])

        # 解析 PDU
        func_code = response[7]
        if func_code == 0x03:
            byte_count = response[8]
            data = response[9:9+byte_count]

            # 解析暫存器資料
            registers = []
            for i in range(0, byte_count, 2):
                reg_value = struct.unpack('>H', data[i:i+2])[0]
                registers.append(reg_value)

            return registers
        else:
            raise Exception(f"非預期的功能碼: {func_code}")

    def write_single_register(self, address, value, unit_id=1):
        """寫入單個暫存器"""
        # PDU: Function Code (1) + Address (2) + Value (2)
        pdu = struct.pack('>BHH', 0x06, address, value)

        # MBAP Header
        mbap = self._build_mbap_header(len(pdu) + 1, unit_id)

        # 發送請求
        request = mbap + pdu
        self.sock.send(request)

        # 接收回應
        response = self.sock.recv(1024)

        # 驗證回應
        if response[7] == 0x06:
            return True
        else:
            raise Exception("寫入失敗")

    def close(self):
        """關閉連線"""
        if self.sock:
            self.sock.close()

# 使用範例
def main():
    client = ModbusTCPClient('192.168.1.100')

    try:
        client.connect()
        print("連線成功")

        # 讀取暫存器
        registers = client.read_holding_registers(0, 5)
        print(f"讀取到的暫存器值: {registers}")

        # 寫入暫存器
        client.write_single_register(10, 1234)
        print("寫入成功")

    except Exception as e:
        print(f"錯誤: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    main()
```

## 0x06 效能最佳化技巧

### 1. 批次操作優化

```python
# 不好的做法：逐一讀取
for i in range(10):
    value = client.read_holding_registers(i, 1)[0]
    process(value)

# 好的做法：批次讀取
values = client.read_holding_registers(0, 10)
for i, value in enumerate(values):
    process(value)
```

### 2. 連線重用

```python
# 保持連線開啟，避免頻繁建立/關閉
class OptimizedModbusClient:
    def __init__(self, host, port=502):
        self.client = ModbusTCPClient(host, port)
        self.client.connect()

    def __enter__(self):
        return self.client

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.close()

# 使用 context manager
with OptimizedModbusClient('192.168.1.100') as client:
    # 多次操作共用同一個連線
    data1 = client.read_holding_registers(0, 10)
    data2 = client.read_holding_registers(20, 5)
    client.write_single_register(30, 500)
```

## 0x07 常見錯誤與除錯

### 1. Transaction ID 不匹配

```python
def verify_transaction_id(request_tid, response):
    response_tid = struct.unpack('>H', response[:2])[0]
    if request_tid != response_tid:
        raise Exception(f"Transaction ID 不匹配: {request_tid} != {response_tid}")
```

### 2. 功能碼驗證

```python
def verify_function_code(expected_fc, response):
    actual_fc = response[7]
    if actual_fc == expected_fc + 0x80:  # 錯誤回應
        exception_code = response[8]
        raise Exception(f"Modbus 異常: {exception_code}")
    elif actual_fc != expected_fc:
        raise Exception(f"功能碼不符: 期望 {expected_fc}, 收到 {actual_fc}")
```

## 0x08 下集預告

在下一集《資料模型與地址空間》中，我們將探討：

- Modbus 四種資料型別的詳細說明
- 地址對應和計算方法
- 不同設備的地址配置策略
- 資料型別轉換技巧

## 0x09 實作練習

**練習 1：** 分析以下封包是什麼操作？

```
00 08 00 00 00 09 01 10 00 32 00 02 04 00 64 00 C8
```

**練習 2：** 如何用批次寫入設定 16 個線圈的狀態為 "1010110011001100"？

**答案將在下一集公布！**

---

_本文為 Modbus TCP 深度解析系列第二篇，歡迎持續關注！_
