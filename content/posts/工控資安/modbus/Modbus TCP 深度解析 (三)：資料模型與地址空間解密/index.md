---
title: "Modbus TCP 深度解析 (三)：資料模型與地址空間解密"
date: 2025-07-03
categories: [工控資安]
tags: [modbus]
slug: "modbus-tcp-series-03-data-model"
---

## 0x00 前情提要

在[前兩集](/posts/modbus-tcp-series-02-function-codes/)中，我們學習了 Modbus TCP 的基礎知識和功能碼。今天我們要深入探討 Modbus 的資料模型，這是理解工控系統資料組織的關鍵。

**上集練習題答案：**

**練習 1：**

```
00 08 00 00 00 09 01 10 00 32 00 02 04 00 64 00 C8

解析：
- 功能碼: 0x10 (批次寫入暫存器)
- 起始地址: 0x0032 (50)
- 數量: 0x0002 (2 個暫存器)
- 資料: Register 50 = 0x0064 (100), Register 51 = 0x00C8 (200)
```

**練習 2：**

```
設定線圈狀態為 "1010110011001100" (16 bits)
資料位元組: 0xCC, 0xAC (小端序排列)

請求封包:
00 09 00 00 00 08 01 0F 00 00 00 10 02 CC AC
```

## 0x01 Modbus 資料模型概述

Modbus 定義了四種不同的資料區域，每種都有特定的用途和特性：

```
┌─────────────────────────────────────────────────────────┐
│                    Modbus 資料模型                        │
├─────────────────┬─────────────┬─────────────┬─────────────┤
│      Coils      │  Discrete   │   Input     │  Holding    │
│    (線圈)       │   Inputs    │ Registers   │ Registers   │
│                 │  (離散輸入)  │ (輸入暫存器) │ (保持暫存器) │
├─────────────────┼─────────────┼─────────────┼─────────────┤
│    1 bit        │   1 bit     │   16 bit    │   16 bit    │
│    讀/寫        │   唯讀      │   唯讀      │   讀/寫     │
│  數位輸出控制    │  數位輸入狀態│  類比輸入值  │  配置參數   │
└─────────────────┴─────────────┴─────────────┴─────────────┘
```

### 資料型別詳細說明

| 資料類型          | 地址範圍    | 存取權限 | 資料大小 | 典型應用               |
| ----------------- | ----------- | -------- | -------- | ---------------------- |
| Coils             | 00001-09999 | 讀/寫    | 1 bit    | 馬達開關、閥門控制     |
| Discrete Inputs   | 10001-19999 | 唯讀     | 1 bit    | 限位開關、故障指示     |
| Input Registers   | 30001-39999 | 唯讀     | 16 bit   | 溫度、壓力、流量感測器 |
| Holding Registers | 40001-49999 | 讀/寫    | 16 bit   | 設定點、配置參數       |

## 0x02 地址對應規則

### Modbus 地址 vs PDU 地址

Modbus 協議中存在兩套地址系統：

```
Modbus 地址範圍        PDU 地址範圍      資料類型
    (1-based)           (0-based)
┌─────────────────┐   ┌─────────────┐   ┌──────────────┐
│ 00001 - 09999   │ → │ 0x0000-0x?  │   │    Coils     │
│ 10001 - 19999   │ → │ 0x0000-0x?  │   │ Disc. Inputs │
│ 30001 - 39999   │ → │ 0x0000-0x?  │   │ Input Regs   │
│ 40001 - 49999   │ → │ 0x0000-0x?  │   │ Hold. Regs   │
└─────────────────┘   └─────────────┘   └──────────────┘
```

### 地址轉換範例

```python
def modbus_to_pdu_address(modbus_addr, data_type):
    """將 Modbus 地址轉換為 PDU 地址"""
    if data_type == "coils":
        if 1 <= modbus_addr <= 9999:
            return modbus_addr - 1
    elif data_type == "discrete_inputs":
        if 10001 <= modbus_addr <= 19999:
            return modbus_addr - 10001
    elif data_type == "input_registers":
        if 30001 <= modbus_addr <= 39999:
            return modbus_addr - 30001
    elif data_type == "holding_registers":
        if 40001 <= modbus_addr <= 49999:
            return modbus_addr - 40001

    raise ValueError("無效的 Modbus 地址或資料類型")

# 範例
print(modbus_to_pdu_address(40001, "holding_registers"))  # 輸出: 0
print(modbus_to_pdu_address(40100, "holding_registers"))  # 輸出: 99
print(modbus_to_pdu_address(30001, "input_registers"))    # 輸出: 0
```

## 0x03 實際應用中的地址規劃

### 典型的 PLC 地址配置

以下是一個實際工廠自動化系統的地址規劃範例：

#### Coils (線圈) - 數位輸出控制

```
地址範圍  |  功能描述
----------|----------------------------------
00001-00020  | 主馬達控制 (M1-M20)
00021-00040  | 閥門控制 (V1-V20)
00041-00060  | 警報燈控制 (A1-A20)
00061-00080  | 加熱器控制 (H1-H20)
00081-00100  | 風扇控制 (F1-F20)
```

**實際封包範例：開啟主馬達 M5**

```
請求: 00 01 00 00 00 06 01 05 00 04 FF 00

解析:
- 地址 0x0004 = Modbus 地址 00005 (M5)
- 數值 0xFF00 = 開啟
```

#### Discrete Inputs (離散輸入) - 數位輸入狀態

```
地址範圍  |  功能描述
----------|----------------------------------
10001-10020  | 限位開關狀態 (LS1-LS20)
10021-10040  | 壓力開關狀態 (PS1-PS20)
10041-10060  | 溫度開關狀態 (TS1-TS20)
10061-10080  | 安全門狀態 (DS1-DS20)
10081-10100  | 緊急停止按鈕 (ES1-ES20)
```

#### Input Registers (輸入暫存器) - 類比輸入

```
地址範圍  |  功能描述           |  單位/範圍
----------|--------------------|--------------
30001-30010  | 溫度感測器 (T1-T10) | 0.1°C, 0-1000
30011-30020  | 壓力感測器 (P1-P10) | 0.01 bar, 0-100
30021-30030  | 流量感測器 (F1-F10) | 0.1 L/min, 0-1000
30031-30040  | 電壓測量 (V1-V10)   | 0.1V, 0-5000
30041-30050  | 電流測量 (I1-I10)   | 0.1A, 0-200
```

**實際封包範例：讀取溫度感測器 T1-T5**

```
請求: 00 02 00 00 00 06 01 04 00 00 00 05

回應: 00 02 00 00 00 0D 01 04 0A 00 FA 01 04 01 2C 01 68 01 90

解析:
- T1 (30001): 0x00FA = 250 → 25.0°C
- T2 (30002): 0x0104 = 260 → 26.0°C
- T3 (30003): 0x012C = 300 → 30.0°C
- T4 (30004): 0x0168 = 360 → 36.0°C
- T5 (30005): 0x0190 = 400 → 40.0°C
```

#### Holding Registers (保持暫存器) - 配置參數

```
地址範圍  |  功能描述           |  存取類型
----------|--------------------|-----------
40001-40010  | 溫度設定點          | 讀/寫
40011-40020  | 壓力設定點          | 讀/寫
40021-40030  | 速度設定點          | 讀/寫
40031-40040  | PID 控制參數 Kp     | 讀/寫
40041-40050  | PID 控制參數 Ki     | 讀/寫
40051-40060  | PID 控制參數 Kd     | 讀/寫
40061-40070  | 報警設定值          | 讀/寫
40071-40080  | 系統狀態暫存器      | 唯讀
40081-40090  | 錯誤代碼暫存器      | 唯讀
40091-40100  | 設備資訊暫存器      | 唯讀
```

## 0x04 資料型別轉換與處理

### 16-bit 暫存器的資料型別

單個 16-bit 暫存器可以表示多種資料型別：

```python
import struct

class ModbusDataConverter:
    @staticmethod
    def uint16_to_int16(value):
        """無符號 16-bit 轉有符號 16-bit"""
        if value > 32767:
            return value - 65536
        return value

    @staticmethod
    def registers_to_float32(reg_high, reg_low):
        """兩個暫存器組合成 32-bit 浮點數"""
        # 大端序組合
        combined = (reg_high << 16) | reg_low
        # 轉換為浮點數
        return struct.unpack('>f', struct.pack('>I', combined))[0]

    @staticmethod
    def float32_to_registers(value):
        """32-bit 浮點數分解為兩個暫存器"""
        packed = struct.pack('>f', value)
        combined = struct.unpack('>I', packed)[0]
        reg_high = (combined >> 16) & 0xFFFF
        reg_low = combined & 0xFFFF
        return reg_high, reg_low

    @staticmethod
    def registers_to_string(registers):
        """暫存器陣列轉換為字串"""
        bytes_data = b''
        for reg in registers:
            bytes_data += struct.pack('>H', reg)
        return bytes_data.decode('ascii', errors='ignore').rstrip('\x00')

# 使用範例
converter = ModbusDataConverter()

# 溫度資料 (有符號整數)
temp_raw = 65436  # 原始資料
temp_celsius = converter.uint16_to_int16(temp_raw) / 10.0
print(f"溫度: {temp_celsius}°C")  # 輸出: -10.0°C

# 浮點數處理
pressure_float = 123.456
reg_h, reg_l = converter.float32_to_registers(pressure_float)
print(f"壓力暫存器: {reg_h}, {reg_l}")

# 重新組合驗證
pressure_restored = converter.registers_to_float32(reg_h, reg_l)
print(f"還原壓力: {pressure_restored}")

# 字串處理
device_name_regs = [0x4D6F, 0x6462, 0x7573, 0x2050, 0x4C43, 0x0000]
device_name = converter.registers_to_string(device_name_regs)
print(f"設備名稱: {device_name}")  # 輸出: "Modbus PLC"
```

### 位元欄位處理

單個暫存器可以包含多個布林值：

```python
class ModbusBitField:
    def __init__(self, register_value=0):
        self.value = register_value

    def get_bit(self, bit_position):
        """取得指定位元的值"""
        return bool(self.value & (1 << bit_position))

    def set_bit(self, bit_position, bit_value):
        """設定指定位元的值"""
        if bit_value:
            self.value |= (1 << bit_position)
        else:
            self.value &= ~(1 << bit_position)

    def get_bits(self, start_bit, num_bits):
        """取得連續位元的值"""
        mask = (1 << num_bits) - 1
        return (self.value >> start_bit) & mask

    def set_bits(self, start_bit, num_bits, bit_value):
        """設定連續位元的值"""
        mask = (1 << num_bits) - 1
        self.value &= ~(mask << start_bit)
        self.value |= (bit_value & mask) << start_bit

# 範例：設備狀態暫存器
# Bit 0: 運行狀態
# Bit 1: 故障狀態
# Bit 2-4: 操作模式 (0-7)
# Bit 5-7: 速度等級 (0-7)

status_reg = ModbusBitField(0b10110100)  # 180

print(f"運行狀態: {status_reg.get_bit(0)}")      # False
print(f"故障狀態: {status_reg.get_bit(1)}")      # False
print(f"操作模式: {status_reg.get_bits(2, 3)}")   # 5 (101)
print(f"速度等級: {status_reg.get_bits(5, 3)}")   # 5 (101)

# 修改狀態
status_reg.set_bit(0, True)     # 啟動設備
status_reg.set_bits(5, 3, 7)    # 設定最高速度

print(f"新狀態暫存器值: {status_reg.value}")  # 225 (11100001)
```

## 0x05 複雜資料結構處理

### 結構化資料範例

實際應用中，經常需要處理複雜的資料結構：

```python
class RecipeData:
    """食譜資料結構 (佔用 10 個暫存器)"""
    def __init__(self):
        self.recipe_id = 0        # 暫存器 0: 食譜編號
        self.temperature = 0      # 暫存器 1: 溫度設定 (0.1°C)
        self.pressure = 0         # 暫存器 2: 壓力設定 (0.01 bar)
        self.time_minutes = 0     # 暫存器 3: 時間設定 (分鐘)
        self.speed_rpm = 0        # 暫存器 4: 速度設定 (RPM)
        self.flags = 0            # 暫存器 5: 控制旗標
        self.name = ""            # 暫存器 6-9: 食譜名稱 (8 字元)

    def to_registers(self):
        """轉換為暫存器陣列"""
        registers = [
            self.recipe_id,
            self.temperature,
            self.pressure,
            self.time_minutes,
            self.speed_rpm,
            self.flags
        ]

        # 名稱轉換為 4 個暫存器
        name_bytes = self.name.ljust(8, '\x00')[:8].encode('ascii')
        for i in range(0, 8, 2):
            reg_value = (name_bytes[i] << 8) | name_bytes[i+1]
            registers.append(reg_value)

        return registers

    def from_registers(self, registers):
        """從暫存器陣列載入"""
        if len(registers) < 10:
            raise ValueError("暫存器數量不足")

        self.recipe_id = registers[0]
        self.temperature = registers[1]
        self.pressure = registers[2]
        self.time_minutes = registers[3]
        self.speed_rpm = registers[4]
        self.flags = registers[5]

        # 名稱重建
        name_bytes = b''
        for i in range(6, 10):
            name_bytes += struct.pack('>H', registers[i])
        self.name = name_bytes.decode('ascii').rstrip('\x00')

# 使用範例
recipe = RecipeData()
recipe.recipe_id = 42
recipe.temperature = 850  # 85.0°C
recipe.pressure = 250     # 2.50 bar
recipe.time_minutes = 120
recipe.speed_rpm = 1500
recipe.flags = 0b1011     # 各種控制旗標
recipe.name = "Recipe1"

# 寫入到 PLC
registers = recipe.to_registers()
print(f"暫存器資料: {registers}")

# 模擬從 PLC 讀取
loaded_recipe = RecipeData()
loaded_recipe.from_registers(registers)
print(f"載入的食譜: ID={loaded_recipe.recipe_id}, "
      f"名稱={loaded_recipe.name}, 溫度={loaded_recipe.temperature/10}°C")
```

### 批次資料操作

```python
def write_recipe_to_plc(client, recipe, base_address=40100):
    """將食譜寫入 PLC"""
    registers = recipe.to_registers()

    # 使用批次寫入提高效率
    client.write_multiple_registers(base_address, registers)
    print(f"食譜已寫入地址 {base_address}-{base_address+len(registers)-1}")

def read_recipe_from_plc(client, base_address=40100):
    """從 PLC 讀取食譜"""
    registers = client.read_holding_registers(base_address, 10)

    recipe = RecipeData()
    recipe.from_registers(registers)
    return recipe

# 實際使用
try:
    client = ModbusTCPClient('192.168.1.100')
    client.connect()

    # 寫入食譜
    recipe = RecipeData()
    recipe.recipe_id = 1
    recipe.name = "CAKE_MIX"
    recipe.temperature = 1800  # 180.0°C

    write_recipe_to_plc(client, recipe)

    # 讀取驗證
    loaded_recipe = read_recipe_from_plc(client)
    print(f"驗證: {loaded_recipe.name}, {loaded_recipe.temperature/10}°C")

except Exception as e:
    print(f"錯誤: {e}")
finally:
    client.close()
```

## 0x06 地址規劃最佳實務

### 1. 分層地址結構

```
系統層級    |  地址範圍    |  說明
-----------|-------------|------------------------
系統級     |  40001-40100 |  全域系統參數
區域級     |  40101-40500 |  各個區域配置 (100個/區域)
設備級     |  40501-45000 |  個別設備參數 (50個/設備)
維護級     |  45001-49999 |  維護和診斷資料
```

### 2. 命名規範

```python
class ModbusAddressMap:
    """地址對應表管理"""

    # 系統級地址
    SYSTEM_STATUS = 40001
    SYSTEM_MODE = 40002
    SYSTEM_ALARM = 40003

    # 區域 1 (混合區)
    ZONE1_BASE = 40101
    ZONE1_TEMP_SP = 40101
    ZONE1_TEMP_PV = 40102
    ZONE1_PRESSURE_SP = 40103
    ZONE1_PRESSURE_PV = 40104

    # 區域 2 (冷卻區)
    ZONE2_BASE = 40201
    ZONE2_TEMP_SP = 40201
    ZONE2_TEMP_PV = 40202

    @classmethod
    def get_device_base(cls, device_id):
        """取得設備基礎地址"""
        return 40501 + (device_id - 1) * 50

    @classmethod
    def get_device_register(cls, device_id, register_offset):
        """取得設備特定暫存器地址"""
        return cls.get_device_base(device_id) + register_offset

# 使用範例
device_3_temp = ModbusAddressMap.get_device_register(3, 0)  # 設備3溫度
device_3_status = ModbusAddressMap.get_device_register(3, 10)  # 設備3狀態
```

### 3. 文件化工具

```python
def generate_address_documentation(client):
    """自動產生地址文件"""
    doc = []
    doc.append("# Modbus 地址對應表\n")

    # 讀取系統資訊
    try:
        system_regs = client.read_holding_registers(40001, 20)
        doc.append("## 系統暫存器")
        for i, value in enumerate(system_regs):
            addr = 40001 + i
            doc.append(f"- {addr:05d}: {value:5d} (0x{value:04X})")
        doc.append("")

    except Exception as e:
        doc.append(f"讀取錯誤: {e}\n")

    return "\n".join(doc)
```

## 0x07 下集預告

在下一集《錯誤處理與異常診斷》中，我們將學習：

- Modbus 異常碼的詳細解釋
- 錯誤檢測和恢復策略
- 診斷功能的使用方法
- 通訊品質監控技巧

## 0x08 實作練習

**練習 1：** 設計一個馬達控制器的地址規劃，包含：

- 啟動/停止控制 (線圈)
- 速度設定點 (保持暫存器)
- 實際速度 (輸入暫存器)
- 故障狀態 (離散輸入)

**練習 2：** 實作一個函數，將浮點數陣列 [123.45, 67.89, -12.34] 轉換為 Modbus 暫存器格式。

**答案將在下一集公布！**

---

_本文為 Modbus TCP 深度解析系列第三篇，下集將探討錯誤處理與診斷技術！_
