---
title: "Modbus TCP 深度解析 (四)：錯誤處理與異常診斷"
date: 2025-07-04
categories: [工控資安]
tags: [modbus]
slug: "modbus-tcp-series-04-error-handling"
---

## 0x00 前情提要

在[前一集](/posts/modbus-tcp-series-03-data-model/)中，我們學習了 Modbus 的資料模型和地址規劃。今天我們要探討當事情出錯時如何處理，這在實際工業應用中至關重要。

**上集練習題答案：**

**練習 1：馬達控制器地址規劃**

```
資料類型          | Modbus地址 | 功能描述
-----------------|-----------|------------------
Coils            | 00001     | 馬達啟動控制
Coils            | 00002     | 馬達停止控制
Discrete Inputs  | 10001     | 運行狀態回饋
Discrete Inputs  | 10002     | 故障狀態指示
Holding Registers| 40001     | 速度設定點 (RPM)
Holding Registers| 40002     | 加速時間 (秒)
Input Registers  | 30001     | 實際速度 (RPM)
Input Registers  | 30002     | 馬達電流 (0.1A)
```

**練習 2：浮點數陣列轉換**

```python
def floats_to_registers(float_array):
    registers = []
    for f in float_array:
        high, low = ModbusDataConverter.float32_to_registers(f)
        registers.extend([high, low])
    return registers

result = floats_to_registers([123.45, 67.89, -12.34])
# 結果: [0x42F6, 0xE666, 0x4287, 0x1CAC, 0xC145, 0x70A4]
```

## 0x01 Modbus 錯誤處理機制

### 錯誤回應的基本結構

當 Modbus 伺服器遇到錯誤時，會返回特殊的錯誤封包：

```
正常回應: [MBAP Header] + [Function Code] + [Data]
錯誤回應: [MBAP Header] + [Error Function Code] + [Exception Code]
```

**錯誤功能碼計算：**

```
Error Function Code = Original Function Code + 0x80

範例：
- 正常讀取暫存器: 0x03
- 錯誤回應: 0x83 (0x03 + 0x80)
```

### 錯誤封包範例

**請求無效地址的暫存器：**

```
請求: 00 01 00 00 00 06 01 03 FF FF 00 01
      (讀取地址 65535 的暫存器，超出範圍)

錯誤回應: 00 01 00 00 00 03 01 83 02

解析：
┌────────┬────────┬────────┬────────┬────────┬────────┐
│ 00 01  │ 00 00  │ 00 03  │   01   │   83   │   02   │
└────────┴────────┴────────┴────────┴────────┴────────┘
   Trans    Proto    Length   Unit    Error   Except
    ID       ID                ID     Code    Code

- Transaction ID: 0x0001 (與請求相同)
- Length: 0x0003 (Unit ID + Error Code + Exception Code)
- Error Function Code: 0x83 (0x03 + 0x80)
- Exception Code: 0x02 (Illegal Data Address)
```

## 0x02 異常碼詳細解析

### 標準異常碼對照表

| 異常碼 | 名稱                     | 說明                    | 常見原因               |
| ------ | ------------------------ | ----------------------- | ---------------------- |
| 0x01   | Illegal Function         | 不支援的功能碼          | 使用了設備不支援的功能 |
| 0x02   | Illegal Data Address     | 無效的資料地址          | 地址超出範圍或不存在   |
| 0x03   | Illegal Data Value       | 無效的資料值            | 數值超出允許範圍       |
| 0x04   | Slave Device Failure     | 從屬設備故障            | 硬體故障或內部錯誤     |
| 0x05   | Acknowledge              | 確認 (長時間操作進行中) | 操作需要較長時間完成   |
| 0x06   | Slave Device Busy        | 從屬設備忙碌            | 設備正在處理其他請求   |
| 0x08   | Memory Parity Error      | 記憶體奇偶校驗錯誤      | 記憶體硬體問題         |
| 0x0A   | Gateway Path Unavailable | 閘道路徑不可用          | 網路閘道問題           |
| 0x0B   | Gateway Target Failed    | 閘道目標設備回應失敗    | 目標設備無回應         |

### 異常碼實戰範例

#### 0x01 - Illegal Function

```
場景：嘗試使用設備不支援的診斷功能

請求: 00 02 00 00 00 06 01 08 00 00 A5 37
      (功能碼 0x08 診斷功能，某些設備不支援)

錯誤回應: 00 02 00 00 00 03 01 88 01
```

#### 0x02 - Illegal Data Address

```python
# 常見錯誤案例
def demonstrate_address_errors():
    client = ModbusTCPClient('192.168.1.100')

    try:
        # 錯誤 1: 地址超出範圍
        client.read_holding_registers(70000, 1)  # 地址太大

    except ModbusException as e:
        print(f"地址錯誤: {e.exception_code}")  # 0x02

    try:
        # 錯誤 2: 讀取不存在的地址
        client.read_holding_registers(45000, 1)  # 設備沒有這個地址

    except ModbusException as e:
        print(f"地址不存在: {e.exception_code}")  # 0x02
```

#### 0x03 - Illegal Data Value

```
場景：寫入超出範圍的數值

請求: 00 03 00 00 00 06 01 06 00 64 FF FF
      (嘗試寫入 65535 到溫度設定點，超出 0-1000 的範圍)

錯誤回應: 00 03 00 00 00 03 01 86 03
```

#### 0x04 - Slave Device Failure

```
場景：設備內部故障

請求: 00 04 00 00 00 06 01 03 00 00 00 0A

錯誤回應: 00 04 00 00 00 03 01 83 04

可能原因：
- 感測器故障
- 類比輸入模組故障
- 設備過熱保護
- 電源供應問題
```

## 0x03 錯誤處理實作策略

### 完整的錯誤處理類別

```python
import time
import logging
from enum import Enum

class ModbusExceptionCode(Enum):
    ILLEGAL_FUNCTION = 0x01
    ILLEGAL_DATA_ADDRESS = 0x02
    ILLEGAL_DATA_VALUE = 0x03
    SLAVE_DEVICE_FAILURE = 0x04
    ACKNOWLEDGE = 0x05
    SLAVE_DEVICE_BUSY = 0x06
    MEMORY_PARITY_ERROR = 0x08
    GATEWAY_PATH_UNAVAILABLE = 0x0A
    GATEWAY_TARGET_FAILED = 0x0B

class ModbusClientWithRetry:
    def __init__(self, host, port=502, max_retries=3, retry_delay=1.0):
        self.host = host
        self.port = port
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.client = None
        self.logger = logging.getLogger(__name__)

    def connect(self):
        """建立連線，支援重試"""
        for attempt in range(self.max_retries):
            try:
                self.client = ModbusTCPClient(self.host, self.port)
                self.client.connect()
                self.logger.info(f"連線成功到 {self.host}:{self.port}")
                return True

            except Exception as e:
                self.logger.warning(f"連線嘗試 {attempt + 1} 失敗: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                else:
                    self.logger.error("所有連線嘗試均失敗")
                    return False

    def _execute_with_retry(self, operation, *args, **kwargs):
        """執行操作並處理重試邏輯"""
        last_exception = None

        for attempt in range(self.max_retries):
            try:
                return operation(*args, **kwargs)

            except ModbusException as e:
                last_exception = e
                self.logger.warning(f"Modbus 異常 (嘗試 {attempt + 1}): "
                                   f"功能碼 {e.function_code}, "
                                   f"異常碼 {e.exception_code}")

                # 根據異常碼決定是否重試
                if e.exception_code in [
                    ModbusExceptionCode.SLAVE_DEVICE_BUSY.value,
                    ModbusExceptionCode.ACKNOWLEDGE.value
                ]:
                    # 這些錯誤可以重試
                    if attempt < self.max_retries - 1:
                        self.logger.info(f"等待 {self.retry_delay} 秒後重試...")
                        time.sleep(self.retry_delay)
                        continue
                else:
                    # 其他錯誤不應重試
                    self.logger.error(f"不可重試的錯誤: {e.exception_code}")
                    break

            except Exception as e:
                last_exception = e
                self.logger.warning(f"通訊錯誤 (嘗試 {attempt + 1}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)

        # 所有重試都失敗
        raise last_exception

    def read_holding_registers_safe(self, address, count, unit_id=1):
        """安全的讀取保持暫存器"""
        return self._execute_with_retry(
            self.client.read_holding_registers,
            address, count, unit_id
        )

    def write_single_register_safe(self, address, value, unit_id=1):
        """安全的寫入單個暫存器"""
        return self._execute_with_retry(
            self.client.write_single_register,
            address, value, unit_id
        )

# 使用範例
def robust_data_collection():
    client = ModbusClientWithRetry('192.168.1.100')

    if not client.connect():
        return None

    data = {}

    # 定義要讀取的暫存器
    registers_to_read = {
        'temperature': (40001, 1),
        'pressure': (40002, 1),
        'flow_rate': (40003, 1),
        'level': (40004, 1)
    }

    for name, (address, count) in registers_to_read.items():
        try:
            result = client.read_holding_registers_safe(address, count)
            data[name] = result[0] if result else None
            logging.info(f"成功讀取 {name}: {data[name]}")

        except ModbusException as e:
            logging.error(f"讀取 {name} 失敗: 異常碼 {e.exception_code}")
            data[name] = None

        except Exception as e:
            logging.error(f"讀取 {name} 通訊錯誤: {e}")
            data[name] = None

    return data
```

### 錯誤統計和監控

```python
class ModbusErrorMonitor:
    def __init__(self):
        self.error_counts = {}
        self.last_errors = []
        self.max_history = 100

    def record_error(self, function_code, exception_code, address=None):
        """記錄錯誤統計"""
        error_key = (function_code, exception_code)
        self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1

        error_record = {
            'timestamp': time.time(),
            'function_code': function_code,
            'exception_code': exception_code,
            'address': address
        }

        self.last_errors.append(error_record)
        if len(self.last_errors) > self.max_history:
            self.last_errors.pop(0)

    def get_error_summary(self):
        """取得錯誤摘要報告"""
        total_errors = sum(self.error_counts.values())

        summary = {
            'total_errors': total_errors,
            'error_types': len(self.error_counts),
            'most_common_errors': sorted(
                self.error_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }

        return summary

    def detect_patterns(self):
        """檢測錯誤模式"""
        if len(self.last_errors) < 5:
            return []

        patterns = []

        # 檢測頻繁的地址錯誤
        recent_errors = self.last_errors[-10:]
        address_errors = {}

        for error in recent_errors:
            if error['exception_code'] == 0x02 and error['address']:
                addr = error['address']
                address_errors[addr] = address_errors.get(addr, 0) + 1

        for addr, count in address_errors.items():
            if count >= 3:
                patterns.append({
                    'type': 'frequent_address_error',
                    'address': addr,
                    'count': count,
                    'suggestion': f'檢查地址 {addr} 的配置是否正確'
                })

        return patterns

# 整合錯誤監控的客戶端
class MonitoredModbusClient(ModbusClientWithRetry):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error_monitor = ModbusErrorMonitor()

    def _execute_with_retry(self, operation, *args, **kwargs):
        try:
            return super()._execute_with_retry(operation, *args, **kwargs)
        except ModbusException as e:
            # 記錄錯誤到監控器
            address = kwargs.get('address') or (args[0] if args else None)
            self.error_monitor.record_error(
                e.function_code, e.exception_code, address
            )
            raise

    def get_health_report(self):
        """取得通訊健康報告"""
        summary = self.error_monitor.get_error_summary()
        patterns = self.error_monitor.detect_patterns()

        return {
            'error_summary': summary,
            'detected_patterns': patterns,
            'recommendations': self._generate_recommendations(summary, patterns)
        }

    def _generate_recommendations(self, summary, patterns):
        """產生改善建議"""
        recommendations = []

        if summary['total_errors'] > 10:
            recommendations.append("錯誤率較高，建議檢查網路連線品質")

        for pattern in patterns:
            recommendations.append(pattern['suggestion'])

        return recommendations
```

## 0x04 診斷功能 (Function Code 0x08)

### 診斷子功能碼

功能碼 0x08 提供了多種診斷功能：

| 子功能碼 | 名稱                         | 說明                    |
| -------- | ---------------------------- | ----------------------- |
| 0x0000   | Return Query Data            | 回傳查詢資料 (迴路測試) |
| 0x0001   | Restart Communications       | 重啟通訊                |
| 0x0002   | Return Diagnostic Register   | 回傳診斷暫存器          |
| 0x0003   | Change ASCII Input Delimiter | 變更 ASCII 分隔符       |
| 0x0004   | Force Listen Only Mode       | 強制進入監聽模式        |

### 迴路測試範例

```python
def modbus_loopback_test(client):
    """Modbus 迴路測試"""
    test_data = 0xA537  # 測試資料

    try:
        # 構建診斷請求
        request = struct.pack('>HHHBBHH',
            1,      # Transaction ID
            0,      # Protocol ID
            6,      # Length
            1,      # Unit ID
            8,      # Function Code (診斷)
            0x0000, # Sub-function (Return Query Data)
            test_data  # Test data
        )

        client.sock.send(request)
        response = client.sock.recv(1024)

        # 解析回應
        if len(response) >= 10:
            response_data = struct.unpack('>H', response[8:10])[0]
            if response_data == test_data:
                print(f"迴路測試成功: {test_data:04X}")
                return True
            else:
                print(f"迴路測試失敗: 送出 {test_data:04X}, 收到 {response_data:04X}")
                return False
        else:
            print("迴路測試失敗: 回應太短")
            return False

    except Exception as e:
        print(f"迴路測試錯誤: {e}")
        return False

# 通訊品質測試
def communication_quality_test(client, test_count=100):
    """通訊品質測試"""
    success_count = 0
    response_times = []

    for i in range(test_count):
        start_time = time.time()

        try:
            # 簡單的讀取測試
            client.read_holding_registers(40001, 1)

            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # ms
            response_times.append(response_time)
            success_count += 1

        except Exception as e:
            print(f"測試 {i+1} 失敗: {e}")

    # 計算統計資料
    if response_times:
        avg_response = sum(response_times) / len(response_times)
        max_response = max(response_times)
        min_response = min(response_times)

        quality_report = {
            'success_rate': (success_count / test_count) * 100,
            'avg_response_time': avg_response,
            'max_response_time': max_response,
            'min_response_time': min_response,
            'total_tests': test_count
        }

        return quality_report
    else:
        return {'success_rate': 0, 'total_tests': test_count}
```

## 0x05 預防性錯誤處理

### 參數驗證

```python
class ModbusValidator:
    @staticmethod
    def validate_address(address, data_type):
        """驗證地址範圍"""
        valid_ranges = {
            'coils': (0, 9998),
            'discrete_inputs': (0, 9998),
            'input_registers': (0, 9998),
            'holding_registers': (0, 9998)
        }

        if data_type not in valid_ranges:
            raise ValueError(f"不支援的資料類型: {data_type}")

        min_addr, max_addr = valid_ranges[data_type]
        if not (min_addr <= address <= max_addr):
            raise ValueError(f"地址 {address} 超出 {data_type} 的範圍 ({min_addr}-{max_addr})")

    @staticmethod
    def validate_register_value(value, min_val=0, max_val=65535):
        """驗證暫存器數值"""
        if not isinstance(value, int):
            raise TypeError("暫存器值必須是整數")

        if not (min_val <= value <= max_val):
            raise ValueError(f"數值 {value} 超出範圍 ({min_val}-{max_val})")

    @staticmethod
    def validate_quantity(quantity, max_quantity=125):
        """驗證讀取數量"""
        if not (1 <= quantity <= max_quantity):
            raise ValueError(f"數量 {quantity} 超出範圍 (1-{max_quantity})")

# 安全的 Modbus 操作
def safe_modbus_operation(client, operation, **kwargs):
    """安全的 Modbus 操作包裝"""
    try:
        # 預驗證
        if operation == 'read_holding_registers':
            ModbusValidator.validate_address(kwargs['address'], 'holding_registers')
            ModbusValidator.validate_quantity(kwargs['count'])

        elif operation == 'write_single_register':
            ModbusValidator.validate_address(kwargs['address'], 'holding_registers')
            ModbusValidator.validate_register_value(kwargs['value'])

        # 執行操作
        method = getattr(client, operation)
        return method(**kwargs)

    except ValueError as e:
        logging.error(f"參數驗證錯誤: {e}")
        raise
    except ModbusException as e:
        logging.error(f"Modbus 錯誤: 功能碼 {e.function_code}, 異常碼 {e.exception_code}")
        raise
    except Exception as e:
        logging.error(f"未預期錯誤: {e}")
        raise
```

## 0x06 下集預告

在下一集《安全威脅與攻擊分析》中，我們將深入探討：

- Modbus TCP 的安全漏洞
- 常見的攻擊手法和技術
- 實際攻擊案例分析
- 攻擊檢測技術

## 0x07 實作練習

**練習 1：** 實作一個錯誤恢復系統，當遇到 "Slave Device Busy" 錯誤時，自動等待並重試。

**練習 2：** 設計一個通訊健康度監控儀表板，顯示錯誤率、回應時間等指標。

**練習 3：** 分析以下錯誤封包，判斷問題所在：

```
00 05 00 00 00 03 01 86 03
```

**答案將在下一集公布！**

---

_本文為 Modbus TCP 深度解析系列第四篇，下集將進入安全領域的深度分析！_
