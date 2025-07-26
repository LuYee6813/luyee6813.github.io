---
title: "Modbus TCP 深度解析 (六)：防護策略與安全最佳實務"
date: 2025-07-06
categories: [工控資安]
tags: [modbus]
slug: "modbus-tcp-series-06-security-defense"
---

## 0x00 系列總結與防護概述

歡迎來到 Modbus TCP 深度解析系列的最終篇！在前面五集中，我們從基礎協議學到了攻擊技術，現在是時候學習如何保護我們的工控系統了。

**系列回顧：**

1. [協議基礎與封包結構](../modbus-tcp-series-01-basics/) - 理解 Modbus TCP 基本原理
2. [功能碼詳解與實戰範例](../modbus-tcp-series-02-function-codes/) - 掌握各種操作功能
3. [資料模型與地址空間](../modbus-tcp-series-03-data-model/) - 深入資料組織方式
4. [錯誤處理與異常診斷](../modbus-tcp-series-04-error-handling/) - 學習故障排除技術
5. [安全威脅與攻擊分析](../modbus-tcp-series-05-security-threats/) - 了解潛在威脅

## 0x01 縱深防禦架構

工控系統安全需要多層防護，單一防護措施是不夠的：

```
┌─────────────────────────────────────────────────────────┐
│                   縱深防禦架構                            │
├─────────────────┬───────────────────────────────────────┤
│ 物理層防護      │ 機房門禁、設備鎖定、監控攝影機           │
├─────────────────┼───────────────────────────────────────┤
│ 網路層防護      │ 網路分段、防火牆、VPN、入侵檢測          │
├─────────────────┼───────────────────────────────────────┤
│ 協議層防護      │ 協議白名單、流量分析、異常檢測           │
├─────────────────┼───────────────────────────────────────┤
│ 應用層防護      │ 存取控制、認證機制、稽核日誌             │
├─────────────────┼───────────────────────────────────────┤
│ 資料層防護      │ 備份機制、完整性檢查、加密儲存           │
├─────────────────┼───────────────────────────────────────┤
│ 管理層防護      │ 安全政策、人員訓練、事件回應             │
└─────────────────┴───────────────────────────────────────┘
```

## 0x02 網路層防護策略

### 網路分段與隔離

```python
# 網路分段規劃範例
class NetworkSegmentation:
    def __init__(self):
        self.network_zones = {
            'enterprise': {
                'subnet': '192.168.1.0/24',
                'description': '企業網路',
                'security_level': 'low',
                'allowed_protocols': ['HTTP', 'HTTPS', 'SMTP']
            },
            'dmz': {
                'subnet': '192.168.2.0/24',
                'description': '緩衝區',
                'security_level': 'medium',
                'allowed_protocols': ['HTTP', 'HTTPS']
            },
            'scada': {
                'subnet': '10.0.1.0/24',
                'description': 'SCADA 網路',
                'security_level': 'high',
                'allowed_protocols': ['Modbus', 'DNP3']
            },
            'control': {
                'subnet': '10.0.2.0/24',
                'description': '控制網路',
                'security_level': 'critical',
                'allowed_protocols': ['Modbus', 'EtherNet/IP']
            },
            'safety': {
                'subnet': '10.0.3.0/24',
                'description': '安全系統',
                'security_level': 'critical',
                'allowed_protocols': ['Safety-over-EtherCAT']
            }
        }

    def generate_firewall_rules(self):
        """產生防火牆規則"""
        rules = []

        # 基本原則：拒絕所有，允許必要
        rules.append({
            'action': 'deny',
            'source': 'any',
            'destination': 'any',
            'protocol': 'any',
            'description': '預設拒絕規則'
        })

        # 允許 SCADA 到控制網路的 Modbus 通訊
        rules.append({
            'action': 'allow',
            'source': '10.0.1.0/24',
            'destination': '10.0.2.0/24',
            'protocol': 'tcp',
            'port': 502,
            'description': 'SCADA 到控制網路 Modbus'
        })

        # 允許企業網路到 DMZ 的 HTTP/HTTPS
        rules.append({
            'action': 'allow',
            'source': '192.168.1.0/24',
            'destination': '192.168.2.0/24',
            'protocol': 'tcp',
            'port': [80, 443],
            'description': '企業網路到 DMZ Web 服務'
        })

        # 禁止企業網路直接存取控制網路
        rules.append({
            'action': 'deny',
            'source': '192.168.1.0/24',
            'destination': ['10.0.2.0/24', '10.0.3.0/24'],
            'protocol': 'any',
            'description': '禁止企業網路直接存取控制系統'
        })

        return rules

    def validate_network_access(self, source_ip, dest_ip, port, protocol):
        """驗證網路存取是否符合政策"""
        import ipaddress

        # 判斷來源和目標網路區域
        source_zone = None
        dest_zone = None

        for zone, config in self.network_zones.items():
            network = ipaddress.ip_network(config['subnet'])
            if ipaddress.ip_address(source_ip) in network:
                source_zone = zone
            if ipaddress.ip_address(dest_ip) in network:
                dest_zone = zone

        # 檢查存取規則
        if not source_zone or not dest_zone:
            return False, "未知的網路區域"

        # 安全等級檢查
        security_levels = {
            'low': 1, 'medium': 2, 'high': 3, 'critical': 4
        }

        source_level = security_levels[self.network_zones[source_zone]['security_level']]
        dest_level = security_levels[self.network_zones[dest_zone]['security_level']]

        # 不允許低安全等級存取高安全等級
        if source_level < dest_level:
            return False, f"安全等級不足: {source_zone} -> {dest_zone}"

        # 檢查協議和埠號
        if protocol == 'tcp' and port == 502:  # Modbus
            if dest_zone in ['control', 'scada']:
                return True, "允許 Modbus 通訊"

        return False, "不符合安全政策"

# 使用範例
def implement_network_security():
    net_seg = NetworkSegmentation()

    # 生成防火牆規則
    fw_rules = net_seg.generate_firewall_rules()
    print("防火牆規則:")
    for rule in fw_rules:
        print(f"  {rule['action']}: {rule['source']} -> {rule['destination']} "
              f"({rule.get('protocol', 'any')}:{rule.get('port', 'any')})")

    # 測試存取控制
    test_cases = [
        ('192.168.1.100', '10.0.2.50', 502, 'tcp'),  # 企業到控制
        ('10.0.1.10', '10.0.2.50', 502, 'tcp'),      # SCADA 到控制
        ('10.0.2.30', '10.0.1.20', 502, 'tcp')       # 控制到 SCADA
    ]

    for source, dest, port, protocol in test_cases:
        allowed, reason = net_seg.validate_network_access(source, dest, port, protocol)
        status = "允許" if allowed else "拒絕"
        print(f"{source} -> {dest}:{port} ({protocol}): {status} - {reason}")
```

### 工業防火牆實作

```python
import threading
import queue
import time
from collections import defaultdict

class IndustrialFirewall:
    def __init__(self):
        self.rules = []
        self.connection_table = {}
        self.rate_limits = defaultdict(list)
        self.blocked_ips = set()
        self.whitelist_ips = set()
        self.modbus_states = {}

    def add_rule(self, rule):
        """新增防火牆規則"""
        self.rules.append(rule)

    def add_rate_limit(self, ip, max_requests=10, window_seconds=60):
        """新增速率限制"""
        self.rate_limits[ip] = {
            'max_requests': max_requests,
            'window_seconds': window_seconds,
            'requests': []
        }

    def check_rate_limit(self, ip):
        """檢查速率限制"""
        if ip not in self.rate_limits:
            return True

        limit_config = self.rate_limits[ip]
        now = time.time()

        # 清理過期的請求記錄
        limit_config['requests'] = [
            req_time for req_time in limit_config['requests']
            if now - req_time < limit_config['window_seconds']
        ]

        # 檢查是否超過限制
        if len(limit_config['requests']) >= limit_config['max_requests']:
            return False

        # 記錄新請求
        limit_config['requests'].append(now)
        return True

    def analyze_modbus_packet(self, packet_data):
        """分析 Modbus 封包內容"""
        try:
            if len(packet_data) < 8:
                return False, "封包太短"

            # 解析 MBAP Header
            tid, pid, length, uid = struct.unpack('>HHHB', packet_data[:7])

            # 基本完整性檢查
            if pid != 0:
                return False, "無效的協議 ID"

            if length != len(packet_data) - 6:
                return False, "長度欄位不匹配"

            if len(packet_data) < 8:
                return False, "PDU 太短"

            function_code = packet_data[7]

            # 功能碼白名單檢查
            allowed_functions = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10]
            if function_code not in allowed_functions:
                return False, f"不允許的功能碼: 0x{function_code:02X}"

            # 檢查是否為錯誤回應
            if function_code & 0x80:
                # 這是錯誤回應，允許通過
                return True, "錯誤回應"

            # 特定功能碼的深度檢查
            if function_code in [0x03, 0x04]:  # 讀取暫存器
                if len(packet_data) >= 12:
                    address, quantity = struct.unpack('>HH', packet_data[8:12])

                    # 地址範圍檢查
                    if address > 1000 or quantity > 100:
                        return False, f"讀取範圍超出限制: 地址={address}, 數量={quantity}"

            elif function_code in [0x06]:  # 寫入單個暫存器
                if len(packet_data) >= 12:
                    address, value = struct.unpack('>HH', packet_data[8:12])

                    # 關鍵暫存器保護
                    protected_addresses = [0, 1, 100, 101, 200]
                    if address in protected_addresses:
                        return False, f"嘗試寫入受保護的地址: {address}"

            return True, "封包正常"

        except Exception as e:
            return False, f"封包分析錯誤: {e}"

    def process_packet(self, source_ip, dest_ip, dest_port, packet_data):
        """處理封包"""
        # 1. IP 黑白名單檢查
        if source_ip in self.blocked_ips:
            return False, "IP 在黑名單中"

        if self.whitelist_ips and source_ip not in self.whitelist_ips:
            return False, "IP 不在白名單中"

        # 2. 速率限制檢查
        if not self.check_rate_limit(source_ip):
            self.blocked_ips.add(source_ip)  # 臨時封鎖
            return False, "超過速率限制"

        # 3. 埠號檢查
        if dest_port == 502:  # Modbus TCP
            allowed, reason = self.analyze_modbus_packet(packet_data)
            if not allowed:
                # 記錄攻擊嘗試
                self.log_security_event(source_ip, "modbus_attack", reason)
                return False, f"Modbus 攻擊: {reason}"

        # 4. 狀態檢查（針對 TCP 連線）
        connection_key = f"{source_ip}:{dest_ip}:{dest_port}"

        # 記錄允許的連線
        self.connection_table[connection_key] = {
            'first_seen': time.time(),
            'last_seen': time.time(),
            'packet_count': self.connection_table.get(connection_key, {}).get('packet_count', 0) + 1
        }

        return True, "允許通過"

    def log_security_event(self, source_ip, event_type, details):
        """記錄安全事件"""
        event = {
            'timestamp': time.time(),
            'source_ip': source_ip,
            'event_type': event_type,
            'details': details
        }

        # 這裡可以擴展為寫入日誌檔案或發送到 SIEM
        print(f"安全事件: {event}")

# 入侵檢測系統
class ModbusIDS:
    def __init__(self):
        self.baseline_traffic = {}
        self.anomaly_threshold = 2.0  # 標準差倍數
        self.attack_signatures = self.load_attack_signatures()

    def load_attack_signatures(self):
        """載入攻擊特徵"""
        return {
            'connection_flood': {
                'pattern': 'high_connection_rate',
                'threshold': 50,  # 每分鐘連線數
                'description': '連線洪水攻擊'
            },
            'function_code_scan': {
                'pattern': 'sequential_function_codes',
                'threshold': 5,  # 連續不同功能碼
                'description': '功能碼掃描攻擊'
            },
            'address_scan': {
                'pattern': 'sequential_addresses',
                'threshold': 20,  # 連續地址讀取
                'description': '地址掃描攻擊'
            },
            'malformed_packet': {
                'pattern': 'protocol_violation',
                'threshold': 1,  # 一次就觸發
                'description': '畸形封包攻擊'
            }
        }

    def analyze_traffic_pattern(self, traffic_data):
        """分析流量模式"""
        anomalies = []

        # 分析連線頻率
        connection_rate = len(traffic_data) / 60  # 每分鐘連線數
        if connection_rate > self.attack_signatures['connection_flood']['threshold']:
            anomalies.append({
                'type': 'connection_flood',
                'severity': 'high',
                'value': connection_rate
            })

        # 分析功能碼模式
        function_codes = [packet.get('function_code') for packet in traffic_data if packet.get('function_code')]
        unique_function_codes = len(set(function_codes))

        if unique_function_codes > self.attack_signatures['function_code_scan']['threshold']:
            anomalies.append({
                'type': 'function_code_scan',
                'severity': 'medium',
                'value': unique_function_codes
            })

        return anomalies

    def detect_anomalies(self, current_metrics):
        """異常檢測"""
        anomalies = []

        for metric_name, current_value in current_metrics.items():
            if metric_name in self.baseline_traffic:
                baseline = self.baseline_traffic[metric_name]
                mean = baseline['mean']
                std_dev = baseline['std_dev']

                # 使用標準差檢測異常
                if abs(current_value - mean) > self.anomaly_threshold * std_dev:
                    anomalies.append({
                        'metric': metric_name,
                        'current_value': current_value,
                        'baseline_mean': mean,
                        'deviation': abs(current_value - mean) / std_dev
                    })

        return anomalies
```

## 0x03 應用層安全強化

### Modbus TCP 安全閘道

```python
import ssl
import hashlib
import hmac
import json
from cryptography.fernet import Fernet

class SecureModbusGateway:
    def __init__(self):
        self.authorized_users = {}
        self.session_tokens = {}
        self.audit_log = []
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)

    def generate_api_key(self, username, permissions):
        """產生 API 金鑰"""
        key_data = {
            'username': username,
            'permissions': permissions,
            'created_at': time.time(),
            'expires_at': time.time() + 86400  # 24 小時
        }

        # 生成安全的 API 金鑰
        api_key = hashlib.sha256(
            f"{username}{time.time()}{os.urandom(16).hex()}".encode()
        ).hexdigest()

        self.authorized_users[api_key] = key_data
        return api_key

    def authenticate_request(self, api_key, request_signature, request_data):
        """驗證請求"""
        if api_key not in self.authorized_users:
            return False, "無效的 API 金鑰"

        user_data = self.authorized_users[api_key]

        # 檢查金鑰是否過期
        if time.time() > user_data['expires_at']:
            del self.authorized_users[api_key]
            return False, "API 金鑰已過期"

        # 驗證請求簽名
        expected_signature = hmac.new(
            api_key.encode(),
            request_data.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(request_signature, expected_signature):
            return False, "請求簽名無效"

        return True, user_data

    def authorize_operation(self, user_data, operation):
        """授權檢查"""
        user_permissions = user_data['permissions']

        permission_mapping = {
            'read_coils': 'read',
            'read_discrete_inputs': 'read',
            'read_holding_registers': 'read',
            'read_input_registers': 'read',
            'write_single_coil': 'write',
            'write_single_register': 'write',
            'write_multiple_coils': 'write_bulk',
            'write_multiple_registers': 'write_bulk'
        }

        required_permission = permission_mapping.get(operation)
        if not required_permission:
            return False, f"未知的操作: {operation}"

        if required_permission not in user_permissions:
            return False, f"權限不足: 需要 {required_permission}"

        return True, "授權成功"

    def secure_modbus_request(self, api_key, signature, encrypted_request):
        """安全的 Modbus 請求處理"""
        try:
            # 1. 解密請求
            decrypted_request = self.cipher.decrypt(encrypted_request.encode())
            request_data = json.loads(decrypted_request.decode())

            # 2. 驗證身份
            auth_success, user_data = self.authenticate_request(
                api_key, signature, encrypted_request
            )

            if not auth_success:
                return self.create_error_response("認證失敗", user_data)

            # 3. 授權檢查
            operation = request_data.get('operation')
            auth_success, auth_message = self.authorize_operation(user_data, operation)

            if not auth_success:
                return self.create_error_response("授權失敗", auth_message)

            # 4. 執行 Modbus 操作
            result = self.execute_modbus_operation(request_data)

            # 5. 記錄稽核日誌
            self.log_operation(user_data['username'], operation, request_data, result)

            # 6. 加密回應
            response = {
                'success': True,
                'data': result,
                'timestamp': time.time()
            }

            encrypted_response = self.cipher.encrypt(json.dumps(response).encode())
            return encrypted_response.decode()

        except Exception as e:
            return self.create_error_response("處理錯誤", str(e))

    def execute_modbus_operation(self, request_data):
        """執行 Modbus 操作"""
        operation = request_data['operation']
        params = request_data['parameters']

        # 連線到實際的 Modbus 設備
        client = ModbusTCPClient(params['host'], params.get('port', 502))
        client.connect()

        try:
            if operation == 'read_holding_registers':
                result = client.read_holding_registers(
                    params['address'],
                    params['count']
                )
                return {'registers': result}

            elif operation == 'write_single_register':
                client.write_single_register(
                    params['address'],
                    params['value']
                )
                return {'status': 'success'}

            # 其他操作...

        finally:
            client.close()

    def log_operation(self, username, operation, request_data, result):
        """記錄操作日誌"""
        log_entry = {
            'timestamp': time.time(),
            'username': username,
            'operation': operation,
            'parameters': request_data.get('parameters', {}),
            'success': result.get('success', False),
            'ip_address': request_data.get('client_ip'),
            'user_agent': request_data.get('user_agent')
        }

        self.audit_log.append(log_entry)

        # 可以擴展為寫入資料庫或日誌檔案
        print(f"稽核日誌: {log_entry}")

# 安全配置管理
class SecurityConfiguration:
    def __init__(self):
        self.config = {
            'access_control': {
                'require_authentication': True,
                'session_timeout': 3600,  # 1 小時
                'max_failed_attempts': 3,
                'lockout_duration': 900   # 15 分鐘
            },
            'encryption': {
                'algorithm': 'AES-256',
                'key_rotation_interval': 86400,  # 24 小時
                'require_tls': True
            },
            'audit': {
                'log_all_operations': True,
                'log_failed_attempts': True,
                'retention_days': 90
            },
            'rate_limiting': {
                'requests_per_minute': 60,
                'burst_limit': 10
            }
        }

    def validate_configuration(self):
        """驗證安全配置"""
        issues = []

        # 檢查認證設定
        if not self.config['access_control']['require_authentication']:
            issues.append("建議啟用認證機制")

        if self.config['access_control']['session_timeout'] > 7200:
            issues.append("會話超時時間過長，建議設為 2 小時以內")

        # 檢查加密設定
        if not self.config['encryption']['require_tls']:
            issues.append("建議啟用 TLS 加密")

        # 檢查稽核設定
        if not self.config['audit']['log_all_operations']:
            issues.append("建議記錄所有操作以便稽核")

        return issues

    def generate_security_recommendations(self):
        """產生安全建議"""
        recommendations = []

        recommendations.extend([
            "實施多因素認證 (MFA)",
            "定期更新密碼和 API 金鑰",
            "使用強式加密演算法",
            "實施網路存取控制清單 (ACL)",
            "定期進行安全稽核",
            "建立事件回應程序",
            "進行定期的滲透測試",
            "實施資料備份和恢復程序"
        ])

        return recommendations
```

## 0x04 監控與檢測系統

### 即時監控儀表板

```python
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime, timedelta

class ModbusSecurityDashboard:
    def __init__(self):
        self.metrics = {
            'connection_count': [],
            'request_rate': [],
            'error_rate': [],
            'blocked_ips': [],
            'anomaly_score': []
        }
        self.alerts = []

    def collect_metrics(self, modbus_traffic):
        """收集監控指標"""
        current_time = datetime.now()

        # 連線數量
        active_connections = len(set([
            f"{packet['source_ip']}:{packet['dest_ip']}"
            for packet in modbus_traffic
        ]))
        self.metrics['connection_count'].append({
            'timestamp': current_time,
            'value': active_connections
        })

        # 請求速率 (每分鐘)
        request_rate = len(modbus_traffic) / 60
        self.metrics['request_rate'].append({
            'timestamp': current_time,
            'value': request_rate
        })

        # 錯誤率
        error_packets = [
            packet for packet in modbus_traffic
            if packet.get('function_code', 0) & 0x80
        ]
        error_rate = len(error_packets) / len(modbus_traffic) if modbus_traffic else 0
        self.metrics['error_rate'].append({
            'timestamp': current_time,
            'value': error_rate
        })

        # 檢查異常
        self.check_anomalies()

    def check_anomalies(self):
        """檢查異常並產生警報"""
        # 檢查連線數異常
        if len(self.metrics['connection_count']) > 1:
            current_connections = self.metrics['connection_count'][-1]['value']
            if current_connections > 50:  # 閾值
                self.create_alert('high_connection_count', {
                    'current_value': current_connections,
                    'threshold': 50,
                    'severity': 'medium'
                })

        # 檢查錯誤率異常
        if len(self.metrics['error_rate']) > 1:
            current_error_rate = self.metrics['error_rate'][-1]['value']
            if current_error_rate > 0.1:  # 10% 錯誤率
                self.create_alert('high_error_rate', {
                    'current_value': current_error_rate,
                    'threshold': 0.1,
                    'severity': 'high'
                })

    def create_alert(self, alert_type, details):
        """建立警報"""
        alert = {
            'timestamp': datetime.now(),
            'type': alert_type,
            'details': details,
            'status': 'active'
        }

        self.alerts.append(alert)
        self.send_notification(alert)

    def send_notification(self, alert):
        """發送通知"""
        print(f"🚨 安全警報: {alert['type']}")
        print(f"   時間: {alert['timestamp']}")
        print(f"   詳情: {alert['details']}")
        print(f"   嚴重性: {alert['details']['severity']}")

        # 這裡可以擴展為發送郵件、簡訊或 Slack 通知

    def generate_security_report(self):
        """產生安全報告"""
        report = {
            'report_time': datetime.now(),
            'summary': self.get_summary_stats(),
            'top_threats': self.get_top_threats(),
            'recommendations': self.get_recommendations()
        }

        return report

    def get_summary_stats(self):
        """取得摘要統計"""
        if not self.metrics['request_rate']:
            return {}

        request_rates = [m['value'] for m in self.metrics['request_rate']]
        error_rates = [m['value'] for m in self.metrics['error_rate']]

        return {
            'avg_request_rate': sum(request_rates) / len(request_rates),
            'max_request_rate': max(request_rates),
            'avg_error_rate': sum(error_rates) / len(error_rates),
            'total_alerts': len(self.alerts),
            'active_alerts': len([a for a in self.alerts if a['status'] == 'active'])
        }

    def visualize_metrics(self):
        """視覺化監控指標"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))

        # 連線數趨勢
        if self.metrics['connection_count']:
            timestamps = [m['timestamp'] for m in self.metrics['connection_count']]
            values = [m['value'] for m in self.metrics['connection_count']]

            axes[0, 0].plot(timestamps, values)
            axes[0, 0].set_title('連線數趨勢')
            axes[0, 0].set_ylabel('連線數')

        # 請求速率
        if self.metrics['request_rate']:
            timestamps = [m['timestamp'] for m in self.metrics['request_rate']]
            values = [m['value'] for m in self.metrics['request_rate']]

            axes[0, 1].plot(timestamps, values, color='orange')
            axes[0, 1].set_title('請求速率')
            axes[0, 1].set_ylabel('請求/分鐘')

        # 錯誤率
        if self.metrics['error_rate']:
            timestamps = [m['timestamp'] for m in self.metrics['error_rate']]
            values = [m['value'] for m in self.metrics['error_rate']]

            axes[1, 0].plot(timestamps, values, color='red')
            axes[1, 0].set_title('錯誤率')
            axes[1, 0].set_ylabel('錯誤率')

        # 警報統計
        alert_types = {}
        for alert in self.alerts:
            alert_type = alert['type']
            alert_types[alert_type] = alert_types.get(alert_type, 0) + 1

        if alert_types:
            axes[1, 1].bar(alert_types.keys(), alert_types.values())
            axes[1, 1].set_title('警報類型分布')
            axes[1, 1].set_ylabel('數量')

        plt.tight_layout()
        plt.savefig('modbus_security_dashboard.png', dpi=300, bbox_inches='tight')
        plt.show()

# 威脅情報整合
class ThreatIntelligence:
    def __init__(self):
        self.threat_feeds = {}
        self.ioc_database = {
            'malicious_ips': set(),
            'suspicious_patterns': [],
            'known_vulnerabilities': []
        }

    def update_threat_feeds(self):
        """更新威脅情報"""
        # 這裡可以整合外部威脅情報源
        # 例如：CERT, ICS-CERT, 商業威脅情報服務

        # 模擬威脅情報更新
        new_malicious_ips = [
            '192.168.100.50',  # 已知的攻擊 IP
            '10.0.0.99',       # 另一個惡意 IP
        ]

        self.ioc_database['malicious_ips'].update(new_malicious_ips)

        # 更新攻擊模式
        new_patterns = [
            {
                'name': 'modbus_reconnaissance',
                'pattern': 'sequential_function_code_scan',
                'severity': 'medium'
            },
            {
                'name': 'data_exfiltration',
                'pattern': 'bulk_register_read',
                'severity': 'high'
            }
        ]

        self.ioc_database['suspicious_patterns'].extend(new_patterns)

    def check_indicators(self, ip_address, traffic_pattern):
        """檢查威脅指標"""
        threats_found = []

        # 檢查惡意 IP
        if ip_address in self.ioc_database['malicious_ips']:
            threats_found.append({
                'type': 'malicious_ip',
                'severity': 'high',
                'description': f'已知惡意 IP: {ip_address}'
            })

        # 檢查攻擊模式
        for pattern in self.ioc_database['suspicious_patterns']:
            if self.match_pattern(traffic_pattern, pattern['pattern']):
                threats_found.append({
                    'type': 'suspicious_pattern',
                    'severity': pattern['severity'],
                    'description': f'檢測到可疑模式: {pattern["name"]}'
                })

        return threats_found

    def match_pattern(self, traffic_pattern, threat_pattern):
        """模式匹配邏輯"""
        # 簡化的模式匹配，實際應用會更複雜
        if threat_pattern == 'sequential_function_code_scan':
            # 檢查是否有連續的功能碼掃描
            function_codes = traffic_pattern.get('function_codes', [])
            return len(set(function_codes)) > 5

        elif threat_pattern == 'bulk_register_read':
            # 檢查是否有大量暫存器讀取
            read_operations = traffic_pattern.get('read_operations', [])
            total_registers = sum(op.get('quantity', 0) for op in read_operations)
            return total_registers > 1000

        return False
```

## 0x05 事件回應與恢復

### 自動化回應系統

```python
class IncidentResponse:
    def __init__(self):
        self.response_playbooks = {
            'malicious_ip': self.block_ip_response,
            'function_code_scan': self.investigation_response,
            'data_manipulation': self.critical_response,
            'dos_attack': self.mitigation_response
        }
        self.incident_queue = queue.Queue()
        self.response_log = []

    def handle_security_incident(self, incident):
        """處理安全事件"""
        incident_id = self.generate_incident_id()

        # 記錄事件
        incident_record = {
            'id': incident_id,
            'timestamp': datetime.now(),
            'type': incident['type'],
            'severity': incident['severity'],
            'details': incident['details'],
            'status': 'investigating'
        }

        self.incident_queue.put(incident_record)

        # 執行自動回應
        if incident['type'] in self.response_playbooks:
            response_result = self.response_playbooks[incident['type']](incident)
            incident_record['auto_response'] = response_result
            incident_record['status'] = 'auto_responded'

        self.response_log.append(incident_record)
        return incident_id

    def block_ip_response(self, incident):
        """封鎖 IP 回應"""
        malicious_ip = incident['details']['source_ip']

        # 自動封鎖 IP
        firewall_rule = {
            'action': 'deny',
            'source': malicious_ip,
            'destination': 'any',
            'protocol': 'any',
            'duration': 3600  # 1 小時
        }

        # 模擬防火牆 API 呼叫
        self.apply_firewall_rule(firewall_rule)

        # 通知管理員
        self.send_notification({
            'type': 'ip_blocked',
            'ip': malicious_ip,
            'reason': incident['details']['reason']
        })

        return {
            'action': 'ip_blocked',
            'target': malicious_ip,
            'success': True
        }

    def investigation_response(self, incident):
        """調查回應"""
        # 收集更多證據
        evidence = self.collect_evidence(incident)

        # 增加監控
        self.enhance_monitoring(incident['details']['source_ip'])

        return {
            'action': 'investigation_initiated',
            'evidence_collected': len(evidence),
            'monitoring_enhanced': True
        }

    def critical_response(self, incident):
        """關鍵回應（資料操縱）"""
        # 立即隔離受影響的設備
        affected_device = incident['details']['target_device']
        self.isolate_device(affected_device)

        # 啟動備用系統
        self.activate_backup_system(affected_device)

        # 通知關鍵人員
        self.notify_critical_staff(incident)

        return {
            'action': 'critical_response',
            'device_isolated': affected_device,
            'backup_activated': True,
            'staff_notified': True
        }

    def generate_incident_report(self, incident_id):
        """產生事件報告"""
        incident = next((i for i in self.response_log if i['id'] == incident_id), None)

        if not incident:
            return None

        report = {
            'incident_id': incident_id,
            'summary': self.generate_incident_summary(incident),
            'timeline': self.generate_timeline(incident),
            'impact_assessment': self.assess_impact(incident),
            'response_actions': incident.get('auto_response', {}),
            'recommendations': self.generate_recommendations(incident)
        }

        return report

    def generate_incident_summary(self, incident):
        """產生事件摘要"""
        return f"""
        事件類型: {incident['type']}
        嚴重程度: {incident['severity']}
        發生時間: {incident['timestamp']}
        狀態: {incident['status']}

        描述: {incident['details'].get('description', '無')}
        來源IP: {incident['details'].get('source_ip', '未知')}
        目標設備: {incident['details'].get('target_device', '未知')}
        """

    def assess_impact(self, incident):
        """評估影響"""
        impact_levels = {
            'malicious_ip': 'medium',
            'function_code_scan': 'low',
            'data_manipulation': 'high',
            'dos_attack': 'high'
        }

        impact_level = impact_levels.get(incident['type'], 'medium')

        return {
            'level': impact_level,
            'affected_systems': incident['details'].get('affected_systems', []),
            'downtime': incident['details'].get('downtime', 0),
            'data_compromised': incident['details'].get('data_compromised', False)
        }

# 備份和恢復系統
class BackupRecoverySystem:
    def __init__(self):
        self.backup_schedule = {
            'full_backup': {'frequency': 'daily', 'time': '02:00'},
            'incremental_backup': {'frequency': 'hourly'},
            'config_backup': {'frequency': 'on_change'}
        }
        self.backup_locations = ['local', 'remote', 'cloud']

    def create_configuration_backup(self, device_ip):
        """建立設備配置備份"""
        try:
            # 連接設備並讀取配置
            client = ModbusTCPClient(device_ip)
            client.connect()

            # 讀取關鍵配置暫存器
            config_data = {}
            config_ranges = [
                (40001, 100),  # 系統參數
                (40101, 50),   # 控制參數
                (40201, 30)    # 安全設定
            ]

            for start_addr, count in config_ranges:
                try:
                    registers = client.read_holding_registers(start_addr, count)
                    config_data[f"range_{start_addr}"] = registers
                except Exception as e:
                    print(f"讀取地址 {start_addr} 失敗: {e}")

            # 儲存備份
            backup_record = {
                'device_ip': device_ip,
                'timestamp': datetime.now(),
                'config_data': config_data,
                'checksum': self.calculate_checksum(config_data)
            }

            self.save_backup(backup_record)
            return True

        except Exception as e:
            print(f"備份建立失敗: {e}")
            return False
        finally:
            client.close()

    def restore_configuration(self, device_ip, backup_timestamp=None):
        """恢復設備配置"""
        # 載入備份
        backup_record = self.load_backup(device_ip, backup_timestamp)

        if not backup_record:
            return False, "找不到備份記錄"

        try:
            client = ModbusTCPClient(device_ip)
            client.connect()

            # 恢復配置
            for range_key, registers in backup_record['config_data'].items():
                start_addr = int(range_key.split('_')[1])

                # 批次寫入暫存器
                for i, value in enumerate(registers):
                    client.write_single_register(start_addr + i, value)

            return True, "配置恢復成功"

        except Exception as e:
            return False, f"配置恢復失敗: {e}"
        finally:
            client.close()

    def calculate_checksum(self, config_data):
        """計算配置校驗和"""
        config_str = json.dumps(config_data, sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()

    def save_backup(self, backup_record):
        """儲存備份記錄"""
        # 這裡可以實作多重備份儲存
        backup_file = f"backup_{backup_record['device_ip']}_{backup_record['timestamp'].strftime('%Y%m%d_%H%M%S')}.json"

        with open(backup_file, 'w') as f:
            json.dump(backup_record, f, default=str, indent=2)

        print(f"備份已儲存: {backup_file}")
```

## 0x06 系列總結與實務建議

### 安全檢查清單

```markdown
# Modbus TCP 安全檢查清單

## 網路安全 ✓

- [ ] 實施網路分段隔離
- [ ] 部署工業防火牆
- [ ] 啟用入侵檢測系統
- [ ] 實施 VPN 或專線連接
- [ ] 定期進行網路掃描

## 設備安全 ✓

- [ ] 更改預設密碼
- [ ] 停用不必要的服務
- [ ] 更新韌體版本
- [ ] 實施存取控制
- [ ] 定期安全稽核

## 通訊安全 ✓

- [ ] 使用 TLS 加密
- [ ] 實施訊息認證
- [ ] 啟用日誌記錄
- [ ] 監控異常流量
- [ ] 實施速率限制

## 操作安全 ✓

- [ ] 建立安全政策
- [ ] 進行人員訓練
- [ ] 實施變更管理
- [ ] 定期備份配置
- [ ] 準備事件回應計畫

## 監控與回應 ✓

- [ ] 部署 SIEM 系統
- [ ] 建立監控儀表板
- [ ] 設定警報機制
- [ ] 建立回應程序
- [ ] 定期演練
```

### 最終建議

1. **分層防護**：不要依賴單一防護措施
2. **持續監控**：實施 24/7 安全監控
3. **定期更新**：保持系統和安全措施的更新
4. **人員培訓**：定期進行安全意識培訓
5. **演練測試**：定期進行安全演練和測試

## 0x07 資源與延伸閱讀

### 相關標準和指引

- IEC 62443: 工業控制系統安全標準
- NIST Cybersecurity Framework
- ISO 27001: 資訊安全管理系統
- NERC CIP: 電力系統網路安全標準

### 實用工具

- Wireshark: 網路封包分析
- Nmap: 網路掃描工具
- ModbusPal: Modbus 模擬器
- Splunk: SIEM 平台

---

**系列完結感謝**

感謝您跟隨完整的 Modbus TCP 深度解析系列！從基礎協議到高級攻防，我們一起探索了工控網路安全的各個面向。

記住：**安全是一個持續的過程，而非終點。**

願這個系列能幫助您建構更安全的工控環境！

_本文為 Modbus TCP 深度解析系列最終篇 - 完結_
