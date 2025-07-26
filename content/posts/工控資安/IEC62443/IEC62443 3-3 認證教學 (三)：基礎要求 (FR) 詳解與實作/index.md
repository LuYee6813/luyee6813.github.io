---
title: "IEC62443-3-3 認證教學 (三)：基礎要求 (FR) 詳解與實作"
date: 2025-07-26
categories: [工控資安]
tags: [IEC62443]
slug: "iec62443-3-3-series-03-foundational-requirements"
---

## 0x00 前言

在[前兩篇](/posts/iec62443-3-3-series-02-security-requirements/)中，我們理解了 IEC 62443-3-3 的需求架構。今天我們要深入每個基礎要求 (FR) 的技術實作細節，並提供實際可操作的實作指南。

## 0x01 FR1：識別與認證控制實作

### FR1.1 人員識別與認證

**核心實作要素：**

```yaml
身份認證系統架構:
  識別層:
    - 唯一使用者 ID
    - 使用者屬性管理
    - 身份生命週期管理

  認證層:
    - 知識因子 (密碼)
    - 持有因子 (智慧卡、token)
    - 生物因子 (指紋、虹膜)

  授權層:
    - 角色型存取控制 (RBAC)
    - 屬性型存取控制 (ABAC)
    - 最小權限原則
```

**實作範例：AD 整合的工控身份認證**

```python
import ldap3
from ldap3 import Server, Connection, ALL
import hashlib
import hmac
import time

class ICSAuthenticationSystem:
    def __init__(self, ad_server, base_dn):
        self.server = Server(ad_server, get_info=ALL)
        self.base_dn = base_dn
        self.failed_attempts = {}
        self.lockout_threshold = 3
        self.lockout_duration = 1800  # 30分鐘

    def authenticate_user(self, username, password, security_level='SL2'):
        """
        根據安全等級進行使用者認證
        """
        # 檢查帳號鎖定狀態
        if self._is_account_locked(username):
            return {
                'success': False,
                'reason': 'ACCOUNT_LOCKED',
                'unlock_time': self.failed_attempts[username]['unlock_time']
            }

        try:
            # AD 認證
            user_dn = f"cn={username},{self.base_dn}"
            conn = Connection(self.server, user_dn, password)

            if not conn.bind():
                self._record_failed_attempt(username)
                return {'success': False, 'reason': 'INVALID_CREDENTIALS'}

            # 取得使用者資訊
            user_info = self._get_user_info(conn, username)

            # 根據安全等級檢查額外要求
            if security_level in ['SL3', 'SL4']:
                if not self._check_mfa_required(user_info):
                    return {'success': False, 'reason': 'MFA_REQUIRED'}

            # 重置失敗計數
            if username in self.failed_attempts:
                del self.failed_attempts[username]

            return {
                'success': True,
                'user_info': user_info,
                'session_token': self._generate_session_token(username)
            }

        except Exception as e:
            self._record_failed_attempt(username)
            return {'success': False, 'reason': 'AUTHENTICATION_ERROR'}

    def _is_account_locked(self, username):
        """檢查帳號是否被鎖定"""
        if username not in self.failed_attempts:
            return False

        attempt_data = self.failed_attempts[username]
        if attempt_data['count'] >= self.lockout_threshold:
            if time.time() < attempt_data['unlock_time']:
                return True
            else:
                # 鎖定時間已過，重置計數
                del self.failed_attempts[username]
                return False
        return False

    def _record_failed_attempt(self, username):
        """記錄失敗嘗試"""
        current_time = time.time()
        if username not in self.failed_attempts:
            self.failed_attempts[username] = {'count': 0, 'first_attempt': current_time}

        self.failed_attempts[username]['count'] += 1
        self.failed_attempts[username]['last_attempt'] = current_time

        if self.failed_attempts[username]['count'] >= self.lockout_threshold:
            self.failed_attempts[username]['unlock_time'] = current_time + self.lockout_duration

    def _generate_session_token(self, username):
        """產生會話令牌"""
        timestamp = str(int(time.time()))
        secret_key = "your_secret_key"  # 實際使用中應從安全存儲取得

        message = f"{username}:{timestamp}"
        signature = hmac.new(
            secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        return f"{message}:{signature}"

# 使用範例
auth_system = ICSAuthenticationSystem(
    ad_server="ldap://domain-controller.company.com",
    base_dn="ou=ICS_Users,dc=company,dc=com"
)

result = auth_system.authenticate_user("operator01", "SecurePass123!", "SL3")
if result['success']:
    print(f"認證成功，會話令牌：{result['session_token']}")
else:
    print(f"認證失敗：{result['reason']}")
```

### FR1.2 軟體程序與設備識別

**設備認證實作：**

```python
import hashlib
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class DeviceAuthentication:
    def __init__(self):
        self.device_registry = {}
        self.device_certificates = {}

    def register_device(self, device_id, device_info, security_level='SL2'):
        """
        註冊設備到系統
        """
        # 產生設備憑證
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048 if security_level in ['SL1', 'SL2'] else 4096
        )

        # 計算設備指紋
        device_fingerprint = self._calculate_device_fingerprint(device_info)

        # 儲存設備資訊
        self.device_registry[device_id] = {
            'device_info': device_info,
            'fingerprint': device_fingerprint,
            'status': 'ACTIVE',
            'security_level': security_level,
            'last_seen': None
        }

        # 儲存憑證
        self.device_certificates[device_id] = {
            'private_key': private_key,
            'public_key': private_key.public_key()
        }

        return {
            'device_id': device_id,
            'fingerprint': device_fingerprint,
            'certificate': self._export_public_key(private_key.public_key())
        }

    def authenticate_device(self, device_id, signature, challenge):
        """
        驗證設備身份
        """
        if device_id not in self.device_registry:
            return {'success': False, 'reason': 'DEVICE_NOT_REGISTERED'}

        if self.device_registry[device_id]['status'] != 'ACTIVE':
            return {'success': False, 'reason': 'DEVICE_INACTIVE'}

        try:
            # 驗證數位簽章
            public_key = self.device_certificates[device_id]['public_key']
            public_key.verify(
                signature,
                challenge.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # 更新最後見面時間
            import time
            self.device_registry[device_id]['last_seen'] = time.time()

            return {
                'success': True,
                'device_info': self.device_registry[device_id]['device_info'],
                'security_level': self.device_registry[device_id]['security_level']
            }

        except Exception as e:
            return {'success': False, 'reason': 'SIGNATURE_VERIFICATION_FAILED'}

    def _calculate_device_fingerprint(self, device_info):
        """計算設備指紋"""
        # 結合多個設備特徵
        fingerprint_data = {
            'mac_address': device_info.get('mac_address'),
            'serial_number': device_info.get('serial_number'),
            'firmware_version': device_info.get('firmware_version'),
            'hardware_model': device_info.get('hardware_model')
        }

        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()
```

## 0x02 FR2：使用控制實作

### 角色型存取控制 (RBAC) 系統

```python
from enum import Enum
from typing import Dict, List, Set
import json

class Permission(Enum):
    READ_HMI = "read_hmi"
    WRITE_HMI = "write_hmi"
    READ_PLC = "read_plc"
    WRITE_PLC = "write_plc"
    SYSTEM_CONFIG = "system_config"
    USER_MANAGEMENT = "user_management"
    EMERGENCY_STOP = "emergency_stop"
    DIAGNOSTIC = "diagnostic"
    REPORT_VIEW = "report_view"
    AUDIT_LOG = "audit_log"

class Role(Enum):
    OPERATOR = "operator"
    ENGINEER = "engineer"
    MAINTENANCE = "maintenance"
    SUPERVISOR = "supervisor"
    ADMIN = "admin"

class RBACSystem:
    def __init__(self):
        # 定義角色權限映射
        self.role_permissions = {
            Role.OPERATOR: {
                Permission.READ_HMI,
                Permission.REPORT_VIEW,
                Permission.EMERGENCY_STOP
            },
            Role.ENGINEER: {
                Permission.READ_HMI,
                Permission.WRITE_HMI,
                Permission.READ_PLC,
                Permission.WRITE_PLC,
                Permission.DIAGNOSTIC,
                Permission.REPORT_VIEW,
                Permission.EMERGENCY_STOP
            },
            Role.MAINTENANCE: {
                Permission.READ_HMI,
                Permission.READ_PLC,
                Permission.DIAGNOSTIC,
                Permission.SYSTEM_CONFIG,
                Permission.REPORT_VIEW,
                Permission.EMERGENCY_STOP
            },
            Role.SUPERVISOR: {
                Permission.READ_HMI,
                Permission.WRITE_HMI,
                Permission.READ_PLC,
                Permission.DIAGNOSTIC,
                Permission.REPORT_VIEW,
                Permission.AUDIT_LOG,
                Permission.EMERGENCY_STOP
            },
            Role.ADMIN: set(Permission)  # 所有權限
        }

        self.user_roles = {}
        self.active_sessions = {}

    def assign_role(self, user_id: str, role: Role):
        """指派角色給使用者"""
        if user_id not in self.user_roles:
            self.user_roles[user_id] = set()
        self.user_roles[user_id].add(role)

    def check_permission(self, user_id: str, permission: Permission,
                        context: Dict = None) -> bool:
        """檢查使用者權限"""
        if user_id not in self.user_roles:
            return False

        # 檢查基本角色權限
        user_permissions = set()
        for role in self.user_roles[user_id]:
            user_permissions.update(self.role_permissions[role])

        if permission not in user_permissions:
            return False

        # 時間基礎存取控制 (TBAC)
        if context and 'time_constraints' in context:
            if not self._check_time_constraints(context['time_constraints']):
                return False

        # 位置基礎存取控制
        if context and 'location_constraints' in context:
            if not self._check_location_constraints(
                user_id, context['location_constraints']
            ):
                return False

        return True

    def _check_time_constraints(self, time_constraints: Dict) -> bool:
        """檢查時間限制"""
        import datetime
        current_time = datetime.datetime.now()

        # 檢查工作時間限制
        if 'working_hours' in time_constraints:
            start_hour = time_constraints['working_hours']['start']
            end_hour = time_constraints['working_hours']['end']
            if not (start_hour <= current_time.hour <= end_hour):
                return False

        # 檢查工作日限制
        if 'working_days' in time_constraints:
            allowed_days = time_constraints['working_days']
            if current_time.weekday() not in allowed_days:
                return False

        return True

    def audit_access_attempt(self, user_id: str, permission: Permission,
                           granted: bool, context: Dict = None):
        """記錄存取嘗試"""
        import time
        audit_record = {
            'timestamp': time.time(),
            'user_id': user_id,
            'permission': permission.value,
            'granted': granted,
            'context': context or {},
            'source_ip': context.get('source_ip') if context else None
        }

        # 這裡應該寫入安全日誌系統
        print(f"AUDIT: {json.dumps(audit_record, indent=2)}")

# 使用範例
rbac = RBACSystem()

# 設定使用者角色
rbac.assign_role("operator01", Role.OPERATOR)
rbac.assign_role("engineer01", Role.ENGINEER)
rbac.assign_role("admin01", Role.ADMIN)

# 檢查權限
context = {
    'time_constraints': {
        'working_hours': {'start': 8, 'end': 18},
        'working_days': [0, 1, 2, 3, 4]  # 週一到週五
    },
    'source_ip': '192.168.1.100'
}

# 操作員嘗試寫入 PLC
can_write_plc = rbac.check_permission(
    "operator01",
    Permission.WRITE_PLC,
    context
)

rbac.audit_access_attempt(
    "operator01",
    Permission.WRITE_PLC,
    can_write_plc,
    context
)

print(f"操作員可以寫入 PLC: {can_write_plc}")  # False
```

## 0x03 FR3：系統完整性實作

### 檔案完整性監控系統

```python
import hashlib
import os
import json
import time
from pathlib import Path

class FileIntegrityMonitor:
    def __init__(self, config_file="fim_config.json"):
        self.config_file = config_file
        self.baseline_file = "baseline.json"
        self.monitored_paths = []
        self.file_hashes = {}
        self.exclusions = []

        self._load_config()

    def _load_config(self):
        """載入監控設定"""
        default_config = {
            "monitored_paths": [
                "/opt/ics/config/",
                "/opt/ics/bin/",
                "/etc/ics/"
            ],
            "exclusions": [
                "*.log",
                "*.tmp",
                "*.swp"
            ],
            "hash_algorithm": "sha256",
            "check_interval": 300  # 5分鐘
        }

        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            config = default_config
            self._save_config(config)

        self.monitored_paths = config["monitored_paths"]
        self.exclusions = config["exclusions"]
        self.hash_algorithm = config["hash_algorithm"]
        self.check_interval = config["check_interval"]

    def create_baseline(self):
        """建立檔案完整性基線"""
        print("建立檔案完整性基線...")
        self.file_hashes = {}

        for path in self.monitored_paths:
            if os.path.isdir(path):
                self._scan_directory(path)
            elif os.path.isfile(path):
                self._calculate_file_hash(path)

        # 儲存基線
        baseline_data = {
            "created_time": time.time(),
            "hash_algorithm": self.hash_algorithm,
            "file_hashes": self.file_hashes
        }

        with open(self.baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=2)

        print(f"基線建立完成，共監控 {len(self.file_hashes)} 個檔案")

    def _scan_directory(self, directory):
        """掃描目錄下所有檔案"""
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if not self._is_excluded(file_path):
                    self._calculate_file_hash(file_path)

    def _calculate_file_hash(self, file_path):
        """計算檔案雜湊值"""
        try:
            hash_func = hashlib.new(self.hash_algorithm)
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_func.update(chunk)

            file_stat = os.stat(file_path)
            self.file_hashes[file_path] = {
                "hash": hash_func.hexdigest(),
                "size": file_stat.st_size,
                "mtime": file_stat.st_mtime,
                "permissions": oct(file_stat.st_mode)[-3:]
            }
        except Exception as e:
            print(f"無法計算 {file_path} 的雜湊值: {e}")

    def check_integrity(self):
        """檢查檔案完整性"""
        try:
            with open(self.baseline_file, 'r') as f:
                baseline = json.load(f)
        except FileNotFoundError:
            print("找不到基線檔案，請先建立基線")
            return []

        violations = []
        baseline_hashes = baseline["file_hashes"]

        # 檢查現有檔案
        current_hashes = {}
        for path in self.monitored_paths:
            if os.path.isdir(path):
                self._scan_directory_for_check(path, current_hashes)
            elif os.path.isfile(path):
                self._calculate_file_hash_for_check(path, current_hashes)

        # 比較變更
        for file_path, baseline_info in baseline_hashes.items():
            if file_path not in current_hashes:
                violations.append({
                    "type": "DELETED",
                    "file": file_path,
                    "timestamp": time.time()
                })
            elif current_hashes[file_path]["hash"] != baseline_info["hash"]:
                violations.append({
                    "type": "MODIFIED",
                    "file": file_path,
                    "old_hash": baseline_info["hash"],
                    "new_hash": current_hashes[file_path]["hash"],
                    "timestamp": time.time()
                })

        # 檢查新增檔案
        for file_path in current_hashes:
            if file_path not in baseline_hashes:
                violations.append({
                    "type": "ADDED",
                    "file": file_path,
                    "hash": current_hashes[file_path]["hash"],
                    "timestamp": time.time()
                })

        return violations

    def _is_excluded(self, file_path):
        """檢查檔案是否在排除清單中"""
        import fnmatch
        for pattern in self.exclusions:
            if fnmatch.fnmatch(file_path, pattern):
                return True
        return False

    def generate_integrity_report(self, violations):
        """產生完整性報告"""
        if not violations:
            print("✓ 檔案完整性檢查通過，未發現異常")
            return

        print(f"⚠ 發現 {len(violations)} 個檔案完整性異常:")
        for violation in violations:
            print(f"  [{violation['type']}] {violation['file']}")
            if violation['type'] == 'MODIFIED':
                print(f"    舊雜湊: {violation['old_hash'][:16]}...")
                print(f"    新雜湊: {violation['new_hash'][:16]}...")

# 使用範例
fim = FileIntegrityMonitor()

# 建立基線
fim.create_baseline()

# 定期檢查完整性
import time
while True:
    violations = fim.check_integrity()
    fim.generate_integrity_report(violations)

    if violations:
        # 觸發告警
        for violation in violations:
            print(f"ALERT: 檔案完整性違規 - {violation}")

    time.sleep(fim.check_interval)
```

## 0x04 FR4：資料機密性實作

### 工控系統加密通訊

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import json

class ICSCommunicationSecurity:
    def __init__(self, security_level='SL2'):
        self.security_level = security_level
        self.encryption_key = None
        self.cipher_suite = None
        self._initialize_encryption()

    def _initialize_encryption(self):
        """根據安全等級初始化加密"""
        if self.security_level in ['SL1']:
            # SL1: 基本加密或無加密
            self.encryption_enabled = False
        elif self.security_level in ['SL2', 'SL3']:
            # SL2/SL3: AES 加密
            self.encryption_enabled = True
            self._setup_aes_encryption()
        elif self.security_level == 'SL4':
            # SL4: 強化加密
            self.encryption_enabled = True
            self._setup_advanced_encryption()

    def _setup_aes_encryption(self):
        """設定 AES 加密"""
        # 產生或載入金鑰
        password = b"your_secure_password"  # 實際環境中應從安全存儲取得
        salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.cipher_suite = Fernet(key)

    def encrypt_message(self, plaintext):
        """加密訊息"""
        if not self.encryption_enabled:
            return plaintext

        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        encrypted_data = self.cipher_suite.encrypt(plaintext)
        return base64.b64encode(encrypted_data).decode()

    def decrypt_message(self, ciphertext):
        """解密訊息"""
        if not self.encryption_enabled:
            return ciphertext

        try:
            encrypted_data = base64.b64decode(ciphertext.encode())
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            return decrypted_data.decode()
        except Exception as e:
            raise ValueError(f"解密失敗: {e}")

    def secure_modbus_communication(self, function_code, address, data):
        """安全的 Modbus 通訊"""
        # 建立 Modbus 訊息
        modbus_message = {
            "function_code": function_code,
            "address": address,
            "data": data,
            "timestamp": time.time()
        }

        # 序列化
        message_json = json.dumps(modbus_message)

        # 加密
        encrypted_message = self.encrypt_message(message_json)

        # 新增完整性檢查
        integrity_hash = hashlib.sha256(encrypted_message.encode()).hexdigest()

        secure_packet = {
            "encrypted_payload": encrypted_message,
            "integrity_hash": integrity_hash,
            "security_level": self.security_level
        }

        return secure_packet

    def verify_and_decrypt_modbus(self, secure_packet):
        """驗證並解密 Modbus 訊息"""
        # 驗證完整性
        calculated_hash = hashlib.sha256(
            secure_packet["encrypted_payload"].encode()
        ).hexdigest()

        if calculated_hash != secure_packet["integrity_hash"]:
            raise ValueError("訊息完整性驗證失敗")

        # 解密
        decrypted_json = self.decrypt_message(secure_packet["encrypted_payload"])
        modbus_message = json.loads(decrypted_json)

        return modbus_message

# 使用範例
import time
import hashlib

comm_security = ICSCommunicationSecurity(security_level='SL3')

# 安全的 Modbus 寫入操作
secure_packet = comm_security.secure_modbus_communication(
    function_code=6,  # Write Single Register
    address=1000,
    data={"value": 150}
)

print("加密封包:", secure_packet)

# 接收端解密
try:
    original_message = comm_security.verify_and_decrypt_modbus(secure_packet)
    print("解密訊息:", original_message)
except ValueError as e:
    print(f"解密失敗: {e}")
```

## 0x05 FR5：限制資料流實作

### 網路分段與存取控制

```python
import ipaddress
from enum import Enum
from typing import Dict, List, Tuple

class Zone(Enum):
    CORPORATE = "corporate"
    DMZ = "dmz"
    CONTROL = "control"
    SAFETY = "safety"
    PROCESS = "process"

class Protocol(Enum):
    MODBUS = 502
    ETHERNET_IP = 44818
    PROFINET = 34962
    OPC_UA = 4840
    HTTP = 80
    HTTPS = 443
    SSH = 22

class NetworkSegmentation:
    def __init__(self):
        # 定義網路區域
        self.zones = {
            Zone.CORPORATE: {
                "networks": ["192.168.10.0/24", "192.168.11.0/24"],
                "description": "企業網路區域"
            },
            Zone.DMZ: {
                "networks": ["192.168.100.0/24"],
                "description": "非軍事化區域"
            },
            Zone.CONTROL: {
                "networks": ["10.1.1.0/24", "10.1.2.0/24"],
                "description": "控制系統區域"
            },
            Zone.SAFETY: {
                "networks": ["10.2.1.0/24"],
                "description": "安全系統區域"
            },
            Zone.PROCESS: {
                "networks": ["10.3.1.0/24", "10.3.2.0/24"],
                "description": "製程系統區域"
            }
        }

        # 定義區域間通訊規則
        self.zone_rules = self._initialize_zone_rules()

    def _initialize_zone_rules(self):
        """初始化區域間通訊規則"""
        return {
            # 企業網路 -> DMZ
            (Zone.CORPORATE, Zone.DMZ): {
                "allowed_protocols": [Protocol.HTTP, Protocol.HTTPS],
                "direction": "outbound",
                "inspection": True
            },
            # DMZ -> 控制系統 (限制性存取)
            (Zone.DMZ, Zone.CONTROL): {
                "allowed_protocols": [Protocol.OPC_UA],
                "direction": "inbound",
                "inspection": True,
                "time_restrictions": {"start": 8, "end": 18}
            },
            # 控制系統內部通訊
            (Zone.CONTROL, Zone.PROCESS): {
                "allowed_protocols": [Protocol.MODBUS, Protocol.ETHERNET_IP],
                "direction": "bidirectional",
                "inspection": False
            },
            # 安全系統隔離
            (Zone.SAFETY, Zone.CONTROL): {
                "allowed_protocols": [],
                "direction": "none",
                "inspection": True
            }
        }

    def check_communication_allowed(self, src_ip: str, dst_ip: str,
                                  protocol: int, timestamp: float = None):
        """檢查通訊是否被允許"""
        src_zone = self._get_zone_by_ip(src_ip)
        dst_zone = self._get_zone_by_ip(dst_ip)

        if not src_zone or not dst_zone:
            return False, "無法確定來源或目標區域"

        # 同區域內通訊通常被允許
        if src_zone == dst_zone:
            return True, f"區域內通訊: {src_zone.value}"

        # 檢查區域間規則
        rule_key = (src_zone, dst_zone)
        if rule_key not in self.zone_rules:
            return False, f"不允許 {src_zone.value} -> {dst_zone.value} 通訊"

        rule = self.zone_rules[rule_key]

        # 檢查協議
        protocol_enum = self._get_protocol_enum(protocol)
        if protocol_enum not in rule["allowed_protocols"]:
            return False, f"協議 {protocol} 不被允許"

        # 檢查方向
        if rule["direction"] == "none":
            return False, "完全禁止通訊"
        elif rule["direction"] == "outbound" and src_zone != Zone.CORPORATE:
            return False, "僅允許企業網路發起連線"
        elif rule["direction"] == "inbound" and dst_zone != Zone.CONTROL:
            return False, "僅允許進入控制系統"

        # 檢查時間限制
        if "time_restrictions" in rule and timestamp:
            import datetime
            dt = datetime.datetime.fromtimestamp(timestamp)
            if not (rule["time_restrictions"]["start"] <= dt.hour <=
                   rule["time_restrictions"]["end"]):
                return False, "不在允許的時間範圍內"

        return True, "通訊被允許"

    def _get_zone_by_ip(self, ip_address: str) -> Zone:
        """根據 IP 地址確定所屬區域"""
        try:
            ip = ipaddress.ip_address(ip_address)
            for zone, info in self.zones.items():
                for network_str in info["networks"]:
                    network = ipaddress.ip_network(network_str)
                    if ip in network:
                        return zone
        except ValueError:
            pass
        return None

    def _get_protocol_enum(self, port: int) -> Protocol:
        """根據埠號取得協議枚舉"""
        for protocol in Protocol:
            if protocol.value == port:
                return protocol
        return None

    def generate_firewall_rules(self):
        """產生防火牆規則"""
        rules = []
        rule_id = 1

        for (src_zone, dst_zone), rule in self.zone_rules.items():
            if rule["direction"] == "none":
                continue

            src_networks = self.zones[src_zone]["networks"]
            dst_networks = self.zones[dst_zone]["networks"]

            for src_net in src_networks:
                for dst_net in dst_networks:
                    for protocol in rule["allowed_protocols"]:
                        firewall_rule = {
                            "id": rule_id,
                            "action": "ALLOW",
                            "src_zone": src_zone.value,
                            "dst_zone": dst_zone.value,
                            "src_network": src_net,
                            "dst_network": dst_net,
                            "protocol": "TCP",
                            "dst_port": protocol.value,
                            "inspection": rule["inspection"]
                        }
                        rules.append(firewall_rule)
                        rule_id += 1

        return rules

# 使用範例
network_seg = NetworkSegmentation()

# 測試通訊檢查
import time
current_time = time.time()

test_cases = [
    ("192.168.10.100", "192.168.100.50", 443),  # 企業 -> DMZ HTTPS
    ("192.168.100.50", "10.1.1.100", 4840),     # DMZ -> 控制 OPC-UA
    ("10.1.1.100", "10.3.1.50", 502),           # 控制 -> 製程 Modbus
    ("10.2.1.100", "10.1.1.100", 502),          # 安全 -> 控制 (應被拒絕)
]

for src, dst, port in test_cases:
    allowed, reason = network_seg.check_communication_allowed(
        src, dst, port, current_time
    )
    status = "✓ 允許" if allowed else "✗ 拒絕"
    print(f"{status}: {src} -> {dst}:{port} ({reason})")

# 產生防火牆規則
firewall_rules = network_seg.generate_firewall_rules()
print(f"\n產生 {len(firewall_rules)} 條防火牆規則")
for rule in firewall_rules[:3]:  # 顯示前3條規則
    print(f"Rule {rule['id']}: {rule['action']} {rule['src_network']} -> "
          f"{rule['dst_network']}:{rule['dst_port']}")
```

## 0x06 實作檢核清單

### FR 實作完成度檢核表

```yaml
FR1 識別與認證控制: ☐ 唯一使用者識別實作
  ☐ 強密碼政策實施
  ☐ 多因子認證 (SL3+)
  ☐ 帳號生命週期管理
  ☐ 設備認證機制
  ☐ 失敗嘗試鎖定
  ☐ 會話管理
  ☐ 身份聯合 (選用)

FR2 使用控制: ☐ 角色型存取控制
  ☐ 最小權限原則
  ☐ 權限分離
  ☐ 時間基礎存取控制
  ☐ 位置基礎存取控制
  ☐ 管理權限監控
  ☐ 權限定期審查
  ☐ 緊急存取程序

FR3 系統完整性: ☐ 檔案完整性監控
  ☐ 設定基線管理
  ☐ 軟體簽章驗證
  ☐ 變更管理流程
  ☐ 系統復原機制
  ☐ 備份驗證
  ☐ 惡意軟體防護
  ☐ 完整性告警

FR4 資料機密性: ☐ 傳輸加密
  ☐ 儲存加密
  ☐ 金鑰管理
  ☐ 資料分類
  ☐ 存取記錄
  ☐ 資料清除
  ☐ 匿名化處理
  ☐ 加密演算法評估

FR5 限制資料流: ☐ 網路分段
  ☐ 防火牆規則
  ☐ 入侵偵測系統
  ☐ 資料外洩防護
  ☐ 通訊協議控制
  ☐ 網路監控
  ☐ 流量分析
  ☐ 異常偵測
```

## 0x07 下一步預告

在下一篇文章中，我們將探討：

- 安全保證需求 (SAR) 的詳細分析
- 認證文件準備與管理
- 第三方評估準備

---

_下一篇：[IEC62443-3-3 認證教學 (四)：安全保證需求 (SAR) 深度解析](/posts/iec62443-3-3-series-04-security-assurance-requirements/)_
