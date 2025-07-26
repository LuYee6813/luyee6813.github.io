---
title: "IEC62443-3-3 認證教學 (二)：系統安全需求與安全等級"
date: 2025-07-26
categories: [工控資安]
tags: [IEC62443]
slug: "iec62443-3-3-series-02-security-requirements"
---

## 0x00 前言

在[上一篇](/posts/iec62443-3-3-series-01-basics/)中，我們了解了 IEC 62443 的基本概念。今天我們要深入探討系統安全需求的設計原理，以及如何正確選擇和實作安全等級。

## 0x01 系統安全需求架構

### 需求分層設計

IEC 62443-3-3 採用三層需求架構：

```
安全需求層次結構
├── 基礎要求 (Foundational Requirements, FR)
│   ├── 主要安全目標 (7個主要類別)
│   └── 具體技術要求 (每類下有多個子項)
├── 系統要求 (System Requirements, SR)
│   ├── 基於 FR 的具體實作要求
│   └── 針對不同安全等級的差異化要求
└── 增強要求 (Enhancement Requirements, ER)
    ├── 超越基本要求的額外保護
    └── 高安全等級環境的必要措施
```

### 安全等級對應關係

每個安全等級對應不同的需求強度：

| 需求類型          | SL1      | SL2        | SL3      | SL4                 |
| ----------------- | -------- | ---------- | -------- | ------------------- |
| **基礎要求 (FR)** | 基本實作 | 強化實作   | 進階實作 | 最高級實作          |
| **系統要求 (SR)** | 部分適用 | 大部分適用 | 全部適用 | 全部適用 + 額外要求 |
| **增強要求 (ER)** | 不適用   | 選擇性適用 | 部分適用 | 全部適用            |

## 0x02 基礎要求 (FR) 詳細解析

### FR1：識別與認證控制

**目的**：確保只有經過識別和認證的實體能夠存取系統。

```
FR1 識別與認證控制
├── FR1.1 人員識別與認證
│   ├── FR1.1.1 唯一識別
│   ├── FR1.1.2 認證要求
│   └── FR1.1.3 帳號管理
├── FR1.2 軟體程序與設備識別與認證
└── FR1.3 節點識別與認證
```

**各安全等級要求差異：**

| 安全等級 | 認證方式       | 密碼要求            | 帳號管理       |
| -------- | -------------- | ------------------- | -------------- |
| **SL1**  | 單因子認證     | 基本密碼規則        | 手動管理       |
| **SL2**  | 雙因子認證建議 | 強密碼規則          | 自動化帳號管理 |
| **SL3**  | 強制雙因子認證 | 複雜密碼 + 定期更換 | 集中化身份管理 |
| **SL4**  | 多因子認證     | 生物識別 + 硬體金鑰 | 特權帳號監控   |

**實作範例：**

```python
# SL2 等級的密碼政策實作範例
def validate_password_sl2(password):
    """
    SL2 等級密碼驗證規則
    """
    requirements = {
        'min_length': 8,
        'require_uppercase': True,
        'require_lowercase': True,
        'require_digit': True,
        'require_special_char': True,
        'max_repeated_chars': 2
    }

    if len(password) < requirements['min_length']:
        return False, "密碼長度至少8位字元"

    if requirements['require_uppercase'] and not any(c.isupper() for c in password):
        return False, "需包含大寫字母"

    if requirements['require_lowercase'] and not any(c.islower() for c in password):
        return False, "需包含小寫字母"

    # 檢查重複字元
    for i in range(len(password) - requirements['max_repeated_chars']):
        if password[i] == password[i+1] == password[i+2]:
            return False, "不可有連續3個相同字元"

    return True, "密碼符合要求"

# 測試範例
print(validate_password_sl2("SecuRe123!"))  # (True, "密碼符合要求")
print(validate_password_sl2("weak"))        # (False, "密碼長度至少8位字元")
```

### FR2：使用控制

**目的**：限制已認證使用者的系統存取權限。

```
權限控制模型
├── 角色型存取控制 (RBAC)
│   ├── 角色定義
│   ├── 權限指派
│   └── 最小權限原則
├── 強制存取控制 (MAC)
│   ├── 分級標籤
│   └── 存取矩陣
└── 屬性型存取控制 (ABAC)
    ├── 主體屬性
    ├── 資源屬性
    └── 環境屬性
```

**實作範例：工控系統權限矩陣**

| 角色           | HMI 操作 | PLC 程式 | 系統設定 | 報表檢視 | 緊急停止 |
| -------------- | -------- | -------- | -------- | -------- | -------- |
| **操作員**     | ✓ 監控   | ✗        | ✗        | ✓ 基本   | ✓        |
| **工程師**     | ✓ 全部   | ✓ 編輯   | ✗        | ✓ 詳細   | ✓        |
| **維護人員**   | ✓ 診斷   | ✓ 檢視   | ✓ 部分   | ✓ 維護   | ✓        |
| **系統管理員** | ✓ 全部   | ✓ 全部   | ✓ 全部   | ✓ 全部   | ✓        |

### FR3：系統完整性

**目的**：確保系統和資料的完整性不被破壞。

```yaml
完整性保護措施:
  軟體完整性:
    - 數位簽章驗證
    - 檔案雜湊檢查
    - 程式碼簽章

  資料完整性:
    - 資料庫檢查點
    - 資料備份與復原
    - 異動記錄

  設定完整性:
    - 設定檔版本控制
    - 變更管理流程
    - 基線設定監控
```

### FR4：資料機密性

**目的**：保護敏感資訊不被未授權存取。

**加密要求對照表：**

| 安全等級 | 傳輸加密     | 儲存加密     | 金鑰管理       |
| -------- | ------------ | ------------ | -------------- |
| **SL1**  | 選擇性       | 不要求       | 簡單金鑰       |
| **SL2**  | TLS 1.2+     | 敏感資料加密 | 基本金鑰管理   |
| **SL3**  | 強制加密     | 全資料加密   | HSM 金鑰管理   |
| **SL4**  | 量子安全加密 | 硬體加密     | 分散式金鑰管理 |

### FR5：限制資料流

**目的**：控制網路通訊和資料傳輸。

```
網路分段策略
├── 物理分段
│   ├── 獨立網路基礎設施
│   └── 氣隙隔離
├── 邏輯分段
│   ├── VLAN 劃分
│   ├── 防火牆規則
│   └── 網路存取控制 (NAC)
└── 應用層分段
    ├── 代理伺服器
    ├── 應用層閘道
    └── 資料二極體
```

### FR6：及時回應事件

**目的**：偵測、記錄和回應安全事件。

```python
# 工控系統事件監控範例
class ICSEventMonitor:
    def __init__(self, security_level):
        self.security_level = security_level
        self.event_thresholds = self._set_thresholds()

    def _set_thresholds(self):
        """根據安全等級設定事件閾值"""
        thresholds = {
            'SL1': {'login_attempts': 5, 'response_time': 24},
            'SL2': {'login_attempts': 3, 'response_time': 4},
            'SL3': {'login_attempts': 3, 'response_time': 1},
            'SL4': {'login_attempts': 2, 'response_time': 0.5}
        }
        return thresholds.get(self.security_level, thresholds['SL1'])

    def detect_brute_force(self, failed_logins):
        """暴力破解偵測"""
        if failed_logins >= self.event_thresholds['login_attempts']:
            return {
                'event_type': 'BRUTE_FORCE_ATTACK',
                'severity': 'HIGH',
                'response_required': True,
                'max_response_time': self.event_thresholds['response_time']
            }
        return None

    def monitor_plc_communication(self, modbus_traffic):
        """PLC通訊異常監控"""
        suspicious_patterns = [
            'unusual_function_codes',
            'unauthorized_write_operations',
            'abnormal_data_volumes'
        ]

        for pattern in suspicious_patterns:
            if self._check_pattern(modbus_traffic, pattern):
                return self._generate_alert(pattern)

        return None

# 使用範例
monitor = ICSEventMonitor('SL3')
alert = monitor.detect_brute_force(failed_logins=3)
if alert:
    print(f"偵測到安全事件：{alert['event_type']}")
    print(f"需在 {alert['max_response_time']} 小時內回應")
```

### FR7：資源可用性

**目的**：確保系統和服務的持續運作。

```
可用性保護措施
├── 冗餘設計
│   ├── 硬體冗餘 (N+1, 2N)
│   ├── 網路冗餘 (雙路徑)
│   └── 電源冗餘 (UPS, 發電機)
├── 故障恢復
│   ├── 自動故障切換
│   ├── 快速重啟機制
│   └── 資料自動同步
└── 容量管理
    ├── 負載監控
    ├── 資源規劃
    └── 效能調整
```

## 0x03 安全等級選擇方法

### 風險評估矩陣

```
風險評估決策矩陣

威脅等級 vs 影響程度
                 低影響  中影響  高影響  極高影響
低威脅             SL1     SL1     SL2     SL2
中威脅             SL1     SL2     SL2     SL3
高威脅             SL2     SL2     SL3     SL3
極高威脅           SL2     SL3     SL3     SL4
```

### 產業別建議等級

| 產業類型       | 典型安全等級 | 主要考量因素         |
| -------------- | ------------ | -------------------- |
| **石化業**     | SL3-SL4      | 環境安全、生命威脅   |
| **電力業**     | SL3-SL4      | 國家基礎設施         |
| **製造業**     | SL2-SL3      | 生產連續性、商業機密 |
| **水處理**     | SL2-SL3      | 公共衛生、環境保護   |
| **建築自動化** | SL1-SL2      | 舒適性、能源效率     |

### 成本效益分析工具

```python
def calculate_security_investment(current_sl, target_sl, system_value):
    """
    計算安全等級提升的投資建議

    Args:
        current_sl: 目前安全等級 (1-4)
        target_sl: 目標安全等級 (1-4)
        system_value: 系統價值 (萬元)

    Returns:
        投資建議與成本估算
    """

    # 各等級實作成本係數 (相對於系統價值的百分比)
    cost_factors = {
        1: 0.02,  # 2%
        2: 0.05,  # 5%
        3: 0.12,  # 12%
        4: 0.25   # 25%
    }

    # 風險降低效益係數
    risk_reduction = {
        1: 0.3,   # 30% 風險降低
        2: 0.6,   # 60% 風險降低
        3: 0.85,  # 85% 風險降低
        4: 0.95   # 95% 風險降低
    }

    upgrade_cost = (cost_factors[target_sl] - cost_factors[current_sl]) * system_value
    risk_benefit = risk_reduction[target_sl] * system_value * 0.1  # 假設年度風險為系統價值10%

    payback_period = upgrade_cost / risk_benefit if risk_benefit > 0 else float('inf')

    return {
        'upgrade_cost': upgrade_cost,
        'annual_benefit': risk_benefit,
        'payback_years': payback_period,
        'recommendation': 'PROCEED' if payback_period <= 3 else 'RECONSIDER'
    }

# 使用範例
result = calculate_security_investment(
    current_sl=2,
    target_sl=3,
    system_value=1000  # 1000萬元系統
)

print(f"升級成本：{result['upgrade_cost']:.0f} 萬元")
print(f"年度效益：{result['annual_benefit']:.0f} 萬元")
print(f"回收期間：{result['payback_years']:.1f} 年")
print(f"建議：{result['recommendation']}")
```

## 0x04 實作規劃與優先順序

### 分階段實作策略

```
階段式安全提升計畫
├── 第一階段 (0-6個月)：基礎防護
│   ├── 網路分段實作
│   ├── 基本身份認證
│   └── 事件記錄機制
├── 第二階段 (6-12個月)：管理強化
│   ├── 權限管理系統
│   ├── 變更管理流程
│   └── 事件回應機制
├── 第三階段 (12-18個月)：技術深化
│   ├── 加密通訊實作
│   ├── 完整性監控
│   └── 進階威脅偵測
└── 第四階段 (18-24個月)：持續改善
    ├── 自動化安全運營
    ├── 威脅情報整合
    └── 預測性安全分析
```

### 快速勝利項目 (Quick Wins)

1. **網路存取控制清單**：立即見效，成本低
2. **預設帳號停用**：高安全效益，零成本
3. **安全設定基線**：標準化配置，易於實作
4. **基礎監控告警**：提升可見性，成本適中

## 0x05 下一步預告

在下一篇文章中，我們將深入探討：

- 基礎要求 (FR) 的具體實作細節
- 各種技術控制措施的選擇與配置
- 實際案例分析與最佳實務

---

_下一篇：[IEC62443-3-3 認證教學 (三)：基礎要求 (FR) 詳解與實作](/posts/iec62443-3-3-series-03-foundational-requirements/)_
