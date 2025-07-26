---
title: "IEC62443-3-3 認證教學 (五)：風險評估與安全等級選擇"
date: 2025-07-26
categories: [工控資安]
tags: [IEC62443]
slug: "iec62443-3-3-series-05-risk-assessment"
---

## 0x00 前言

在[前一篇](/posts/iec62443-3-3-series-04-security-assurance-requirements/)中，我們深入了解了安全保證需求 (SAR)。今天我們要探討認證過程中最關鍵的環節之一：風險評估與安全等級選擇。這個步驟將直接決定您的系統需要實作哪些安全控制措施。

## 0x01 風險評估方法論

### IEC 62443 風險評估框架

```
風險評估框架
├── 第一階段：範圍定義與資產識別
│   ├── 系統邊界定義
│   ├── 關鍵資產清單
│   └── 業務影響分析
├── 第二階段：威脅識別與建模
│   ├── 威脅來源分析
│   ├── 攻擊向量識別
│   └── 攻擊情境建構
├── 第三階段：脆弱性評估
│   ├── 技術脆弱性
│   ├── 程序脆弱性
│   └── 人員脆弱性
├── 第四階段：風險計算與評級
│   ├── 影響程度評估
│   ├── 發生機率評估
│   └── 風險等級計算
└── 第五階段：風險處理與控制
    ├── 風險接受策略
    ├── 安全控制選擇
    └── 殘餘風險評估
```

### 風險評估實作工具

```python
import numpy as np
import pandas as pd
from enum import Enum
from typing import Dict, List, Tuple
import json
import matplotlib.pyplot as plt

class ThreatSource(Enum):
    ACCIDENTAL = 1
    INSIDER_BASIC = 2
    OUTSIDER_BASIC = 3
    INSIDER_ADVANCED = 4
    OUTSIDER_ADVANCED = 5
    NATION_STATE = 6

class ImpactLevel(Enum):
    NEGLIGIBLE = 1
    MINOR = 2
    MODERATE = 3
    MAJOR = 4
    CATASTROPHIC = 5

class VulnerabilityLevel(Enum):
    VERY_LOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    VERY_HIGH = 5

class RiskAssessmentFramework:
    def __init__(self):
        self.assets = {}
        self.threats = {}
        self.vulnerabilities = {}
        self.risk_matrix = self._initialize_risk_matrix()
        self.impact_criteria = self._define_impact_criteria()

    def _initialize_risk_matrix(self):
        """初始化風險矩陣"""
        # 風險 = 威脅 × 脆弱性 × 影響
        # 使用5x5矩陣，結果對應到安全等級
        matrix = np.array([
            [1, 1, 2, 2, 3],  # 威脅等級 1
            [1, 2, 2, 3, 3],  # 威脅等級 2
            [2, 2, 3, 3, 4],  # 威脅等級 3
            [2, 3, 3, 4, 4],  # 威脅等級 4
            [3, 3, 4, 4, 4]   # 威脅等級 5
        ])
        return matrix

    def _define_impact_criteria(self):
        """定義影響標準"""
        return {
            'safety': {
                1: '無安全影響',
                2: '輕微傷害可能',
                3: '嚴重傷害可能',
                4: '生命威脅',
                5: '多人死亡'
            },
            'environmental': {
                1: '無環境影響',
                2: '局部輕微污染',
                3: '區域環境影響',
                4: '嚴重環境災害',
                5: '不可逆環境破壞'
            },
            'financial': {
                1: '< 10萬元',
                2: '10萬-100萬元',
                3: '100萬-1000萬元',
                4: '1000萬-1億元',
                5: '> 1億元'
            },
            'operational': {
                1: '< 1小時停機',
                2: '1-8小時停機',
                3: '8-24小時停機',
                4: '1-7天停機',
                5: '> 7天停機'
            },
            'reputation': {
                1: '無聲譽影響',
                2: '局部負面報導',
                3: '全國性負面報導',
                4: '國際負面報導',
                5: '永久聲譽損害'
            }
        }

    def add_asset(self, asset_id, asset_info):
        """新增資產"""
        self.assets[asset_id] = {
            'name': asset_info['name'],
            'type': asset_info['type'],
            'criticality': asset_info['criticality'],
            'location': asset_info['location'],
            'dependencies': asset_info.get('dependencies', []),
            'security_zones': asset_info.get('security_zones', [])
        }

    def add_threat(self, threat_id, threat_info):
        """新增威脅"""
        self.threats[threat_id] = {
            'name': threat_info['name'],
            'source': threat_info['source'],
            'attack_vectors': threat_info['attack_vectors'],
            'capability_level': threat_info['capability_level'],
            'motivation': threat_info['motivation'],
            'affected_assets': threat_info.get('affected_assets', [])
        }

    def assess_threat_capability(self, threat_source: ThreatSource,
                               attack_complexity: str) -> int:
        """評估威脅能力等級"""
        base_capability = {
            ThreatSource.ACCIDENTAL: 1,
            ThreatSource.INSIDER_BASIC: 2,
            ThreatSource.OUTSIDER_BASIC: 2,
            ThreatSource.INSIDER_ADVANCED: 4,
            ThreatSource.OUTSIDER_ADVANCED: 4,
            ThreatSource.NATION_STATE: 5
        }

        complexity_modifier = {
            'low': 0,
            'medium': -1,
            'high': -2
        }

        capability = base_capability[threat_source] + complexity_modifier.get(attack_complexity, 0)
        return max(1, min(5, capability))

    def assess_vulnerability_level(self, asset_id: str, vulnerability_factors: Dict) -> int:
        """評估脆弱性等級"""
        factors = {
            'patch_level': vulnerability_factors.get('patch_level', 3),
            'configuration': vulnerability_factors.get('configuration', 3),
            'access_controls': vulnerability_factors.get('access_controls', 3),
            'monitoring': vulnerability_factors.get('monitoring', 3),
            'network_exposure': vulnerability_factors.get('network_exposure', 3)
        }

        # 計算加權平均
        weights = {
            'patch_level': 0.25,
            'configuration': 0.20,
            'access_controls': 0.25,
            'monitoring': 0.15,
            'network_exposure': 0.15
        }

        weighted_score = sum(
            factors[factor] * weights[factor]
            for factor in factors
        )

        return int(round(weighted_score))

    def calculate_impact_level(self, asset_id: str, impact_categories: Dict) -> int:
        """計算影響等級"""
        # 取最高影響等級作為總體影響
        max_impact = max(impact_categories.values())
        return max_impact

    def perform_risk_assessment(self, scenario_id: str, scenario_data: Dict):
        """執行風險評估"""
        threat_capability = self.assess_threat_capability(
            scenario_data['threat_source'],
            scenario_data['attack_complexity']
        )

        vulnerability_level = self.assess_vulnerability_level(
            scenario_data['target_asset'],
            scenario_data['vulnerability_factors']
        )

        impact_level = self.calculate_impact_level(
            scenario_data['target_asset'],
            scenario_data['impact_categories']
        )

        # 使用風險矩陣計算風險等級
        risk_index = (threat_capability + vulnerability_level + impact_level) / 3

        # 對應到安全等級
        if risk_index <= 1.5:
            security_level = 'SL1'
            risk_rating = 'LOW'
        elif risk_index <= 2.5:
            security_level = 'SL2'
            risk_rating = 'MEDIUM'
        elif risk_index <= 3.5:
            security_level = 'SL3'
            risk_rating = 'HIGH'
        else:
            security_level = 'SL4'
            risk_rating = 'CRITICAL'

        assessment_result = {
            'scenario_id': scenario_id,
            'threat_capability': threat_capability,
            'vulnerability_level': vulnerability_level,
            'impact_level': impact_level,
            'risk_index': risk_index,
            'risk_rating': risk_rating,
            'recommended_security_level': security_level,
            'assessment_date': pd.Timestamp.now().isoformat()
        }

        return assessment_result

    def generate_risk_register(self, scenarios: List[Dict]):
        """產生風險登記表"""
        risk_register = []

        for scenario in scenarios:
            assessment = self.perform_risk_assessment(
                scenario['scenario_id'],
                scenario
            )
            risk_register.append(assessment)

        # 轉換為 DataFrame 便於分析
        df = pd.DataFrame(risk_register)

        # 統計分析
        summary = {
            'total_scenarios': len(risk_register),
            'risk_distribution': df['risk_rating'].value_counts().to_dict(),
            'security_level_distribution': df['recommended_security_level'].value_counts().to_dict(),
            'average_risk_index': df['risk_index'].mean(),
            'highest_risk_scenarios': df.nlargest(5, 'risk_index')[['scenario_id', 'risk_rating', 'risk_index']].to_dict('records')
        }

        return {
            'risk_register': risk_register,
            'summary': summary,
            'dataframe': df
        }

    def visualize_risk_landscape(self, risk_register_data):
        """視覺化風險態勢"""
        df = risk_register_data['dataframe']

        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))

        # 風險等級分布
        risk_counts = df['risk_rating'].value_counts()
        ax1.pie(risk_counts.values, labels=risk_counts.index, autopct='%1.1f%%')
        ax1.set_title('風險等級分布')

        # 安全等級建議分布
        sl_counts = df['recommended_security_level'].value_counts()
        ax2.bar(sl_counts.index, sl_counts.values)
        ax2.set_title('建議安全等級分布')
        ax2.set_xlabel('安全等級')
        ax2.set_ylabel('情境數量')

        # 威脅能力 vs 脆弱性散點圖
        scatter = ax3.scatter(
            df['threat_capability'],
            df['vulnerability_level'],
            c=df['risk_index'],
            cmap='RdYlBu_r',
            s=df['impact_level']*20
        )
        ax3.set_xlabel('威脅能力等級')
        ax3.set_ylabel('脆弱性等級')
        ax3.set_title('威脅能力 vs 脆弱性 (顏色=風險指數, 大小=影響等級)')
        plt.colorbar(scatter, ax=ax3)

        # 風險指數分布直方圖
        ax4.hist(df['risk_index'], bins=20, alpha=0.7, edgecolor='black')
        ax4.set_xlabel('風險指數')
        ax4.set_ylabel('頻率')
        ax4.set_title('風險指數分布')
        ax4.axvline(df['risk_index'].mean(), color='red', linestyle='--', label=f'平均值: {df["risk_index"].mean():.2f}')
        ax4.legend()

        plt.tight_layout()
        plt.savefig('risk_landscape.png', dpi=300, bbox_inches='tight')
        plt.show()

        return fig

# 使用範例
risk_framework = RiskAssessmentFramework()

# 定義資產
assets = [
    {
        'id': 'HMI_001',
        'info': {
            'name': 'HMI 工作站 #1',
            'type': 'HMI',
            'criticality': 'HIGH',
            'location': '控制室',
            'dependencies': ['PLC_001', 'HIS_001']
        }
    },
    {
        'id': 'PLC_001',
        'info': {
            'name': '主控制器',
            'type': 'PLC',
            'criticality': 'CRITICAL',
            'location': '控制櫃',
            'dependencies': ['IO_MODULES']
        }
    }
]

for asset in assets:
    risk_framework.add_asset(asset['id'], asset['info'])

# 定義風險情境
risk_scenarios = [
    {
        'scenario_id': 'SC001',
        'name': '惡意內部人員攻擊 HMI',
        'threat_source': ThreatSource.INSIDER_ADVANCED,
        'attack_complexity': 'low',
        'target_asset': 'HMI_001',
        'vulnerability_factors': {
            'patch_level': 3,
            'configuration': 2,
            'access_controls': 2,
            'monitoring': 3,
            'network_exposure': 4
        },
        'impact_categories': {
            'safety': 4,
            'environmental': 2,
            'financial': 3,
            'operational': 4,
            'reputation': 3
        }
    },
    {
        'scenario_id': 'SC002',
        'name': '遠端攻擊者入侵 PLC',
        'threat_source': ThreatSource.OUTSIDER_ADVANCED,
        'attack_complexity': 'high',
        'target_asset': 'PLC_001',
        'vulnerability_factors': {
            'patch_level': 2,
            'configuration': 3,
            'access_controls': 3,
            'monitoring': 2,
            'network_exposure': 3
        },
        'impact_categories': {
            'safety': 5,
            'environmental': 4,
            'financial': 4,
            'operational': 5,
            'reputation': 4
        }
    },
    {
        'scenario_id': 'SC003',
        'name': '員工誤操作',
        'threat_source': ThreatSource.ACCIDENTAL,
        'attack_complexity': 'low',
        'target_asset': 'HMI_001',
        'vulnerability_factors': {
            'patch_level': 3,
            'configuration': 3,
            'access_controls': 2,
            'monitoring': 3,
            'network_exposure': 2
        },
        'impact_categories': {
            'safety': 3,
            'environmental': 2,
            'financial': 2,
            'operational': 3,
            'reputation': 1
        }
    }
]

# 執行風險評估
risk_results = risk_framework.generate_risk_register(risk_scenarios)

print("=== 風險評估結果 ===")
print(f"總情境數: {risk_results['summary']['total_scenarios']}")
print(f"平均風險指數: {risk_results['summary']['average_risk_index']:.2f}")
print("\n風險等級分布:")
for rating, count in risk_results['summary']['risk_distribution'].items():
    print(f"  {rating}: {count}")

print("\n建議安全等級分布:")
for sl, count in risk_results['summary']['security_level_distribution'].items():
    print(f"  {sl}: {count}")

print("\n最高風險情境:")
for scenario in risk_results['summary']['highest_risk_scenarios']:
    print(f"  {scenario['scenario_id']}: {scenario['risk_rating']} (指數: {scenario['risk_index']:.2f})")
```

## 0x02 威脅建模與攻擊樹分析

### STRIDE 威脅模型應用

```python
from enum import Enum
import networkx as nx
import matplotlib.pyplot as plt

class STRIDECategory(Enum):
    SPOOFING = "偽造身份"
    TAMPERING = "竄改資料"
    REPUDIATION = "否認行為"
    INFORMATION_DISCLOSURE = "資訊洩露"
    DENIAL_OF_SERVICE = "阻斷服務"
    ELEVATION_OF_PRIVILEGE = "權限提升"

class ThreatModelingFramework:
    def __init__(self):
        self.data_flows = {}
        self.trust_boundaries = {}
        self.threats = {}
        self.attack_trees = {}

    def create_data_flow_diagram(self, system_components):
        """建立資料流程圖"""
        G = nx.DiGraph()

        for component in system_components:
            G.add_node(
                component['id'],
                type=component['type'],
                trust_level=component['trust_level']
            )

        # 新增資料流
        for flow in system_components:
            for connection in flow.get('connections', []):
                G.add_edge(
                    flow['id'],
                    connection['target'],
                    protocol=connection['protocol'],
                    data_type=connection['data_type'],
                    encryption=connection.get('encryption', False)
                )

        return G

    def identify_stride_threats(self, data_flow_graph):
        """識別 STRIDE 威脅"""
        stride_threats = []

        for node in data_flow_graph.nodes():
            node_data = data_flow_graph.nodes[node]

            # 根據組件類型識別威脅
            component_threats = self._get_component_threats(node, node_data)
            stride_threats.extend(component_threats)

        for edge in data_flow_graph.edges():
            edge_data = data_flow_graph.edges[edge]

            # 根據資料流識別威脅
            flow_threats = self._get_flow_threats(edge, edge_data)
            stride_threats.extend(flow_threats)

        return stride_threats

    def _get_component_threats(self, component_id, component_data):
        """取得組件相關威脅"""
        threats = []
        component_type = component_data['type']

        threat_templates = {
            'HMI': [
                {
                    'category': STRIDECategory.SPOOFING,
                    'description': 'HMI 身份偽造攻擊',
                    'impact': 'HIGH',
                    'likelihood': 'MEDIUM'
                },
                {
                    'category': STRIDECategory.TAMPERING,
                    'description': 'HMI 顯示資料竄改',
                    'impact': 'HIGH',
                    'likelihood': 'MEDIUM'
                }
            ],
            'PLC': [
                {
                    'category': STRIDECategory.TAMPERING,
                    'description': 'PLC 程式邏輯竄改',
                    'impact': 'CRITICAL',
                    'likelihood': 'LOW'
                },
                {
                    'category': STRIDECategory.DENIAL_OF_SERVICE,
                    'description': 'PLC 服務阻斷攻擊',
                    'impact': 'CRITICAL',
                    'likelihood': 'MEDIUM'
                }
            ]
        }

        for threat_template in threat_templates.get(component_type, []):
            threat = {
                'id': f"THR_{component_id}_{threat_template['category'].name}",
                'component': component_id,
                'category': threat_template['category'],
                'description': threat_template['description'],
                'impact': threat_template['impact'],
                'likelihood': threat_template['likelihood']
            }
            threats.append(threat)

        return threats

    def create_attack_tree(self, target_goal, attack_vectors):
        """建立攻擊樹"""
        tree = nx.DiGraph()

        # 根節點 - 攻擊目標
        tree.add_node(target_goal, type='goal', difficulty='', success_rate=0)

        for vector in attack_vectors:
            self._add_attack_vector_to_tree(tree, target_goal, vector)

        return tree

    def _add_attack_vector_to_tree(self, tree, parent, vector):
        """新增攻擊向量到攻擊樹"""
        vector_id = vector['id']
        tree.add_node(
            vector_id,
            type='vector',
            difficulty=vector['difficulty'],
            success_rate=vector['success_rate'],
            description=vector['description']
        )
        tree.add_edge(parent, vector_id)

        # 新增子步驟
        for step in vector.get('sub_steps', []):
            step_id = f"{vector_id}_{step['id']}"
            tree.add_node(
                step_id,
                type='step',
                difficulty=step['difficulty'],
                success_rate=step['success_rate'],
                description=step['description']
            )
            tree.add_edge(vector_id, step_id)

    def calculate_attack_success_probability(self, attack_tree, target_node):
        """計算攻擊成功機率"""
        if attack_tree.out_degree(target_node) == 0:
            # 葉節點，返回基本成功率
            return attack_tree.nodes[target_node]['success_rate']

        success_rates = []
        for child in attack_tree.successors(target_node):
            child_success_rate = self.calculate_attack_success_probability(attack_tree, child)
            success_rates.append(child_success_rate)

        # 假設為 OR 邏輯（任一成功即可）
        # P(A or B) = P(A) + P(B) - P(A and B)
        combined_success_rate = 1 - np.prod([1 - rate for rate in success_rates])

        return min(1.0, combined_success_rate)

# 使用範例
threat_modeler = ThreatModelingFramework()

# 定義系統組件
system_components = [
    {
        'id': 'HMI_01',
        'type': 'HMI',
        'trust_level': 'medium',
        'connections': [
            {
                'target': 'PLC_01',
                'protocol': 'Modbus TCP',
                'data_type': 'control_commands',
                'encryption': False
            }
        ]
    },
    {
        'id': 'PLC_01',
        'type': 'PLC',
        'trust_level': 'high',
        'connections': [
            {
                'target': 'IO_MODULE_01',
                'protocol': 'Proprietary',
                'data_type': 'sensor_data',
                'encryption': False
            }
        ]
    },
    {
        'id': 'IO_MODULE_01',
        'type': 'IO_MODULE',
        'trust_level': 'high',
        'connections': []
    }
]

# 建立資料流程圖
dfd = threat_modeler.create_data_flow_diagram(system_components)

# 識別 STRIDE 威脅
stride_threats = threat_modeler.identify_stride_threats(dfd)

print("=== STRIDE 威脅分析結果 ===")
for threat in stride_threats:
    print(f"威脅 ID: {threat['id']}")
    print(f"類別: {threat['category'].value}")
    print(f"描述: {threat['description']}")
    print(f"影響: {threat['impact']}")
    print(f"可能性: {threat['likelihood']}")
    print("-" * 50)

# 建立攻擊樹
attack_vectors = [
    {
        'id': 'NETWORK_ATTACK',
        'description': '網路攻擊路徑',
        'difficulty': 'medium',
        'success_rate': 0.3,
        'sub_steps': [
            {
                'id': 'NETWORK_SCAN',
                'description': '網路掃描',
                'difficulty': 'low',
                'success_rate': 0.9
            },
            {
                'id': 'EXPLOIT_VULN',
                'description': '利用漏洞',
                'difficulty': 'high',
                'success_rate': 0.4
            }
        ]
    },
    {
        'id': 'PHYSICAL_ATTACK',
        'description': '物理攻擊路徑',
        'difficulty': 'high',
        'success_rate': 0.2,
        'sub_steps': [
            {
                'id': 'FACILITY_ACCESS',
                'description': '進入設施',
                'difficulty': 'medium',
                'success_rate': 0.5
            },
            {
                'id': 'DEVICE_ACCESS',
                'description': '接觸設備',
                'difficulty': 'low',
                'success_rate': 0.8
            }
        ]
    }
]

attack_tree = threat_modeler.create_attack_tree('COMPROMISE_PLC', attack_vectors)

# 計算攻擊成功機率
success_probability = threat_modeler.calculate_attack_success_probability(
    attack_tree, 'COMPROMISE_PLC'
)

print(f"\n=== 攻擊樹分析結果 ===")
print(f"攻擊目標: COMPROMISE_PLC")
print(f"整體成功機率: {success_probability:.2%}")
```

## 0x03 安全等級選擇決策框架

### 多準則決策分析 (MCDA)

```python
import numpy as np
from scipy.stats import entropy

class SecurityLevelDecisionFramework:
    def __init__(self):
        self.criteria = {
            'safety_impact': {'weight': 0.30, 'type': 'benefit'},
            'security_threats': {'weight': 0.25, 'type': 'cost'},
            'implementation_cost': {'weight': 0.20, 'type': 'cost'},
            'operational_complexity': {'weight': 0.15, 'type': 'cost'},
            'business_continuity': {'weight': 0.10, 'type': 'benefit'}
        }

        self.security_levels = ['SL1', 'SL2', 'SL3', 'SL4']

    def normalize_criteria_matrix(self, decision_matrix):
        """正規化決策矩陣"""
        normalized_matrix = np.zeros_like(decision_matrix)

        for j in range(decision_matrix.shape[1]):
            column = decision_matrix[:, j]
            # 使用向量正規化
            norm = np.linalg.norm(column)
            if norm != 0:
                normalized_matrix[:, j] = column / norm
            else:
                normalized_matrix[:, j] = column

        return normalized_matrix

    def calculate_weighted_scores(self, normalized_matrix, criteria_weights):
        """計算加權分數"""
        weighted_matrix = normalized_matrix.copy()

        for j, (criterion, info) in enumerate(self.criteria.items()):
            weight = info['weight']
            criterion_type = info['type']

            if criterion_type == 'cost':
                # 成本型準則，值越小越好
                weighted_matrix[:, j] = (1 - normalized_matrix[:, j]) * weight
            else:
                # 效益型準則，值越大越好
                weighted_matrix[:, j] = normalized_matrix[:, j] * weight

        return weighted_matrix

    def topsis_analysis(self, decision_matrix):
        """TOPSIS 多準則決策分析"""
        # 步驟 1: 正規化決策矩陣
        normalized_matrix = self.normalize_criteria_matrix(decision_matrix)

        # 步驟 2: 計算加權正規化矩陣
        weighted_matrix = self.calculate_weighted_scores(normalized_matrix, self.criteria)

        # 步驟 3: 確定正理想解和負理想解
        ideal_positive = np.max(weighted_matrix, axis=0)
        ideal_negative = np.min(weighted_matrix, axis=0)

        # 步驟 4: 計算與理想解的距離
        positive_distances = np.sqrt(np.sum((weighted_matrix - ideal_positive) ** 2, axis=1))
        negative_distances = np.sqrt(np.sum((weighted_matrix - ideal_negative) ** 2, axis=1))

        # 步驟 5: 計算相對接近度
        closeness_scores = negative_distances / (positive_distances + negative_distances)

        # 排序結果
        ranking = np.argsort(closeness_scores)[::-1]

        results = []
        for i, rank in enumerate(ranking):
            results.append({
                'security_level': self.security_levels[rank],
                'closeness_score': closeness_scores[rank],
                'rank': i + 1
            })

        return results

    def sensitivity_analysis(self, decision_matrix, criteria_variations):
        """敏感度分析"""
        base_results = self.topsis_analysis(decision_matrix)
        sensitivity_results = {'base_ranking': base_results}

        for variation_name, weight_changes in criteria_variations.items():
            # 暫時修改權重
            original_weights = self.criteria.copy()

            for criterion, change in weight_changes.items():
                if criterion in self.criteria:
                    self.criteria[criterion]['weight'] *= (1 + change)

            # 重新正規化權重
            total_weight = sum(info['weight'] for info in self.criteria.values())
            for criterion in self.criteria:
                self.criteria[criterion]['weight'] /= total_weight

            # 重新計算
            variation_results = self.topsis_analysis(decision_matrix)
            sensitivity_results[variation_name] = variation_results

            # 恢復原始權重
            self.criteria = original_weights

        return sensitivity_results

    def generate_recommendation_report(self, analysis_results, system_context):
        """產生建議報告"""
        best_option = analysis_results['base_ranking'][0]

        report = f"""
# 安全等級選擇建議報告

## 系統背景
- 系統名稱: {system_context['system_name']}
- 產業類別: {system_context['industry']}
- 關鍵程度: {system_context['criticality']}

## 分析結果

### 推薦安全等級: {best_option['security_level']}
- 綜合分數: {best_option['closeness_score']:.3f}
- 排名: {best_option['rank']}

### 完整排名
"""

        for result in analysis_results['base_ranking']:
            report += f"- {result['rank']}. {result['security_level']} (分數: {result['closeness_score']:.3f})\n"

        report += "\n### 決策理由\n"

        if best_option['security_level'] == 'SL1':
            report += "- 系統面臨的威脅等級較低\n- 成本效益考量優先\n- 基本安全措施已足夠\n"
        elif best_option['security_level'] == 'SL2':
            report += "- 平衡安全性與成本\n- 適合一般工業環境\n- 標準安全控制措施\n"
        elif best_option['security_level'] == 'SL3':
            report += "- 高安全需求環境\n- 面臨進階威脅\n- 強化安全控制必要\n"
        else:  # SL4
            report += "- 關鍵基礎設施\n- 國家級威脅考量\n- 最高等級安全保護\n"

        return report

# 使用範例
decision_framework = SecurityLevelDecisionFramework()

# 定義決策矩陣 (行: 安全等級, 列: 評估準則)
# 準則: [安全影響, 安全威脅, 實作成本, 營運複雜性, 業務連續性]
decision_matrix = np.array([
    [2, 2, 1, 1, 2],  # SL1
    [3, 3, 2, 2, 3],  # SL2
    [4, 4, 4, 4, 4],  # SL3
    [5, 5, 5, 5, 5]   # SL4
])

# 執行 TOPSIS 分析
topsis_results = decision_framework.topsis_analysis(decision_matrix)

print("=== TOPSIS 分析結果 ===")
for result in topsis_results:
    print(f"排名 {result['rank']}: {result['security_level']} (分數: {result['closeness_score']:.3f})")

# 敏感度分析
sensitivity_variations = {
    'high_safety_priority': {'safety_impact': 0.5},  # 安全影響權重增加 50%
    'cost_sensitive': {'implementation_cost': 0.5},  # 成本權重增加 50%
    'threat_focused': {'security_threats': 0.3}      # 威脅權重增加 30%
}

sensitivity_results = decision_framework.sensitivity_analysis(decision_matrix, sensitivity_variations)

print("\n=== 敏感度分析 ===")
for scenario, results in sensitivity_results.items():
    print(f"\n{scenario}:")
    top_choice = results[0]
    print(f"  推薦: {top_choice['security_level']} (分數: {top_choice['closeness_score']:.3f})")

# 產生建議報告
system_context = {
    'system_name': '石化廠控制系統',
    'industry': '石油化工',
    'criticality': '高'
}

recommendation_report = decision_framework.generate_recommendation_report(
    {'base_ranking': topsis_results},
    system_context
)

print(recommendation_report)
```

## 0x04 成本效益分析模型

### 投資回收期分析

```python
import numpy as np
from scipy.optimize import minimize_scalar

class SecurityInvestmentAnalysis:
    def __init__(self):
        self.discount_rate = 0.08  # 8% 貼現率
        self.analysis_period = 10  # 10年分析期間

    def calculate_security_investment_cost(self, current_sl, target_sl, system_value):
        """計算安全投資成本"""
        # 各安全等級的實作成本係數（相對於系統價值）
        implementation_costs = {
            'SL1': 0.02,  # 2%
            'SL2': 0.05,  # 5%
            'SL3': 0.12,  # 12%
            'SL4': 0.25   # 25%
        }

        # 年度維護成本係數
        maintenance_costs = {
            'SL1': 0.005,  # 0.5%
            'SL2': 0.010,  # 1.0%
            'SL3': 0.020,  # 2.0%
            'SL4': 0.035   # 3.5%
        }

        current_cost = implementation_costs[current_sl] * system_value
        target_cost = implementation_costs[target_sl] * system_value
        upgrade_cost = max(0, target_cost - current_cost)

        annual_maintenance = maintenance_costs[target_sl] * system_value

        return {
            'initial_investment': upgrade_cost,
            'annual_maintenance': annual_maintenance,
            'total_maintenance_npv': self._calculate_npv(
                [annual_maintenance] * self.analysis_period
            )
        }

    def calculate_risk_reduction_benefits(self, current_sl, target_sl,
                                        annual_risk_exposure):
        """計算風險降低效益"""
        # 各安全等級的風險降低效率
        risk_reduction_rates = {
            'SL1': 0.30,  # 30%
            'SL2': 0.60,  # 60%
            'SL3': 0.85,  # 85%
            'SL4': 0.95   # 95%
        }

        current_protection = risk_reduction_rates[current_sl]
        target_protection = risk_reduction_rates[target_sl]

        additional_protection = target_protection - current_protection
        annual_risk_reduction = annual_risk_exposure * additional_protection

        # 考慮風險事件的機率遞減（因為改善後風險降低）
        risk_benefits = []
        for year in range(self.analysis_period):
            # 假設每年風險遞減 5%（由於持續改善）
            yearly_benefit = annual_risk_reduction * (0.95 ** year)
            risk_benefits.append(yearly_benefit)

        return {
            'annual_risk_reduction': annual_risk_reduction,
            'risk_benefits_stream': risk_benefits,
            'total_risk_benefits_npv': self._calculate_npv(risk_benefits)
        }

    def calculate_productivity_benefits(self, target_sl, system_value):
        """計算生產力提升效益"""
        # 安全投資帶來的生產力提升
        productivity_factors = {
            'SL1': 0.01,  # 1%
            'SL2': 0.02,  # 2%
            'SL3': 0.03,  # 3%
            'SL4': 0.04   # 4%
        }

        annual_productivity_gain = system_value * productivity_factors[target_sl] * 0.1
        productivity_stream = [annual_productivity_gain] * self.analysis_period

        return {
            'annual_productivity_gain': annual_productivity_gain,
            'total_productivity_npv': self._calculate_npv(productivity_stream)
        }

    def calculate_compliance_benefits(self, target_sl):
        """計算合規效益"""
        # 避免罰款和聲譽損失
        compliance_benefits = {
            'SL1': 50000,    # 5萬元
            'SL2': 200000,   # 20萬元
            'SL3': 500000,   # 50萬元
            'SL4': 1000000   # 100萬元
        }

        annual_compliance_benefit = compliance_benefits[target_sl]
        compliance_stream = [annual_compliance_benefit] * self.analysis_period

        return {
            'annual_compliance_benefit': annual_compliance_benefit,
            'total_compliance_npv': self._calculate_npv(compliance_stream)
        }

    def _calculate_npv(self, cash_flows):
        """計算淨現值"""
        npv = 0
        for year, cash_flow in enumerate(cash_flows):
            npv += cash_flow / ((1 + self.discount_rate) ** (year + 1))
        return npv

    def comprehensive_cost_benefit_analysis(self, current_sl, target_sl,
                                          system_value, annual_risk_exposure):
        """綜合成本效益分析"""
        # 計算成本
        investment_costs = self.calculate_security_investment_cost(
            current_sl, target_sl, system_value
        )

        total_costs = (investment_costs['initial_investment'] +
                      investment_costs['total_maintenance_npv'])

        # 計算效益
        risk_benefits = self.calculate_risk_reduction_benefits(
            current_sl, target_sl, annual_risk_exposure
        )

        productivity_benefits = self.calculate_productivity_benefits(
            target_sl, system_value
        )

        compliance_benefits = self.calculate_compliance_benefits(target_sl)

        total_benefits = (risk_benefits['total_risk_benefits_npv'] +
                         productivity_benefits['total_productivity_npv'] +
                         compliance_benefits['total_compliance_npv'])

        # 計算關鍵指標
        net_present_value = total_benefits - total_costs
        benefit_cost_ratio = total_benefits / total_costs if total_costs > 0 else float('inf')

        # 計算回收期
        payback_period = self._calculate_payback_period(
            investment_costs['initial_investment'],
            risk_benefits['annual_risk_reduction'] +
            productivity_benefits['annual_productivity_gain'] +
            compliance_benefits['annual_compliance_benefit']
        )

        return {
            'costs': {
                'initial_investment': investment_costs['initial_investment'],
                'annual_maintenance': investment_costs['annual_maintenance'],
                'total_costs_npv': total_costs
            },
            'benefits': {
                'risk_reduction_npv': risk_benefits['total_risk_benefits_npv'],
                'productivity_npv': productivity_benefits['total_productivity_npv'],
                'compliance_npv': compliance_benefits['total_compliance_npv'],
                'total_benefits_npv': total_benefits
            },
            'financial_metrics': {
                'net_present_value': net_present_value,
                'benefit_cost_ratio': benefit_cost_ratio,
                'payback_period_years': payback_period,
                'internal_rate_of_return': self._calculate_irr(
                    total_costs, total_benefits
                )
            },
            'recommendation': self._generate_investment_recommendation(
                net_present_value, benefit_cost_ratio, payback_period
            )
        }

    def _calculate_payback_period(self, initial_investment, annual_benefit):
        """計算投資回收期"""
        if annual_benefit <= 0:
            return float('inf')
        return initial_investment / annual_benefit

    def _calculate_irr(self, total_costs, total_benefits):
        """計算內部收益率（簡化版）"""
        if total_costs <= 0:
            return float('inf')

        # 簡化的 IRR 計算
        benefit_cost_ratio = total_benefits / total_costs
        if benefit_cost_ratio <= 1:
            return 0

        # 近似計算
        irr = (benefit_cost_ratio ** (1/self.analysis_period)) - 1
        return irr

    def _generate_investment_recommendation(self, npv, bcr, payback):
        """產生投資建議"""
        if npv > 0 and bcr > 1.2 and payback < 5:
            return "強烈建議投資"
        elif npv > 0 and bcr > 1.0 and payback < 8:
            return "建議投資"
        elif npv > 0:
            return "可考慮投資"
        else:
            return "不建議投資"

    def scenario_analysis(self, base_parameters, scenarios):
        """情境分析"""
        scenario_results = {}

        for scenario_name, scenario_params in scenarios.items():
            # 合併基礎參數和情境參數
            combined_params = {**base_parameters, **scenario_params}

            analysis_result = self.comprehensive_cost_benefit_analysis(
                combined_params['current_sl'],
                combined_params['target_sl'],
                combined_params['system_value'],
                combined_params['annual_risk_exposure']
            )

            scenario_results[scenario_name] = analysis_result

        return scenario_results

# 使用範例
investment_analyzer = SecurityInvestmentAnalysis()

# 基礎參數
base_params = {
    'current_sl': 'SL1',
    'target_sl': 'SL3',
    'system_value': 50000000,  # 5000萬元系統
    'annual_risk_exposure': 5000000  # 年度風險暴露 500萬元
}

# 執行綜合成本效益分析
cba_result = investment_analyzer.comprehensive_cost_benefit_analysis(
    base_params['current_sl'],
    base_params['target_sl'],
    base_params['system_value'],
    base_params['annual_risk_exposure']
)

print("=== 成本效益分析結果 ===")
print(f"初始投資: {cba_result['costs']['initial_investment']:,.0f} 元")
print(f"年度維護成本: {cba_result['costs']['annual_maintenance']:,.0f} 元")
print(f"總成本現值: {cba_result['costs']['total_costs_npv']:,.0f} 元")
print(f"總效益現值: {cba_result['benefits']['total_benefits_npv']:,.0f} 元")
print(f"淨現值: {cba_result['financial_metrics']['net_present_value']:,.0f} 元")
print(f"效益成本比: {cba_result['financial_metrics']['benefit_cost_ratio']:.2f}")
print(f"回收期: {cba_result['financial_metrics']['payback_period_years']:.1f} 年")
print(f"投資建議: {cba_result['recommendation']}")

# 情境分析
scenarios = {
    '樂觀情境': {
        'annual_risk_exposure': 8000000,  # 風險暴露較高
        'system_value': 60000000          # 系統價值較高
    },
    '悲觀情境': {
        'annual_risk_exposure': 2000000,  # 風險暴露較低
        'system_value': 40000000          # 系統價值較低
    },
    '高威脅情境': {
        'target_sl': 'SL4',              # 需要更高安全等級
        'annual_risk_exposure': 10000000  # 風險暴露很高
    }
}

scenario_results = investment_analyzer.scenario_analysis(base_params, scenarios)

print("\n=== 情境分析結果 ===")
for scenario_name, result in scenario_results.items():
    print(f"\n{scenario_name}:")
    print(f"  淨現值: {result['financial_metrics']['net_present_value']:,.0f} 元")
    print(f"  效益成本比: {result['financial_metrics']['benefit_cost_ratio']:.2f}")
    print(f"  投資建議: {result['recommendation']}")
```

## 0x05 下一步預告

在最後一篇文章中，我們將探討：

- 認證準備的具體步驟與時程規劃
- 第三方評估機構的選擇與配合
- 認證後的持續維護與改善

---

_下一篇：[IEC62443-3-3 認證教學 (六)：認證準備與實作指南](/posts/iec62443-3-3-series-06-certification-guide/)_
