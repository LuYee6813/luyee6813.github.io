# #!/bin/note

個人資訊安全 blog，分享安全研究和 CTF writeups。

## 特色

- 🔒 資訊安全研究
- 🏆 CTF writeups
- 🛠️ 工具介紹
- 📚 技術分享

## 技術棧

- **Static Site Generator**: [Hugo](https://gohugo.io/)
- **Theme**: [PaperMod](https://github.com/adityatelange/hugo-PaperMod)
- **Hosting**: [GitHub Pages](https://pages.github.com/)
- **CI/CD**: [GitHub Actions](https://github.com/features/actions)

## 本地開發

### 前置需求

- [Hugo Extended](https://gohugo.io/installation/) (version 0.148.1 或更高)
- [Git](https://git-scm.com/)

### 安裝和執行

```bash
# 克隆存儲庫
git clone https://github.com/luyee6813/luyee6813.github.io.git
cd luyee6813.github.io

# 初始化 Git submodules
git submodule update --init --recursive

# 本地運行
hugo server --buildDrafts

# 建置生產版本
hugo --minify
```

網站將在 `http://localhost:1313` 上運行。

## 內容結構

```
content/
├── posts/          # 部落格文章
├── about.md        # 關於頁面
├── archives.md     # 文章歸檔
└── search.md       # 搜尋頁面
```

## 撰寫文章

建立新文章：

```bash
hugo new content/posts/your-post-title.md
```

文章模板：

```markdown
---
title: "您的文章標題"
date: 2024-01-15T10:00:00+08:00
description: "文章描述"
categories: ["CTF", "Security Research"]
tags: ["web", "pwn", "writeup"]
author: "Your Name"
ShowToc: true
TocOpen: false
draft: false
---

您的文章內容...
```

## 部署

每當推送到 `main` 分支時，GitHub Actions 會自動建置和部署網站到 GitHub Pages。

## 自訂配置

主要配置位於 `hugo.toml` 檔案中。您可以修改：

- 網站資訊 (標題、描述、作者)
- 社交媒體連結
- 選單項目
- 主題設定

## 貢獻

歡迎提出問題和建議！

## 授權

本專案採用 MIT 授權。詳見 [LICENSE](LICENSE) 檔案。

---

⭐ 如果這個專案對您有幫助，請給它一個星星！
