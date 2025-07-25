# Favicon 生成說明

## 如何創建多種尺寸的 favicon

您的綠色水滴頭像已經設定為 favicon，但為了在所有設備和瀏覽器上獲得最佳效果，建議創建以下尺寸：

### 推薦的 Favicon 尺寸：

- favicon.ico (16x16, 32x32, 48x48 多重尺寸)
- favicon-16x16.png
- favicon-32x32.png
- apple-touch-icon.png (180x180)
- android-chrome-192x192.png
- android-chrome-512x512.png

### 線上工具生成 Favicon：

1. **RealFaviconGenerator**: https://realfavicongenerator.net/

   - 上傳您的 avatar.png
   - 自動生成所有需要的尺寸和格式

2. **Favicon.io**: https://favicon.io/
   - 可以從 PNG 圖片生成完整的 favicon 套件

### 手動操作步驟：

1. 訪問 https://realfavicongenerator.net/
2. 上傳 `/static/images/avatar.png`
3. 配置各平台設定（可保持預設）
4. 下載生成的 favicon 套件
5. 將檔案放入 `/static/` 目錄
6. 更新 hugo.toml 中的路徑

### 目前配置：

- 所有 favicon 都指向 `/images/avatar.png`
- 這樣可以正常工作，但可能在某些情況下顯示效果不佳

如果您需要最佳效果，建議使用上述工具生成專用的 favicon 檔案。
