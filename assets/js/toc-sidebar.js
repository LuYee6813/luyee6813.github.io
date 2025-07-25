// 右側 TOC 功能增強
(function() {
    'use strict';
    
    // 當頁面載入完成後初始化
    document.addEventListener('DOMContentLoaded', function() {
        initTocHighlight();
        initSmoothScroll();
        initTocToggle();
    });
    
    // 初始化 TOC 高亮功能
    function initTocHighlight() {
        const tocSidebar = document.querySelector('.toc-sidebar');
        if (!tocSidebar) return;
        
        const tocLinks = tocSidebar.querySelectorAll('a');
        const headings = document.querySelectorAll('h1[id], h2[id], h3[id], h4[id], h5[id], h6[id]');
        
        if (tocLinks.length === 0 || headings.length === 0) return;
        
        // 創建 Intersection Observer 來監視標題
        const observer = new IntersectionObserver(
            function(entries) {
                entries.forEach(function(entry) {
                    const id = entry.target.getAttribute('id');
                    const tocLink = tocSidebar.querySelector('a[href="#' + id + '"]');
                    
                    if (entry.isIntersecting) {
                        // 移除所有活動狀態
                        tocLinks.forEach(function(link) {
                            link.classList.remove('active');
                        });
                        
                        // 添加當前項目的活動狀態
                        if (tocLink) {
                            tocLink.classList.add('active');
                        }
                    }
                });
            },
            {
                rootMargin: '-80px 0px -80% 0px',
                threshold: 0
            }
        );
        
        // 監視所有標題
        headings.forEach(function(heading) {
            observer.observe(heading);
        });
    }
    
    // 初始化平滑滾動
    function initSmoothScroll() {
        const tocSidebar = document.querySelector('.toc-sidebar');
        if (!tocSidebar) return;
        
        const tocLinks = tocSidebar.querySelectorAll('a[href^="#"]');
        
        tocLinks.forEach(function(link) {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                
                const targetId = this.getAttribute('href').substring(1);
                const targetElement = document.getElementById(targetId);
                
                if (targetElement) {
                    const offsetTop = targetElement.offsetTop - 80;
                    
                    window.scrollTo({
                        top: offsetTop,
                        behavior: 'smooth'
                    });
                    
                    // 更新 URL 但不跳轉
                    if (history.pushState) {
                        history.pushState(null, null, '#' + targetId);
                    }
                }
            });
        });
    }
    
    // 初始化 TOC 切換功能
    function initTocToggle() {
        console.log('initTocToggle called'); // 調試用
        
        const tocSidebar = document.getElementById('toc-sidebar');
        const tocToggle = document.getElementById('toc-toggle');
        const tocToggleIcon = document.getElementById('toc-toggle-icon');
        const tocContent = document.getElementById('toc-content');
        
        console.log('Elements found:', { tocSidebar, tocToggle, tocToggleIcon, tocContent }); // 調試用
        
        if (!tocSidebar || !tocToggle || !tocToggleIcon || !tocContent) {
            console.log('Some elements not found, returning'); // 調試用
            return;
        }
        
        // 讀取保存的狀態
        const isCollapsed = localStorage.getItem('toc-collapsed') === 'true';
        if (isCollapsed) {
            tocSidebar.classList.add('collapsed');
            tocContent.style.display = 'none';
            tocToggleIcon.textContent = '+';
        } else {
            tocContent.style.display = 'block';
            tocToggleIcon.textContent = '−';
        }
        
        // 切換按鈕點擊事件
        tocToggle.addEventListener('click', function(e) {
            console.log('Toggle button clicked'); // 調試用
            e.preventDefault();
            e.stopPropagation();
            
            const isCurrentlyCollapsed = tocSidebar.classList.contains('collapsed');
            console.log('Currently collapsed:', isCurrentlyCollapsed); // 調試用
            
            if (isCurrentlyCollapsed) {
                // 展開：顯示內容
                tocSidebar.classList.remove('collapsed');
                tocContent.style.display = 'block';
                tocToggleIcon.textContent = '−';
                localStorage.setItem('toc-collapsed', 'false');
                console.log('Expanded TOC'); // 調試用
            } else {
                // 收合：隱藏內容
                tocSidebar.classList.add('collapsed');
                tocContent.style.display = 'none';
                tocToggleIcon.textContent = '+';
                localStorage.setItem('toc-collapsed', 'true');
                console.log('Collapsed TOC'); // 調試用
            }
        });
    }
    
    // 處理視窗大小變化
    window.addEventListener('resize', function() {
        // 在移動設備上隱藏/顯示側邊欄
        const tocSidebar = document.querySelector('.toc-sidebar');
        if (!tocSidebar) return;
        
        if (window.innerWidth <= 768) {
            tocSidebar.style.position = 'relative';
        } else {
            tocSidebar.style.position = 'fixed';
        }
    });
    
})();
