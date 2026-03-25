#!/usr/bin/env python3
"""
專案報告生成器
生成PNG格式的專案分析報告
包含：專案代號、開始時間、掃描時長、請求數、Priority統計、回應時間等
"""

import os
import json
import glob
import re
from datetime import datetime, timedelta
from collections import Counter
from PIL import Image, ImageDraw, ImageFont
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm

def parse_fast_log_priorities(log_file):
    """從 fast.log 中解析 Priority 統計"""
    priority_counter = Counter()
    
    if not os.path.exists(log_file):
        return priority_counter
    
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                # 尋找 Priority 資訊
                match = re.search(r'\[Priority:\s*(\d+)\]', line)
                if match:
                    priority = int(match.group(1))
                    priority_counter[priority] += 1
    except Exception as e:
        print(f"解析 fast.log 時發生錯誤: {e}")
    
    return priority_counter

def calculate_duration(start_time, end_time):
    """計算時間差"""
    try:
        start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        duration = end - start
        
        hours = duration.seconds // 3600
        minutes = (duration.seconds % 3600) // 60
        seconds = duration.seconds % 60
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    except Exception as e:
        return "N/A"

def format_bytes(bytes_val):
    """格式化位元組大小"""
    if bytes_val >= 1073741824:
        return f"{bytes_val / 1073741824:.2f} GB"
    elif bytes_val >= 1048576:
        return f"{bytes_val / 1048576:.2f} MB"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.2f} KB"
    else:
        return f"{bytes_val} B"

def get_total_requests(event_data):
    """計算總請求數（各協議的總數）"""
    total = 0
    for protocol, stats in event_data.items():
        if isinstance(stats, dict) and 'count' in stats:
            total += stats['count']
    return total

def generate_report_image(project_code, output_path='report.png'):
    """
    生成專案報告圖片
    
    參數:
        project_code: 專案代號 (例如: '114_ksy')
        output_path: 輸出圖片路徑
    """
    project_dir = os.path.join('project', project_code)
    
    # 檢查專案目錄是否存在
    if not os.path.exists(project_dir):
        print(f"錯誤: 找不到專案目錄 {project_dir}")
        return False
    
    # 讀取 analysis_summary.json
    summary_file = os.path.join(project_dir, 'analysis_summary.json')
    if not os.path.exists(summary_file):
        print(f"錯誤: 找不到分析摘要檔案 {summary_file}")
        return False
    
    try:
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary = json.load(f)
    except Exception as e:
        print(f"錯誤: 無法讀取分析摘要檔案: {e}")
        return False
    
    # 讀取 fast.log 的 Priority 統計
    fast_log = os.path.join(project_dir, 'merged_fast.log')
    priority_stats = parse_fast_log_priorities(fast_log)
    
    # 提取資料
    flow_data = summary.get('flow', {})
    event_data = summary.get('event', {})
    
    start_time = flow_data.get('start_time', 'N/A')
    end_time = flow_data.get('end_time', 'N/A')
    total_bytes = flow_data.get('total_bytes', 0)
    
    # 格式化開始時間
    if start_time != 'N/A':
        try:
            dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            formatted_start_time = dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            formatted_start_time = start_time
    else:
        formatted_start_time = 'N/A'
    
    # 計算掃描時長
    scan_duration = calculate_duration(start_time, end_time)
    
    # 計算總請求數
    total_requests = get_total_requests(event_data)
    
    # Priority 統計
    priority_1 = priority_stats.get(1, 0)
    priority_2 = priority_stats.get(2, 0)
    priority_3 = priority_stats.get(3, 0)
    
    # 設置圖片大小和背景
    fig, ax = plt.subplots(figsize=(14, 10))
    ax.axis('off')
    fig.patch.set_facecolor('#f8f9fa')
    
    # 設置中文字體
    try:
        # Windows 系統使用微軟正黑體
        font_path = 'C:\\Windows\\Fonts\\msjh.ttc'
        if os.path.exists(font_path):
            plt.rcParams['font.sans-serif'] = ['Microsoft JhengHei']
        else:
            plt.rcParams['font.sans-serif'] = ['Arial Unicode MS', 'DejaVu Sans']
    except:
        pass
    plt.rcParams['axes.unicode_minus'] = False
    
    # 創建標題背景框
    from matplotlib.patches import Rectangle
    title_box = Rectangle((0.05, 0.90), 0.9, 0.08, 
                          transform=ax.transAxes,
                          facecolor='#2c3e50', edgecolor='none')
    ax.add_patch(title_box)
    
    # 創建報告標題
    title_text = f"專案分析報告 - {project_code}"
    ax.text(0.5, 0.94, title_text, ha='center', va='center', 
            fontsize=26, fontweight='bold', color='white',
            transform=ax.transAxes)
    
    # 創建內容背景框
    content_box = Rectangle((0.08, 0.10), 0.84, 0.78, 
                           transform=ax.transAxes,
                           facecolor='white', edgecolor='#dee2e6', linewidth=2)
    ax.add_patch(content_box)
    
    # 定義資料欄位和值
    data_fields = [
        ('專案代號', project_code, '#3498db'),
        ('Start Time', formatted_start_time, '#2ecc71'),
        ('Scan Duration', scan_duration, '#f39c12'),
        ('Total Traffic', format_bytes(total_bytes), '#9b59b6'),
        ('Requests', f"{total_requests:,}", '#e74c3c'),
        ('Priority 1 數量', f"{priority_1:,}", '#e74c3c'),
        ('Priority 2 數量', f"{priority_2:,}", '#f39c12'),
        ('Priority 3 數量', f"{priority_3:,}", '#95a5a6'),
        ('Average Response Time', 'N/A (PCAP分析)', '#7f8c8d'),
        ('Maximum Response Time', 'N/A (PCAP分析)', '#7f8c8d'),
    ]
    
    # 添加資料欄位
    y_position = 0.83
    line_spacing = 0.065
    
    for i, (field_name, field_value, color) in enumerate(data_fields):
        # 背景條紋效果（交替顏色）
        if i % 2 == 0:
            stripe = Rectangle((0.10, y_position - 0.032), 0.80, 0.055, 
                              transform=ax.transAxes,
                              facecolor='#f8f9fa', edgecolor='none', zorder=1)
            ax.add_patch(stripe)
        
        # 欄位名稱（左側）- 加粗
        ax.text(0.13, y_position, field_name + ':', 
                ha='left', va='center', fontsize=15, fontweight='bold',
                transform=ax.transAxes, zorder=2)
        
        # 欄位值（右側）- 帶顏色
        ax.text(0.50, y_position, str(field_value), 
                ha='left', va='center', fontsize=15, fontweight='600',
                transform=ax.transAxes, color=color, zorder=2)
        
        y_position -= line_spacing
    
    # 添加頁尾
    footer_box = Rectangle((0.05, 0.02), 0.9, 0.05, 
                          transform=ax.transAxes,
                          facecolor='#ecf0f1', edgecolor='none')
    ax.add_patch(footer_box)
    
    footer_y = 0.045
    ax.text(0.5, footer_y, f"報告生成時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
            ha='center', va='center', fontsize=11, style='italic',
            transform=ax.transAxes, color='#7f8c8d')
    
    # 儲存圖片
    plt.tight_layout()
    plt.savefig(output_path, dpi=200, bbox_inches='tight', 
                facecolor='#f8f9fa', edgecolor='none')
    plt.close()
    
    print(f"✅ 報告已生成: {output_path}")
    return True

def list_available_projects():
    """列出所有可用的專案"""
    project_dir = 'project'
    if not os.path.exists(project_dir):
        return []
    
    projects = []
    for item in os.listdir(project_dir):
        item_path = os.path.join(project_dir, item)
        if os.path.isdir(item_path):
            summary_file = os.path.join(item_path, 'analysis_summary.json')
            if os.path.exists(summary_file):
                projects.append(item)
    
    return sorted(projects)

def main():
    """主函數"""
    print("=" * 60)
    print("專案報告生成器")
    print("=" * 60)
    
    # 列出可用專案
    projects = list_available_projects()
    
    if not projects:
        print("錯誤: 沒有找到任何已分析的專案")
        print("請先執行 1.pcap_to_json.py 和 2.tshark.py 進行分析")
        return
    
    print("\n可用的專案:")
    for i, project in enumerate(projects, 1):
        print(f"  {i}. {project}")
    
    # 讓使用者選擇專案
    print()
    print("選項:")
    print("  - 輸入專案編號: 生成單一專案報告")
    print("  - 輸入專案代號: 生成指定專案報告")
    print("  - 輸入 'all': 生成所有專案報告")
    print()
    
    choice = input("請選擇: ").strip()
    
    # 判斷是否生成所有報告
    if choice.lower() == 'all':
        print("\n正在生成所有專案報告...")
        success_count = 0
        
        for project_code in projects:
            output_file = f"{project_code}_report.png"
            print(f"\n處理: {project_code}")
            if generate_report_image(project_code, output_file):
                success_count += 1
        
        print(f"\n✅ 完成! 成功生成 {success_count}/{len(projects)} 個報告")
        return
    
    # 判斷輸入是編號還是專案代號
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(projects):
            project_code = projects[idx]
        else:
            print("錯誤: 無效的專案編號")
            return
    else:
        project_code = choice
    
    # 詢問輸出檔名
    default_output = f"{project_code}_report.png"
    output_file = input(f"請輸入輸出檔名 (預設: {default_output}): ").strip()
    
    if not output_file:
        output_file = default_output
    
    # 確保副檔名為 .png
    if not output_file.lower().endswith('.png'):
        output_file += '.png'
    
    # 生成報告
    print()
    print("正在生成報告...")
    if generate_report_image(project_code, output_file):
        print(f"\n✅ 成功! 報告已儲存為: {output_file}")
    else:
        print("\n❌ 報告生成失敗")

if __name__ == "__main__":
    main()
