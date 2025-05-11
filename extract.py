import glob
import os
import json
from datetime import datetime

def generate_markdown_report():
    # 创建或清空 markdown 文件
    with open('vulnerability_report.md', 'w', encoding='utf-8') as md_file:
        # 写入表头，增加“Date”列
        md_file.write("# Android Vulnerability Report\n\n")
        md_file.write("| Package | OSV-ID | CVE | Severity | Description | Date | References |\n")
        md_file.write("|---------|---------|-----|----------|-------------|------|------------|\n")

        # 读取 results 目录下所有 json 文件
        results_files = glob.glob('results/*.json')
        unique_entries = set()  # 用于去重
        
        for result_file in results_files:
            try:
                with open(result_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                if 'vulns' in data:
                    for vuln in data['vulns']:
                        packages = []
                        severity = 'N/A'
                        
                        if 'affected' in vuln:
                            for affected in vuln['affected']:
                                if 'package' in affected and 'name' in affected['package']:
                                    packages.append(affected['package']['name'])
                                # 从 ecosystem_specific 中获取 severity
                                if 'ecosystem_specific' in affected and 'severity' in affected['ecosystem_specific']:
                                    severity = affected['ecosystem_specific']['severity']
                            
                        # 去重 package 列表
                        packages = list(set(packages))  
                        package_str = ', '.join(packages) if packages else 'N/A'
                        
                        osv_id = vuln.get('id', 'N/A')
                        cve_ids = [alias for alias in vuln.get('aliases', []) if alias.startswith('CVE-')]
                        cve_str = ', '.join(cve_ids) if cve_ids else 'N/A'
                        description = vuln.get('details', vuln.get('summary', 'N/A')).replace('\n', ' ').replace('|', '\|')
                        
                        # 提取日期信息
                        # 优先使用 'published' 日期，其次是 'modified' 日期
                        # 通常这些日期是 ISO 格式的字符串，例如 "2023-05-17T10:00:00Z"
                        # 我们只取日期部分 YYYY-MM-DD
                        date_str = 'N/A'
                        published_date = vuln.get('published')
                        modified_date = vuln.get('modified')
                        
                        if published_date:
                            try:
                                # 解析完整的 ISO 日期时间字符串并格式化为 YYYY-MM-DD
                                date_obj = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                                date_str = date_obj.strftime('%Y-%m-%d')
                            except ValueError:
                                # 如果格式不标准，尝试直接截取前10个字符
                                if len(published_date) >= 10:
                                    date_str = published_date[:10]
                                else:
                                    date_str = published_date # 或者保持原样，如果格式未知
                        elif modified_date:
                            try:
                                date_obj = datetime.fromisoformat(modified_date.replace('Z', '+00:00'))
                                date_str = date_obj.strftime('%Y-%m-%d')
                            except ValueError:
                                if len(modified_date) >= 10:
                                    date_str = modified_date[:10]
                                else:
                                    date_str = modified_date
                        
                        # 获取参考链接并用空格隔开
                        references = vuln.get('references', [])
                        ref_links = []
                        for idx, ref in enumerate(references, start=1):
                            if isinstance(ref, dict) and 'url' in ref:
                                ref_links.append(f'[{idx}]({ref["url"]})')
                            elif isinstance(ref, str): # 有些参考直接是 URL 字符串
                                ref_links.append(f'[{idx}]({ref})')
                        ref_str = ' '.join(ref_links) if ref_links else 'N/A'
                        
                        # 根据严重程度添加颜色标记
                        severity_formatted = severity
                        if severity.lower() == 'critical':
                            severity_formatted = '**Critical** 🔴'
                        elif severity.lower() == 'high':
                            severity_formatted = '**High** 🟠'
                        elif severity.lower() == 'moderate':
                            severity_formatted = '**Moderate** 🟡'
                        elif severity.lower() == 'low':
                            severity_formatted = '**Low** 🟢'
                        
                        # 将日期添加到 entry 元组中
                        entry = (package_str, osv_id, cve_str, severity_formatted, description, date_str, ref_str)
                        
                        if entry not in unique_entries:
                            unique_entries.add(entry)
                            # 在 Markdown 表格行中添加日期
                            md_file.write(f"| {package_str} | {osv_id} | {cve_str} | {severity_formatted} | {description} | {date_str} | {ref_str} |\n")
            
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON from {result_file}: {str(e)}")
            except Exception as e:
                print(f"Error processing {result_file}: {str(e)}")

    print("Markdown report generated: vulnerability_report.md")

def main():
    try:
        # 确保 results 目录存在
        if not os.path.exists('results'):
            os.makedirs('results')
            print("Created 'results' directory. Please place your JSON files there.")
            return # 如果目录是新创建的，可能没有文件可处理，直接返回

        generate_markdown_report()
    except FileNotFoundError: # 这个异常在 glob 没有匹配到文件时不会触发，glob 会返回空列表
        print("Error: No JSON files found in the 'results' directory or the directory itself is missing.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()