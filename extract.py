import glob
import os
import json

def generate_markdown_report():
    # 创建或清空 markdown 文件
    with open('vulnerability_report.md', 'w', encoding='utf-8') as md_file:
        # 写入表头
        md_file.write("# Android Vulnerability Report\n\n")
        md_file.write("| Package | OSV-ID | CVE | Severity | Description | References |\n")
        md_file.write("|---------|---------|-----|----------|-------------|------------|\n")

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
                        
                        # 获取参考链接并用空格隔开
                        references = vuln.get('references', [])
                        ref_links = []
                        for idx, ref in enumerate(references, start=1):
                            if isinstance(ref, dict) and 'url' in ref:
                                ref_links.append(f'[{idx}]({ref["url"]})')
                            elif isinstance(ref, str):
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
                        
                        entry = (package_str, osv_id, cve_str, severity_formatted, description, ref_str)
                        
                        if entry not in unique_entries:
                            unique_entries.add(entry)
                            md_file.write(f"| {package_str} | {osv_id} | {cve_str} | {severity_formatted} | {description} | {ref_str} |\n")
            
            except Exception as e:
                print(f"Error processing {result_file}: {str(e)}")

    print("Markdown report generated: vulnerability_report.md")

def main():
    try:
        generate_markdown_report()
    except FileNotFoundError:
        print("Error: repo.list file not found")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()