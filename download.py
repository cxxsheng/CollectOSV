import requests
import json
import threading
from concurrent.futures import ThreadPoolExecutor
import os

# 读取repo.list文件
def read_repo_list(filename):
    repos = []
    with open(filename, 'r') as file:
        for line in file:
            # 去除空白字符并忽略空行
            line = line.strip()
            if line and not line.startswith("#"):
                repos.append(line)
    return repos

def query_vulnerabilities(repo_name):
    url = "https://api.osv.dev/v1/query"
    data = {
        "package": {
            "name": repo_name,
            "ecosystem": "Android"
        }
    }
    
    try:
        response = requests.post(url, json=data)
        response.raise_for_status()  # 检查响应状态
        result = response.json()
        
        # 如果结果不为空,写入文件
        if result and result.get('vulns'):
            # 创建results目录(如果不存在)
            os.makedirs('results', exist_ok=True)
            # 将repo名称中的/替换为_,避免文件路径问题
            safe_filename = repo_name.replace('/', '_') + '.json'
            filepath = os.path.join('results', safe_filename)
            
            with open(filepath, 'w') as f:
                json.dump(result, f, indent=2)
                print(f"Results for {repo_name} written to {filepath}")
        
        return result
    except requests.exceptions.RequestException as e:
        print(f"Error querying {repo_name}: {e}")
        return None

def process_repo(repo):
    print(f"\nQuerying vulnerabilities for: {repo}")
    result = query_vulnerabilities(repo)
    if result:
        print(f"Found vulnerabilities for: {repo}")

def main():
    # 读取repo.list文件
    try:
        repos = read_repo_list('repo.list')
        
        # 使用线程池处理查询
        with ThreadPoolExecutor(max_workers=10) as executor:
            # 提交所有任务到线程池
            futures = [executor.submit(process_repo, repo) for repo in repos]
            
            # 等待所有任务完成
            for future in futures:
                future.result()
                
        print("\nAll queries completed!")
            
    except FileNotFoundError:
        print("Error: repo.list file not found")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()