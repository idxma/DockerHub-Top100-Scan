import os
import requests
import subprocess
import json
import logging
from collections import defaultdict

# ログ設定
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# DockerHubの上位100のイメージを取得する
def get_top_100_images():
    url = "https://hub.docker.com/v2/repositories/library/?page_size=100"
    response = requests.get(url)
    data = response.json()
    images = [result['name'] for result in data['results']]
    return images

# DockerHubにログインする
def docker_login():
    username = input("DockerHub Username: ")
    password = input("DockerHub Password: ")
    
    result = subprocess.run(['docker', 'login', '--username', username, '--password-stdin'], input=password, text=True, capture_output=True)
    if result.returncode != 0:
        logging.error(f"Failed to login to DockerHub: {result.stderr}")
        return False
    return True

# Dockleでスキャンを行い、結果を解析する
def scan_image(image):
    result = subprocess.run(['dockle', '-f', 'json', image], capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        logging.error(f"JSONDecodeError: {e}")
        logging.error(f"Dockle output: {result.stdout}")
        return {}

# スキャン結果を解析して脆弱性の数を集計する
def parse_scan_results(scan_output):
    counts = defaultdict(int)
    details = []
    for issue in scan_output.get('details', []):
        level = issue.get('level')
        if level:
            counts[level] += 1
            details.append(issue)
    return counts, details

# メイン処理
def main():
    if not docker_login():
        logging.error("DockerHubへのログインに失敗しました。認証情報を確認してください。")
        return
    
    images = get_top_100_images()
    total_counts = defaultdict(int)
    all_details = []
    
    for index, image in enumerate(images, start=1):
        logging.info(f"Scanning image {index}/{len(images)}: {image}")
        scan_output = scan_image(image)
        counts, details = parse_scan_results(scan_output)
        for level, count in counts.items():
            total_counts[level] += count
        all_details.extend(details)
        logging.info(f"Completed scanning image {index}/{len(images)}: {image}")
    
    logging.info("脆弱性の数（Dockleの5段階のレベルに合わせて集計）:")
    for level in ['FATAL', 'WARN', 'INFO', 'SKIP', 'PASS']:
        logging.info(f"{level}: {total_counts[level]}")
    
    logging.info("脆弱性の詳細:")
    for detail in all_details:
        logging.info(f"Level: {detail.get('level')}, Title: {detail.get('title')}, Description: {detail.get('description')}")

if __name__ == "__main__":
    main()
