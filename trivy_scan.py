import requests
import subprocess
import re

def get_top_100_images():
    url = "https://hub.docker.com/v2/repositories/library/?page_size=100"
    response = requests.get(url)
    data = response.json()
    images = [result['name'] for result in data['results']]
    return images

def run_trivy(image):
    process = subprocess.Popen(['trivy', 'image', image], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    output = []
    for line in process.stdout:
        print(line, end='')  # リアルタイムで出力を表示
        output.append(line)
    process.wait()
    return ''.join(output)

def parse_vulnerabilities(trivy_output):
    vulnerabilities = {
        'UNKNOWN': 0,
        'LOW': 0,
        'MEDIUM': 0,
        'HIGH': 0,
        'CRITICAL': 0
    }
    for line in trivy_output.splitlines():
        for severity in vulnerabilities.keys():
            match = re.search(rf'{severity}:\s+(\d+)', line)
            if match:
                vulnerabilities[severity] += int(match.group(1))
    return vulnerabilities

def main():
    # Docker Hubにログイン
    subprocess.run(['docker', 'login'], check=True)

    images = get_top_100_images()
    total_vulnerabilities = {
        'UNKNOWN': 0,
        'LOW': 0,
        'MEDIUM': 0,
        'HIGH': 0,
        'CRITICAL': 0
    }

    for image in images:
        print(f"Scanning {image}...")
        trivy_output = run_trivy(image)
        image_vulnerabilities = parse_vulnerabilities(trivy_output)
        for severity, count in image_vulnerabilities.items():
            total_vulnerabilities[severity] += count

    print("Total vulnerabilities found:")
    for severity, count in total_vulnerabilities.items():
        print(f"{severity}: {count}")

if __name__ == "__main__":
    main()
