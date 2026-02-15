import re

def analyze_logs(file_path):
    suspicious_ips = {}

    try:
        with open(file_path, "r") as file:
            for line in file:
                if "Failed login" in line:
                    ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                    if ip_match:
                        ip = ip_match.group()
                        suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

        print("Suspicious IP Addresses:")
        for ip, count in suspicious_ips.items():
            print(f"{ip} - {count} failed attempts")

    except FileNotFoundError:
        print("Log file not found.")

if __name__ == "__main__":
    analyze_logs("sample_logs.txt")
