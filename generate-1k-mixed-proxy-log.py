import random
from datetime import datetime, timedelta

# Sample user agents and URLs
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
]

normal_urls = [
    "http://www.example.com/",
    "http://www.example.com/style.css",
    "http://www.example.com/script.js",
    "http://update.software.com/check",
    "http://update.software.com/version.xml",
    "http://cloudstorage.com/login",
    "http://cloudstorage.com/authenticate",
    "http://cloudstorage.com/files",
    "http://intranet.company.com/home",
    "http://intranet.company.com/docs/document.pdf",
]

malicious_urls = [
    "http://www.example.com/login.php?user=admin'--",
    "http://www.example.com/search?q=<script>alert('xss')</script>",
    "http://www.example.com/admin",
    "http://www.example.com/../../etc/passwd",
    "http://www.example.com/index.php?page=../../../../../../etc/passwd",
]

# Function to generate a random IP address
def generate_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

# Function to generate a random timestamp
def generate_timestamp():
    start = datetime(2024, 8, 1, 0, 0, 0)
    end = datetime(2024, 8, 2, 0, 0, 0)
    delta = end - start
    random_second = random.randint(0, int(delta.total_seconds()))
    return start + timedelta(seconds=random_second)

# Function to generate a normal log entry
def generate_normal_log_entry():
    ip = generate_ip()
    timestamp = generate_timestamp().strftime("%d/%b/%Y:%H:%M:%S %z")
    url = random.choice(normal_urls)
    user_agent = random.choice(user_agents)
    status_code = 200
    size = random.randint(512, 1048576)  # Random size between 512 bytes and 1 MB
    return f'{ip} - - [{timestamp}] "GET {url} HTTP/1.1" {status_code} {size} "{url}" "{user_agent}"\n'

# Function to generate a malicious log entry
def generate_malicious_log_entry():
    ip = generate_ip()
    timestamp = generate_timestamp().strftime("%d/%b/%Y:%H:%M:%S %z")
    url = random.choice(malicious_urls)
    user_agent = random.choice(user_agents)
    status_code = 404  # Assuming the malicious attempt is unsuccessful
    size = random.randint(512, 1048576)  # Random size between 512 bytes and 1 MB
    return f'{ip} - - [{timestamp}] "GET {url} HTTP/1.1" {status_code} {size} "{url}" "{user_agent}"\n'

# Generate 1000 log entries with 950 normal and 50 malicious
with open("proxy_logs_mixed-950good-50malicious.txt", "w") as f:
    for _ in range(950):
        f.write(generate_normal_log_entry())
    for _ in range(50):
        f.write(generate_malicious_log_entry())
