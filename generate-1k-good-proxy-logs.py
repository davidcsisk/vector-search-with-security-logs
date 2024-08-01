import random
from datetime import datetime, timedelta

# Sample user agents and URLs
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
]

urls = [
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

# Function to generate a log entry
def generate_log_entry():
    ip = generate_ip()
    timestamp = generate_timestamp().strftime("%d/%b/%Y:%H:%M:%S %z")
    url = random.choice(urls)
    user_agent = random.choice(user_agents)
    status_code = 200
    size = random.randint(512, 1048576)  # Random size between 512 bytes and 1 MB
    return f'{ip} - - [{timestamp}] "GET {url} HTTP/1.1" {status_code} {size} "{url}" "{user_agent}"\n'

# Generate 1000 log entries
with open("proxy_logs_good.txt", "w") as f:
    for _ in range(1000):
        f.write(generate_log_entry())
