""" 
Sample log generator — for testing the Cyber Defense Arsenal only.

Writes realistic-looking but synthetic log lines to data/sample.log so 
you can see the Pattern Engine and Dashboard react without needing a 
real attacker or real production logs. Safe to run anytime.

Usage: 
python3 test/sample_log_generator.py 
"""

import os 
import random 
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) 
SAMPLE_LOG = os.path.join(BASE_DIR, "data", "sample.log")

NORMAL_LINES = [ 
    "sshd[1021]: Accepted password for deploy from 10.0.0.5 port 51322 ssh2", 
    "nginx: 10.0.0.7 - - \"GET /index.html HTTP/1.1\" 200", 
    "sshd[1044]: Connection closed by 10.0.0.5 port 51322", 
    "nginx: 10.0.0.9 - - \"GET /api/health HTTP/1.1\" 200", 
]

SUSPICIOUS_LINES = [ 
    "sshd[1055]: Failed password for root from 203.0.113.{ip} port 41112 ssh2", 
    "sshd[1056]: Failed password for invalid user admin from 203.0.113.{ip} port 41113 ssh2", 
    "nginx: 198.51.100.{ip} - - \"GET /index.php?id=1' OR 1=1-- HTTP/1.1\" 403", 
    "nginx: 198.51.100.{ip} - - \"GET /search?q=<script>alert(1)</script> HTTP/1.1\" 403", 
    "nginx: 198.51.100.{ip} - - \"GET /../../etc/passwd HTTP/1.1\" 403", 
    "nginx: 198.51.100.{ip} - - \"GET /.env HTTP/1.1\" 404", 
    "nginx: 198.51.100.{ip} - - \"GET /shell.php?cmd=;rm -rf /tmp HTTP/1.1\" 403", 
]


def main(): 
    os.makedirs(os.path.dirname(SAMPLE_LOG), exist_ok=True) 
    print(f"Writing synthetic test traffic to {SAMPLE_LOG}") 
    print("Mostly normal traffic, with some suspicious lines mixed in (~1 in 4).") 
    print("Press Ctrl+C to stop.\n")

    with open(SAMPLE_LOG, "a") as f:
        try:
            while True:
                if random.random() < 0.25:
                    line = random.choice(SUSPICIOUS_LINES).format(ip=random.randint(1, 254))
                else:
                    line = random.choice(NORMAL_LINES)
                f.write(line + "\n")
                f.flush()
                print(line)
                time.sleep(random.uniform(0.5, 2.0))
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__": 
    main()
