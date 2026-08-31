import paramiko
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect("82.156.224.174", username="root", password="NL!", timeout=15)

cmds = [
    "systemctl is-active mariadb",
    "mysql -uroot -p'Xf4aGbTaf!' -e \"SHOW DATABASES;\" 2>&1",
    "du -sh /var/lib/mysql/* 2>/dev/null | sort -hr | head -15",
    "ss -tlnp | grep 3306",
]

for cmd in cmds:
    print("=" * 60)
    print("CMD:", cmd.replace("Xf4aGbTaf!", "***"))
    stdin, stdout, stderr = client.exec_command(cmd, timeout=60)
    print(stdout.read().decode("utf-8", errors="replace"))

client.close()
