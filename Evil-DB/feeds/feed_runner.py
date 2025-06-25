import requests
import sqlite3
from datetime import datetime
import os
import sys
print("==== FEED RUNNER DEBUG ====")
print("cwd:", os.getcwd())
print("script dir:", os.path.dirname(os.path.abspath(__file__)))
print("DB_PATH:", os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../db/threats.db")))
print("user:", os.getuid() if hasattr(os, "getuid") else "windows?")
print("python:", sys.executable)
print("===========================")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "db", "threats.db")

def insert_ip(ip, category, source, severity="high", notes=""):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT OR IGNORE INTO threat_indicators (type, value, category, source, first_seen, severity, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "ip",
            ip,
            category,
            source,
            datetime.utcnow().strftime("%Y-%m-%d"),
            severity,
            notes
        ))
        conn.commit()
    except sqlite3.DatabaseError as e:
        print(f"❌ DB error while inserting {ip}: {e}")
    finally:
        conn.close()


def get_feed_lines(url):
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith("#")]
    except requests.RequestException as e:
        print(f"❌ Failed to fetch {url}: {e}")
        return []


def parse_feed_ips(text, split_on=None, col=0):
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if split_on:
            fields = line.strip().split(split_on)
            if len(fields) > col:
                yield fields[col].strip()
        else:
            yield line.strip()


def abusech():
    print("💀 Abuse.ch Feodo Tracker...")
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    for ip in get_feed_lines(url):
        insert_ip(ip, "malware", "abusech_feodo", "high", "Feodo C2")


def emerging_threats():
    print("🚨 Emerging Threats Compromised...")
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    for ip in get_feed_lines(url):
        insert_ip(ip, "compromised", "emerging_threats", "high", "Compromised Host")


def spamhaus_drop():
    print("🛑 Spamhaus DROP...")
    url = "https://www.spamhaus.org/drop/drop.txt"
    text = "\n".join(get_feed_lines(url))
    for ip in parse_feed_ips(text):
        insert_ip(ip.split(";")[0].strip(), "spam", "spamhaus_drop", "high", "Spamhaus DROP")


def alienvault_otx():
    print("👽 AlienVault OTX...")
    url = "https://reputation.alienvault.com/reputation.generic"
    text = "\n".join(get_feed_lines(url))
    for ip in parse_feed_ips(text):
        insert_ip(ip.split("#")[0].strip(), "malicious", "alienvault_otx", "medium", "AlienVault OTX bad IP")


def cisco_talos():
    print("🦾 Cisco Talos Intelligence...")
    url = "https://talosintelligence.com/documents/ip-blacklist"
    for ip in get_feed_lines(url):
        insert_ip(ip, "malicious", "cisco_talos", "high", "Cisco Talos blacklist")


def openphish():
    print("🎣 OpenPhish...")
    url = "https://openphish.com/feed.txt"
    for ip in get_feed_lines(url):
        insert_ip(ip, "phishing", "openphish", "high", "OpenPhish Indicator")


def firehol_level1():
    print("🔥 FireHOL...")
    for ip in get_feed_lines("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"):
        insert_ip(ip, "malicious", "firehol_level1", "high", "Auto-imported")


def blocklist_de():
    print("💣 blocklist.de...")
    for ip in get_feed_lines("https://lists.blocklist.de/lists/all.txt"):
        insert_ip(ip, "ssh_brute", "blocklist_de", "medium", "Aggressive brute force")


def artillery_banlist():
    print("🛡️  Artillery banlist...")
    for ip in get_feed_lines("https://raw.githubusercontent.com/trustedsec/artillery/master/banlist.txt"):
        insert_ip(ip, "honeypot", "artillery", "medium", "Honeypot caught")


def malwaredomainlist():
    print("🦠 MalwareDomainList...")
    lines = get_feed_lines("http://www.malwaredomainlist.com/hostslist/hosts.txt")
    for line in lines:
        parts = line.split()
        if len(parts) >= 2:
            insert_ip(parts[0], "malware", "malwaredomainlist", "medium", "Malware-serving domain")


def ciarmy():
    print("🪖 CIArmy...")
    for ip in get_feed_lines("http://cinsscore.com/list/ci-badguys.txt"):
        insert_ip(ip, "scanner", "ciarmy", "medium", "Suspicious scanning IP")


def tor_exit_nodes():
    print("🧅 Tor Exit Nodes...")
    for ip in get_feed_lines("https://check.torproject.org/torbulkexitlist"):
        insert_ip(ip, "tor", "tor_exit", "low", "Tor exit node")


def blocklistpro():
    print("🧨 Blocklist Pro Threat Feed...")
    url = "https://blocklistpro.com/downloads/BlocklistPro.txt"
    for ip in get_feed_lines(url):
        insert_ip(ip, "malicious", "blocklistpro", "high", "BlocklistPro bad IP")


def sans_dshield():
    print("⚔️ SANS DShield Suspicious IPs...")
    url = "https://www.dshield.org/ipsascii.html?limit=10000"
    for ip in get_feed_lines(url):
        insert_ip(ip, "suspicious", "sans_dshield", "medium", "DShield Suspicious IP")


def abusech_sslbl():
    print("🔒 Abuse.ch SSL Blacklist...")
    url = "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"
    for ip in get_feed_lines(url):
        insert_ip(ip, "malicious", "abusech_sslbl", "high", "SSL Blacklist")


def cybercrime_tracker():
    print("💀 CyberCrime Tracker...")
    url = "https://cybercrime-tracker.net/all.php"
    for ip in get_feed_lines(url):
        insert_ip(ip, "malicious", "cybercrime_tracker", "high", "Cybercrime Tracker bad IP")


def urlhaus():
    print("🦠 Abuse.ch URLHaus Payloads...")
    url = "https://urlhaus.abuse.ch/downloads/text_online/"
    for ip in get_feed_lines(url):
        insert_ip(ip, "malicious", "abusech_urlhaus", "high", "URLHaus bad IP")


def run_all_feeds():
    print("🚀 Starting EvilWatch Feed Importer")
    firehol_level1()
    blocklist_de()
    artillery_banlist()
    malwaredomainlist()
    ciarmy()
    tor_exit_nodes()
    abusech()
    emerging_threats()
    spamhaus_drop()
    alienvault_otx()
    cisco_talos()
    openphish()
    blocklistpro()
    sans_dshield()
    abusech_sslbl()
    cybercrime_tracker()
    urlhaus()
    print("✅ Done.")


if __name__ == "__main__":
    run_all_feeds()
