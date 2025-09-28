import csv
import ipaddress
import sys
import time
import os
import requests
from collections import defaultdict, Counter
from datetime import datetime

# =============================
# Настройки
# =============================
IPINFO_TOKENS = [
    "ваш_ipinfo_токен_1",
    "ваш_ipinfo_токен_2",
]

ABUSEIPDB_TOKENS = [
    "ваш_abuseipdb_ключ_1",
    "ваш_abuseipdb_ключ_2",
]

# FireHOL: только рабочие списки (без sslbl)
FIREHOL_LISTS = [
    "firehol_level1.netset",
    "firehol_level2.netset",
    "firehol_level3.netset",
    "feodo.ipset",
    "bruteforceblocker.ipset"
]

FIREHOL_GITHUB_BASE = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/"
CACHE_DIR = "firehol_cache"

# URL других источников
BLOCKLIST_URL = "https://lists.blocklist.de/lists/all.txt"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
ET_COMPROMISED_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

# Проверка настроек
if not IPINFO_TOKENS or IPINFO_TOKENS == ["ваш_ipinfo_токен_1"]:
    print("❌ Укажите IPINFO_TOKENS!")
    sys.exit(1)
if not ABUSEIPDB_TOKENS or ABUSEIPDB_TOKENS == ["ваш_abuseipdb_ключ_1"]:
    print("❌ Укажите ABUSEIPDB_TOKENS!")
    sys.exit(1)

IPINFO_URL = "https://api.ipinfo.io/lite/{}/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

current_ipinfo_token = 0
current_abuse_token = 0
asn_cache = {}
abuse_cache = {}

# =============================
# FireHOL: загрузка и проверка с CIDR
# =============================
def load_cidr_list(filepath):
    cidrs = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '/' not in line:
                        line = line + '/32'
                    try:
                        ipaddress.IPv4Network(line, strict=False)
                        cidrs.append(line)
                    except:
                        continue
    except Exception as e:
        print(f"⚠️ Ошибка загрузки {filepath}: {e}")
    return cidrs

def ip_in_cidr_list(ip_str, cidr_list):
    try:
        ip = ipaddress.IPv4Address(ip_str)
        for cidr in cidr_list:
            if ip in ipaddress.IPv4Network(cidr, strict=False):
                return True
    except:
        pass
    return False

def download_firehol_list(list_name):
    url = FIREHOL_GITHUB_BASE + list_name
    os.makedirs(CACHE_DIR, exist_ok=True)
    file_path = os.path.join(CACHE_DIR, list_name)

    print(f"    Загрузка: {url}")
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
            print(f"    Сохранено: {file_path}")
            return load_cidr_list(file_path)
        else:
            print(f"    Ошибка HTTP: {response.status_code}")
    except Exception as e:
        print(f"    Исключение: {e}")
    return []

def ask_firehol():
    print("\n" + "="*60)
    print("🔍 FireHOL Integration")
    print("Проверка по агрегированным блоклистам (GitHub, с CIDR)")
    print("Общий объём: ~10 МБ")
    choice = input("Выполнить проверку по FireHOL? [y/N]: ").strip().lower()
    if choice not in ('y', 'yes', '1'):
        return None

    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_files = [f for f in os.listdir(CACHE_DIR) if f in FIREHOL_LISTS]
    if cache_files:
        mtime = os.path.getmtime(os.path.join(CACHE_DIR, cache_files[0]))
        cache_date = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d')
        print(f"\n📁 Найдена локальная база от {cache_date}")
        update_choice = input("Использовать текущую [C] или обновить [U]? ").strip().lower()
        if update_choice.startswith('u'):
            for f in os.listdir(CACHE_DIR):
                os.remove(os.path.join(CACHE_DIR, f))
            print("🗑️ Старая база удалена.")
    else:
        print("\n📁 Локальная база не найдена. Будет загружена новая.")

    print("\n📥 Загрузка списков FireHOL...")
    firehol_sets = {}
    for name in FIREHOL_LISTS:
        print(f"  ⬇️ {name}")
        firehol_sets[name] = download_firehol_list(name)
        time.sleep(0.3)
    print("✅ FireHOL списки готовы.")
    return firehol_sets

# =============================
# Остальные источники
# =============================
def load_blocklist_de():
    ips = set()
    try:
        response = requests.get(BLOCKLIST_URL, timeout=15)
        if response.status_code == 200:
            for line in response.text.splitlines():
                ip = line.strip()
                if ip and not ip.startswith('#'):
                    try:
                        ipaddress.IPv4Address(ip)
                        ips.add(ip)
                    except:
                        continue
    except Exception as e:
        print(f"⚠️ Blocklist.de error: {e}")
    return ips

def load_feodo_original():
    ips = set()
    try:
        response = requests.get(FEODO_URL, timeout=15)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if line.startswith('#') or ',' not in line:
                    continue
                parts = line.split(',')
                if len(parts) >= 2:
                    ip = parts[1].strip('"')
                    try:
                        ipaddress.IPv4Address(ip)
                        ips.add(ip)
                    except:
                        continue
    except Exception as e:
        print(f"⚠️ Feodo error: {e}")
    return ips

def load_emerging_threats():
    ips = set()
    try:
        response = requests.get(ET_COMPROMISED_URL, timeout=15)
        if response.status_code == 200:
            for line in response.text.splitlines():
                ip = line.strip()
                if ip and not ip.startswith('#'):
                    try:
                        ipaddress.IPv4Address(ip)
                        ips.add(ip)
                    except:
                        continue
    except Exception as e:
        print(f"⚠️ ET error: {e}")
    return ips

# =============================
# ASN — опционально
# =============================
def ask_for_asn():
    choice = input("Требуется ли определение ASN, страны и имени сети? [Y/n]: ").strip().lower()
    return choice in ('', 'y', 'yes', '1')

# =============================
# Вспомогательные функции
# =============================
def update_progress(current, total, item, prefix=""):
    msg = f"{prefix}[{current}/{total}] {item}"
    sys.stdout.write("\r" + msg.ljust(80))
    sys.stdout.flush()
    if current == total:
        sys.stdout.write("\n")

def get_network_24(ip_str):
    try:
        ip = ipaddress.IPv4Address(ip_str.strip())
        if ip.is_private:
            return None
        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return str(network.network_address)
    except Exception:
        return None

def get_asn_for_subnet(subnet):
    global current_ipinfo_token
    for _ in range(len(IPINFO_TOKENS)):
        token = IPINFO_TOKENS[current_ipinfo_token]
        url = IPINFO_URL.format(subnet) + f"?token={token}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                raw_asn = data.get("asn", "N/A")
                asn = raw_asn[2:] if raw_asn.startswith("AS") else raw_asn
                as_name = data.get("as_name", "N/A")
                cc = data.get("country_code", "N/A")
                return {'asn': asn, 'as_name': as_name, 'cc': cc}
            elif response.status_code == 429:
                current_ipinfo_token = (current_ipinfo_token + 1) % len(IPINFO_TOKENS)
                time.sleep(1)
                continue
            else:
                break
        except Exception:
            current_ipinfo_token = (current_ipinfo_token + 1) % len(IPINFO_TOKENS)
            time.sleep(1)
            continue
    return {'asn': 'N/A', 'as_name': 'N/A', 'cc': 'N/A'}

def check_abuseipdb(ip):
    global current_abuse_token
    if ip in abuse_cache:
        return abuse_cache[ip]

    for _ in range(len(ABUSEIPDB_TOKENS)):
        token = ABUSEIPDB_TOKENS[current_abuse_token]
        try:
            response = requests.get(
                ABUSEIPDB_URL,
                headers={"Key": token, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json().get("data", {})
                result = {
                    "score": data.get("abuseConfidenceScore", 0),
                    "reports": data.get("totalReports", 0)
                }
                abuse_cache[ip] = result
                return result
            elif response.status_code == 429:
                current_abuse_token = (current_abuse_token + 1) % len(ABUSEIPDB_TOKENS)
                time.sleep(1)
                continue
            else:
                break
        except Exception:
            current_abuse_token = (current_abuse_token + 1) % len(ABUSEIPDB_TOKENS)
            time.sleep(1)
            continue

    result = {"score": 0, "reports": 0}
    abuse_cache[ip] = result
    return result

def get_action_and_reason(row):
    """Определяет Action и Reason по правилам."""
    ip = row['ip']
    count = row['count']
    abuse_score = row['abuse_score']
    feodo_orig = row['feodo_original']
    blocklist_de = row['blocklist_de']
    bruteforce = row.get('bruteforceblocker', 0)
    firehol_l1 = row.get('firehol_level1', 0)

    if abuse_score >= 80:
        return "block", "AbuseScore >= 80"
    elif feodo_orig == 1:
        return "block", "Feodo_Original = 1 (botnet C&C)"
    elif firehol_l1 == 1:
        return "block", "In FireHOL Level1"
    elif blocklist_de == 1:
        return "block", "SSH brute-force (BlocklistDE)"
    elif bruteforce == 1:
        return "block", "Brute-force attacker (bruteforceblocker)"
    elif abuse_score >= 70 and count >= 5:
        return "block", "Persistent attacker (AbuseScore >= 70, Count >= 5)"
    else:
        return "monitor", "Low risk — monitor"

# =============================
# Генерация HTML-отчёта
# =============================
def generate_html_report(output_file, enriched_rows, summary):
    html_path = output_file.replace('.csv', '_report.html')
    block_ips = [row['ip'] for row in enriched_rows if row['action'] == 'block']

    # Топ-10 стран
    cc_counter = Counter(row['cc'] for row in enriched_rows if row['cc'] != 'N/A')
    top_countries = cc_counter.most_common(10)
    country_labels = [item[0] for item in top_countries]
    country_data = [item[1] for item in top_countries]

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Анализ хулиганов — {datetime.now().strftime('%Y-%m-%d')}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .block {{ background-color: #ffebee; }}
        .monitor {{ background-color: #f1f8e9; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #eee; }}
        .btn {{ padding: 10px 15px; background: #4CAF50; color: white; border: none; cursor: pointer; margin-top: 10px; }}
    </style>
</head>
<body>
    <h1>🛡️ Анализ подозрительных IP-адресов</h1>
    
    <div class="summary">
        <p><b>Дата анализа:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
        <p><b>Всего IP:</b> {summary['total_ips']}</p>
        <p><b>К блокировке:</b> {summary['block_count']}</p>
        <p><b>Уникальных подсетей /24:</b> {summary['unique_subnets']}</p>
        <p><b>Топ стран:</b> {', '.join([f"{cc} ({cnt})" for cc, cnt in top_countries[:5]])}</p>
    </div>

    <canvas id="countryChart" width="600" height="300"></canvas>

    <h2>Детали</h2>
    <table>
        <thead>
            <tr>
                <th>IP</th><th>Count</th><th>AS</th><th>CC</th><th>AbuseScore</th><th>Action</th><th>Reason</th>
            </tr>
        </thead>
        <tbody>
"""
    for row in enriched_rows:
        cls = "block" if row['action'] == "block" else "monitor"
        html_content += f"""
            <tr class="{cls}">
                <td>{row['ip']}</td>
                <td>{row['count']}</td>
                <td>{row['asn']}</td>
                <td>{row['cc']}</td>
                <td>{row['abuse_score']}</td>
                <td>{row['action']}</td>
                <td>{row['reason']}</td>
            </tr>
"""

    html_content += f"""
        </tbody>
    </table>

    <button class="btn" onclick="copyBlocklist()">Скопировать IP для блокировки</button>
    <pre id="blocklist" style="display:none;">{'\n'.join(block_ips)}</pre>

    <script>
        function copyBlocklist() {{
            const text = document.getElementById('blocklist').textContent;
            navigator.clipboard.writeText(text).then(() => {{
                alert('Список IP для блокировки скопирован в буфер обмена!');
            }});
        }}

        const ctx = document.getElementById('countryChart').getContext('2d');
        new Chart(ctx, {{
            type: 'bar',
            data: {{
                labels: {country_labels},
                datasets: [{{
                    label: 'Количество атак по странам',
                    data: {country_data},
                    backgroundColor: '#4CAF50'
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{ beginAtZero: true }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"📄 HTML-отчёт сохранён: {html_path}")

# =============================
# Основная функция
# =============================
def main(input_file):
    start_time = time.time()

    use_asn = ask_for_asn()
    firehol_sets = ask_firehol()

    print("📥 Загрузка остальных источников...")
    blocklist_set = load_blocklist_de()
    feodo_orig_set = load_feodo_original()
    et_set = load_emerging_threats()

    # Чтение входного файла
    ip_counts = []
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 2:
                continue
            ip = parts[0].strip()
            try:
                count = int(parts[1].strip())
                ipaddress.IPv4Address(ip)
                ip_counts.append((ip, count))
            except (ValueError, ipaddress.AddressValueError):
                continue

    if not ip_counts:
        print("❌ Нет валидных записей.")
        return

    # /24 и Count/24
    subnet_total = defaultdict(int)
    ip_with_subnet = []
    for ip, count in ip_counts:
        subnet = get_network_24(ip)
        if subnet:
            subnet_total[subnet] += count
            ip_with_subnet.append((ip, count, subnet))

    # ASN (опционально)
    subnet_asn_map = {}
    if use_asn:
        unique_subnets = list(subnet_total.keys())
        print(f"🔍 Уникальных подсетей: {len(unique_subnets)}")
        for i, subnet in enumerate(unique_subnets, 1):
            update_progress(i, len(unique_subnets), subnet, prefix="ASN: ")
            subnet_asn_map[subnet] = get_asn_for_subnet(subnet)
            time.sleep(0.2)
    else:
        for ip, count, subnet in ip_with_subnet:
            if subnet not in subnet_asn_map:
                subnet_asn_map[subnet] = {'asn': 'N/A', 'as_name': 'N/A', 'cc': 'N/A'}

    # Проверка угроз
    total_ips = len(ip_with_subnet)
    print(f"\n🛡️ Проверка {total_ips} IP...")
    enriched_rows = []
    asn_count_total = defaultdict(int)

    for idx, (ip, count, subnet) in enumerate(ip_with_subnet, 1):
        update_progress(idx, total_ips, ip, prefix="Threats: ")
        abuse = check_abuseipdb(ip)
        in_blocklist = 1 if ip in blocklist_set else 0
        in_feodo_orig = 1 if ip in feodo_orig_set else 0
        in_et = 1 if ip in et_set else 0

        firehol_flags = {}
        if firehol_sets:
            for name in FIREHOL_LISTS:
                short_name = name.replace(".netset", "").replace(".ipset", "")
                firehol_flags[short_name] = 1 if ip_in_cidr_list(ip, firehol_sets[name]) else 0
        else:
            for name in FIREHOL_LISTS:
                short_name = name.replace(".netset", "").replace(".ipset", "")
                firehol_flags[short_name] = 0

        info = subnet_asn_map[subnet]
        asn = info['asn']
        if use_asn:
            asn_count_total[asn] += count
        else:
            asn_count_total['N/A'] += count

        row_data = {
            'ip': ip,
            'count': count,
            'subnet': subnet,
            'asn': asn,
            'as_name': info['as_name'],
            'cc': info['cc'],
            'abuse_score': abuse['score'],
            'abuse_reports': abuse['reports'],
            'feodo_original': in_feodo_orig,
            'blocklist_de': in_blocklist,
            'emerging_threats': in_et,
            **firehol_flags
        }

        action, reason = get_action_and_reason(row_data)
        row_data['action'] = action
        row_data['reason'] = reason

        enriched_rows.append(row_data)
        time.sleep(0.2)

    # Запись CSV
    output_file = input_file.rsplit('.', 1)[0] + '_1.4.csv'
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        headers = [
            'IP', 'Count', '/24', 'Count/24', 'AS', 'AS Name', 'CC', 'Count/AS',
            'AbuseScore', 'AbuseReports', 'Feodo_Original', 'BlocklistDE', 'EmergingThreats'
        ]
        if firehol_sets is not None:
            firehol_cols = [name.replace(".netset", "").replace(".ipset", "") for name in FIREHOL_LISTS]
            headers.extend(firehol_cols)
        headers.extend(['Action', 'Reason'])
        writer.writerow(headers)

        for row in enriched_rows:
            base_row = [
                row['ip'], row['count'], row['subnet'], subnet_total[row['subnet']],
                row['asn'], row['as_name'], row['cc'],
                asn_count_total[row['asn']] if use_asn else asn_count_total['N/A'],
                row['abuse_score'], row['abuse_reports'],
                row['feodo_original'], row['blocklist_de'], row['emerging_threats']
            ]
            if firehol_sets is not None:
                base_row.extend(row[col] for col in [name.replace(".netset", "").replace(".ipset", "") for name in FIREHOL_LISTS])
            base_row.extend([row['action'], row['reason']])
            writer.writerow(base_row)

    # Сводка для HTML
    summary = {
        'total_ips': len(enriched_rows),
        'block_count': sum(1 for r in enriched_rows if r['action'] == 'block'),
        'unique_subnets': len(subnet_total)
    }

    # Генерация HTML
    generate_html_report(output_file, enriched_rows, summary)

    # Время выполнения
    elapsed = time.time() - start_time
    print(f"\n✅ Готово! Результат: {output_file}")
    print(f"⏱️  Время выполнения: {elapsed:.2f} секунд")

# =============================
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python huligany1.4.py <input.txt>")
        sys.exit(1)
    main(sys.argv[1])
