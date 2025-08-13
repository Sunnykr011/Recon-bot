import logging
import requests
from bs4 import BeautifulSoup
from telegram.ext import Updater, CommandHandler

logging.basicConfig(level=logging.INFO)

# CRT.SH scan function (integrated)
def crtsh_scan(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}"
        res = requests.get(url, timeout=10)
        res.raise_for_status()
    except requests.RequestException:
        return []
    soup = BeautifulSoup(res.text, 'html.parser')
    subdomains = set()
    for td in soup.find_all('td'):
        text = td.get_text(strip=True)
        if text.endswith(domain):
            subdomains.add(text.lower())
    return list(subdomains)

# Wayback scan function (integrated)
def wayback_scan(domain):
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json"
        res = requests.get(url, timeout=10)
        res.raise_for_status()
    except requests.RequestException:
        return []
    try:
        data = res.json()
    except ValueError:
        return []
    urls = [entry[2] for entry in data[1:]]
    return list(set(urls))

# Sitemap scan function (integrated)
def sitemap_scan(domain):
    urls = []
    for scheme in ['http://', 'https://']:
        url = f"{scheme}{domain}/sitemap.xml"
        try:
            res = requests.get(url, timeout=10)
            res.raise_for_status()
        except requests.RequestException:
            continue
        soup = BeautifulSoup(res.text, 'xml')
        for loc in soup.find_all('loc'):
            text = loc.text.strip()
            if text:
                urls.append(text)
        if urls:
            break
    return list(set(urls))

# Pastebin scan function (integrated)
def pastebin_scan(domain):
    try:
        res = requests.get(f"https://pastebin.com/search?q={domain}", timeout=10)
        res.raise_for_status()
    except requests.RequestException:
        return []
    soup = BeautifulSoup(res.text, 'html.parser')
    results = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        if href.startswith('/paste/') or href.startswith('/raw/'):
            paste_id = href.split('/')[-1]
            raw_url = f"https://pastebin.com/raw/{paste_id}"
            try:
                raw = requests.get(raw_url, timeout=5)
                raw.raise_for_status()
                text = raw.text
                if domain in text:
                    results.append(text)
            except requests.RequestException:
                continue
    return results

def split_text(text: str, max_length: int = 4000) -> list:
    return [text[i:i + max_length] for i in range(0, len(text), max_length)]

def scan(update, context):
    args = context.args
    if not args:
        update.message.reply_text("Usage: /scan <domain> (comma-separated)")
        return
    query = ' '.join(args)
    domains = [d.strip() for d in query.split(',') if d.strip()]
    all_results = []
    for domain in domains:
        findings = []
        try:
            subdomains = crtsh_scan(domain)
            if subdomains:
                findings.append("Subdomains: " + ", ".join(subdomains))
        except Exception:
            findings.append("Error in crt.sh lookup")
        try:
            history = wayback_scan(domain)
            if history:
                findings.append("Wayback URLs: " + ", ".join(history))
        except Exception:
            findings.append("Error in Wayback lookup")
        try:
            sitemaps = sitemap_scan(domain)
            if sitemaps:
                findings.append("Sitemap links: " + ", ".join(sitemaps))
        except Exception:
            findings.append("Error in sitemap lookup")
        try:
            pastes = pastebin_scan(domain)
            if pastes:
                findings.append(f"Pastebin found {len(pastes)} pastes")
        except Exception:
            findings.append("Error in Pastebin lookup")
        all_results.append(f"Results for *{domain}*:\n" + "\n".join(findings))
    response = "\n\n".join(all_results) or "No results."
    for chunk in split_text(response, 4000):
        update.message.reply_text(chunk)

def main():
    TOKEN = "YOUR_BOT_TOKEN_HERE"  # Replace with your actual Telegram Bot Token
    updater = Updater(TOKEN, use_context=True)
    dp = updater.dispatcher
    dp.add_handler(CommandHandler("scan", scan))
    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
  
