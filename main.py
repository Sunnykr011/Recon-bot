#!/usr/bin/env python3
"""
Advanced Telegram Reconnaissance Bot with 200+ Google Dorks
Built for vulnerability discovery and security assessment
"""

import logging
import asyncio
import time
import threading
import requests
from bs4 import BeautifulSoup
import json
from vulnerability_scanner import VulnerabilityScanner
from report_generator import ReportGenerator
from utils import split_text, validate_domain

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import telegram library (v13 compatibility)
from telegram.ext import Updater, CommandHandler, CallbackContext
from telegram import Update
import telegram
TELEGRAM_VERSION = "v13"

class ReconBot:
    def __init__(self, token):
        self.token = token
        self.scanner = VulnerabilityScanner()
        self.report_generator = ReportGenerator()
        self.active_scans = {}

    # Legacy scanning functions from original code
    def crtsh_scan(self, domain):
        """Certificate transparency subdomain discovery"""
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

    def wayback_scan(self, domain):
        """Wayback Machine URL discovery"""
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

    def sitemap_scan(self, domain):
        """Sitemap discovery and parsing"""
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

    def pastebin_scan(self, domain):
        """Pastebin content discovery"""
        try:
            res = requests.get(f"https://pastebin.com/search?q={domain}", timeout=10)
            res.raise_for_status()
        except requests.RequestException:
            return []
        
        soup = BeautifulSoup(res.text, 'html.parser')
        results = []
        for a in soup.find_all('a'):
            if hasattr(a, 'get') and a.get('href'):
                href = str(a.get('href'))
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

    def start(self, update: Update, context: CallbackContext):
        """Start command handler"""
        welcome_text = """🤖 *Advanced Recon Bot* - Bug Hunting Edition

🎯 *Available Commands:*
• `/scan <domain>` - Full reconnaissance scan
• `/dorks <domain>` - Google dork vulnerability scan
• `/quick <domain>` - Quick vulnerability check
• `/status` - Show active scans
• `/help` - Show detailed help

🔍 *Features:*
• 200+ Google dorks for vulnerability discovery
• SQL injection, XSS, and LFI detection
• Exposed files and admin panels discovery
• Smart false positive filtering
• Detailed vulnerability reports with severity scoring
• Multi-threaded scanning for efficiency

⚠️ *Usage:* `/scan example.com` or `/dorks target.com`

*Note:* This bot is for educational and authorized security testing only."""

        update.message.reply_text(welcome_text, parse_mode='Markdown')

    def help_command(self, update: Update, context: CallbackContext):
        """Help command handler"""
        help_text = """📚 *Detailed Help - Advanced Recon Bot*

🔍 **SCAN COMMANDS:**

**`/scan <domain>`**
- Complete reconnaissance scan
- Includes: subdomains, wayback URLs, sitemaps, pastebins
- Google dork vulnerability scanning
- Comprehensive security assessment

**`/dorks <domain>`**  
- Focused Google dork scanning
- 200+ vulnerability-specific dorks
- Categories: SQLi, XSS, LFI, exposed files
- Smart result validation and filtering

**`/quick <domain>`**
- Fast vulnerability check
- Essential dorks only
- Quick response for time-sensitive assessments

📊 **SCAN TYPES COVERED:**
• SQL Injection vulnerabilities
• Cross-Site Scripting (XSS)
• Local File Inclusion (LFI)
• Directory traversal
• Exposed configuration files
• Database backups and dumps
• Admin panels and login pages
• API endpoints and documentation
• Sensitive file exposure

🎯 **REPORT FEATURES:**
• CVSS-like severity scoring
• Detailed vulnerability descriptions
• Proof-of-concept URLs
• Remediation recommendations
• False positive filtering

⚠️ **IMPORTANT DISCLAIMERS:**
• Use only on domains you own or have permission to test
• Bot includes rate limiting to avoid IP blocks
• Results are for security assessment purposes only
• Always verify findings manually before reporting

Type `/scan example.com` to get started!"""

        update.message.reply_text(help_text, parse_mode='Markdown')

    def scan_command(self, update: Update, context: CallbackContext):
        """Main scan command - combines legacy + Google dorks"""
        args = context.args if hasattr(context, 'args') else []
        if not args:
            update.message.reply_text(
                "❌ Usage: `/scan <domain>`\nExample: `/scan example.com`",
                parse_mode='Markdown'
            )
            return

        domain = args[0].strip()
        if not validate_domain(domain):
            update.message.reply_text(
                "❌ Invalid domain format. Please provide a valid domain name.",
                parse_mode='Markdown'
            )
            return

        chat_id = update.message.chat_id
        
        # Check if scan already running for this domain
        if domain in self.active_scans:
            update.message.reply_text(
                f"⏳ Scan already in progress for `{domain}`\nPlease wait for completion.",
                parse_mode='Markdown'
            )
            return

        self.active_scans[domain] = True
        
        update.message.reply_text(
            f"🚀 Starting comprehensive scan for `{domain}`\n"
            f"⏱️ This may take 5-10 minutes...\n"
            f"📊 Scanning: subdomains, wayback, sitemaps, pastebins, and 200+ vulnerability dorks",
            parse_mode='Markdown'
        )

        # Run scan in thread to avoid blocking
        def run_scan():
            try:
                # Legacy reconnaissance
                legacy_results = self.run_legacy_scan(domain)
                
                # Google dork vulnerability scanning
                vuln_results = self.scanner.comprehensive_scan(domain)
                
                # Generate report
                report = self.report_generator.generate_full_report(
                    domain, legacy_results, vuln_results
                )
                
                # Send results
                self.send_scan_results(chat_id, domain, report)
                
            except Exception as e:
                logger.error(f"Scan error for {domain}: {str(e)}")
                error_msg = f"❌ Scan failed for `{domain}`\nError: {str(e)}"
                self.send_error_message(chat_id, error_msg)
            finally:
                if domain in self.active_scans:
                    del self.active_scans[domain]

        threading.Thread(target=run_scan, daemon=True).start()

    def dorks_command(self, update: Update, context: CallbackContext):
        """Google dorks only command"""
        args = context.args if hasattr(context, 'args') else []
        if not args:
            update.message.reply_text(
                "❌ Usage: `/dorks <domain>`\nExample: `/dorks example.com`",
                parse_mode='Markdown'
            )
            return

        domain = args[0].strip()
        if not validate_domain(domain):
            update.message.reply_text(
                "❌ Invalid domain format. Please provide a valid domain name.",
                parse_mode='Markdown'
            )
            return

        chat_id = update.message.chat_id
        
        update.message.reply_text(
            f"🎯 Starting Google dork scan for `{domain}`\n"
            f"🔍 Testing 200+ vulnerability-focused dorks...",
            parse_mode='Markdown'
        )

        def run_dork_scan():
            try:
                vuln_results = self.scanner.dork_scan_only(domain)
                report = self.report_generator.generate_dork_report(domain, vuln_results)
                self.send_scan_results(chat_id, domain, report)
                
            except Exception as e:
                logger.error(f"Dork scan error for {domain}: {str(e)}")
                error_msg = f"❌ Dork scan failed for `{domain}`\nError: {str(e)}"
                self.send_error_message(chat_id, error_msg)

        threading.Thread(target=run_dork_scan, daemon=True).start()

    def quick_command(self, update: Update, context: CallbackContext):
        """Quick vulnerability scan"""
        args = context.args if hasattr(context, 'args') else []
        if not args:
            update.message.reply_text(
                "❌ Usage: `/quick <domain>`\nExample: `/quick example.com`",
                parse_mode='Markdown'
            )
            return

        domain = args[0].strip()
        if not validate_domain(domain):
            update.message.reply_text(
                "❌ Invalid domain format. Please provide a valid domain name.",
                parse_mode='Markdown'
            )
            return

        chat_id = update.message.chat_id
        
        update.message.reply_text(
            f"⚡ Quick scan for `{domain}`\n🔍 Testing high-priority dorks...",
            parse_mode='Markdown'
        )

        def run_quick_scan():
            try:
                vuln_results = self.scanner.quick_scan(domain)
                report = self.report_generator.generate_quick_report(domain, vuln_results)
                self.send_scan_results(chat_id, domain, report)
                
            except Exception as e:
                logger.error(f"Quick scan error for {domain}: {str(e)}")
                error_msg = f"❌ Quick scan failed for `{domain}`\nError: {str(e)}"
                self.send_error_message(chat_id, error_msg)

        threading.Thread(target=run_quick_scan, daemon=True).start()

    def status_command(self, update: Update, context: CallbackContext):
        """Show active scans"""
        if not self.active_scans:
            update.message.reply_text("✅ No active scans running")
        else:
            active_list = "\n".join([f"• `{domain}`" for domain in self.active_scans.keys()])
            update.message.reply_text(
                f"⏳ *Active Scans:*\n{active_list}",
                parse_mode='Markdown'
            )

    def run_legacy_scan(self, domain):
        """Run legacy reconnaissance scans"""
        results = {}
        
        try:
            subdomains = self.crtsh_scan(domain)
            results['subdomains'] = subdomains
        except Exception as e:
            logger.error(f"CRT.sh scan error: {e}")
            results['subdomains'] = []

        try:
            wayback_urls = self.wayback_scan(domain)
            results['wayback'] = wayback_urls
        except Exception as e:
            logger.error(f"Wayback scan error: {e}")
            results['wayback'] = []

        try:
            sitemap_urls = self.sitemap_scan(domain)
            results['sitemap'] = sitemap_urls
        except Exception as e:
            logger.error(f"Sitemap scan error: {e}")
            results['sitemap'] = []

        try:
            pastebin_results = self.pastebin_scan(domain)
            results['pastebin'] = pastebin_results
        except Exception as e:
            logger.error(f"Pastebin scan error: {e}")
            results['pastebin'] = []

        return results

    def send_scan_results(self, chat_id, domain, report):
        """Send scan results to chat"""
        try:
            bot = telegram.Bot(token=self.token)
            for chunk in split_text(report, 4000):
                bot.send_message(chat_id=chat_id, text=chunk, parse_mode='Markdown')
        except Exception as e:
            logger.error(f"Error sending results: {e}")

    def send_error_message(self, chat_id, message):
        """Send error message to chat"""
        try:
            bot = telegram.Bot(token=self.token)
            bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown')
        except Exception as e:
            logger.error(f"Error sending error message: {e}")

def main():
    # Use provided token
    TOKEN = "8277384583:AAEfx-q85AAFtMrONM88pxS2JeknIaQ0hSg"
    
    # Create bot instance
    bot = ReconBot(TOKEN)
    
    logger.info("🚀 Advanced Recon Bot starting...")
    logger.info("✅ Bot ready with 200+ Google dorks for vulnerability discovery")
    
    # Use Updater for v13
    updater = Updater(TOKEN, use_context=True)
    dp = updater.dispatcher
    
    # Add handlers
    dp.add_handler(CommandHandler("start", bot.start))
    dp.add_handler(CommandHandler("help", bot.help_command))
    dp.add_handler(CommandHandler("scan", bot.scan_command))
    dp.add_handler(CommandHandler("dorks", bot.dorks_command))
    dp.add_handler(CommandHandler("quick", bot.quick_command))
    dp.add_handler(CommandHandler("status", bot.status_command))
    
    # Start the bot
    logger.info("🔗 Starting bot polling...")
    updater.start_polling()
    logger.info("🎯 Bot is now active and listening for commands!")
    updater.idle()

if __name__ == '__main__':
    main()