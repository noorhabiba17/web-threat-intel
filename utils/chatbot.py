"""Smart cybersecurity chatbot — keyword scoring + question type detection."""
import re
import random
import math
from typing import Any

STOPWORDS = {"a","an","the","is","are","was","were","do","does","did","can",
             "could","will","would","shall","should","may","might","must",
             "i","you","he","she","it","we","they","me","my","your","his",
             "her","its","our","their","to","of","in","for","on","with",
             "at","by","from","as","into","through","during","before","after",
             "above","below","between","out","off","over","under","again",
             "further","then","once","here","there","when","where","why",
             "how","all","each","every","both","few","more","most","other",
             "some","such","no","nor","not","only","own","same","so","than",
             "too","very","just","because","about","also","have","has","had",
             "been","being","be","get","got","gets","tell","ask","need","know",
             "like","want","please","help","thanks","thank","what","which",
             "who","whom","this","that","these","those","am","are","was","were"}

def extract_keywords(text: str) -> list[str]:
    """Extract meaningful keywords from text."""
    words = re.findall(r"[a-zA-Z][a-zA-Z0-9#+.-]{1,}", text.lower())
    return [w for w in words if w not in STOPWORDS and len(w) > 1]


def tokenize_question(text: str) -> tuple[str, str]:
    """Detect question type and extract target."""
    t = text.lower().strip()
    qtype: str = "statement"
    target: str = ""
    patterns = [
        (r"^(what|who)\s+(is|are|was|were|does)\s+(.+?)\??$", "what_is", 3),
        (r"^(what|who)\s+(is|are|was)\s+(a|an|the)\s+(.+?)\??$", "what_is", 4),
        (r"^(what)\s+(do|does)\s+(.+?)\s+(mean|stand for)\??$", "what_is", 3),
        (r"^how\s+(to|do|can|does|would)\s+(.+?)\??$", "how_to", 2),
        (r"^how\s+(.+?)\??$", "how_to", 1),
        (r"^(explain|describe|define)\s+(.+?)\??$", "explain", 2),
        (r"^(tell|show|give)\s+(me\s+)?(about\s+)?(.+?)\??$", "explain", 4),
        (r"^(can|could|will|would)\s+(you\s+)?(.+?)\??$", "request", 3),
        (r"^why\s+(do|does|is|are|would|should)\s+(.+?)\??$", "why", 2),
        (r"^(what|which)\s+(are|is)\s+(the\s+)?(best|good|safe|strong|top)\s+(.+?)\??$", "recommend", 5),
        (r"^(what|when)\s+(should|do)\s+(i|you|we)\s+(.+?)\??$", "advice", 4),
    ]
    for pat, qt, grp in patterns:
        m = re.match(pat, t)
        if m:
            target = m.group(grp).strip()
            return qt, target
    return qtype, ""

# ── Topic: (keywords, responses, aliases) ──
# keywords: words/phrases that indicate this topic (higher weight = more specific)
# aliases: alternative names for the topic (what_is lookup)
# responses: answer templates

TOPICS = [
    # ─── Phishing ───
    {
        "name": "phishing",
        "keywords": {
            "phishing": 3, "phish": 3, "spear phishing": 4, "spearphishing": 4,
            "email scam": 3, "fake email": 3, "phishing link": 3, "phishing email": 3,
            "deceptive email": 3, "email fraud": 3, "credential theft": 3,
            "url phishing": 2, "web phishing": 2, "phishing attack": 3,
            "clone phishing": 4, "whaling": 4, "CEO fraud": 4,
        },
        "aliases": ["phishing", "email scam", "phishing attack", "spear phishing"],
        "responses": [
            "Phishing is when attackers send fake messages (email, SMS, social media) pretending to be a trusted company or person to steal your passwords, credit card numbers, or install malware. **Red flags:** urgent language, generic greetings ('Dear Customer'), mismatched sender address, suspicious links, requests for personal info.",
            "**6 signs of phishing:** 1) Urgency/threats ('act now or account closed') 2) Generic greeting 3) Spoofed sender address 4) Suspicious links (hover first!) 5) Requests for passwords/OTPs 6) Poor grammar. When in doubt, contact the company directly through their official website — not the link in the message.",
            "**Did you know?** Modern phishing kits can clone real websites almost perfectly, including HTTPS certificates. Always type the website URL yourself instead of clicking email links. Enable 2FA to protect yourself even if credentials are stolen.",
        ],
    },
    # ─── Spam ───
    {
        "name": "spam",
        "keywords": {
            "spam": 3, "junk mail": 3, "bulk email": 2, "unsolicited": 2,
            "spam message": 3, "spam filter": 2, "spam call": 2,
        },
        "aliases": ["spam", "junk mail", "spam message"],
        "responses": [
            "Spam is unwanted bulk messages — usually advertising, scams, or malware delivery. Don't reply, don't click links, just mark as spam and delete. Most email services filter spam automatically but some slip through.",
            "Spam often promises prizes, lotteries, miracle cures, or 'get rich quick' schemes. If it sounds too good to be true, it is. Never buy from spam — you'll lose money and your email will be sold to more spammers.",
        ],
    },
    # ─── Passwords ───
    {
        "name": "passwords",
        "keywords": {
            "password": 3, "passwords": 3, "passphrase": 3, "login": 1,
            "credentials": 2, "password manager": 4, "password strength": 3,
            "strong password": 3, "password reuse": 3, "password security": 3,
            "password leak": 3, "password breach": 3, "password reset": 2,
            "create password": 3, "choose password": 3, "make password": 3,
            "password generator": 3, "password safe": 3,
        },
        "aliases": ["password", "passphrase", "password security", "password manager"],
        "responses": [
            "**Strong password rules:** 1) 14+ characters 2) Mix uppercase, lowercase, numbers, symbols 3) No dictionary words or personal info 4) Unique for every account 5) Use a password manager (Bitwarden is free & open-source). A passphrase like 'correct-horse-battery-staple' is strong and memorable.",
            "**Password manager recommendations:** Bitwarden (free, open-source) — best overall. 1Password (paid) — great UX. KeePass (free, offline-only). They generate strong random passwords and fill them in for you. You only need to remember one master password.",
            "Never reuse passwords! If one site gets breached, attackers try the same email+password on banking, email, and social media (credential stuffing). A password manager makes unique passwords easy.",
        ],
    },
    # ─── 2FA / MFA ───
    {
        "name": "2fa",
        "keywords": {
            "2fa": 3, "two factor": 3, "two-factor": 3, "mfa": 3,
            "multi factor": 3, "multi-factor": 3, "authenticator": 3,
            "2 step verification": 3, "two step": 2, "security key": 3,
            "yubikey": 4, "google authenticator": 3, "authy": 3,
            "microsoft authenticator": 3, "tfa": 3,
        },
        "aliases": ["2fa", "two factor authentication", "mfa", "multi-factor authentication"],
        "responses": [
            "Two-Factor Authentication (2FA) adds a second layer beyond your password. Even if someone steals your password, they can't log in without the second factor. **Enable it everywhere that offers it — especially email, banking, and social media.**",
            "**Best 2FA methods ranked:** 1) Hardware security key (YubiKey) — most secure 2) Authenticator app (Google Authenticator, Authy, Microsoft Authenticator) 3) SMS text codes — better than nothing, but vulnerable to SIM swapping. Never use email-based 2FA.",
        ],
    },
    # ─── OTP ───
    {
        "name": "otp",
        "keywords": {
            "otp": 3, "one time password": 3, "one time pin": 3,
            "one time code": 3, "verification code": 2, "2fa code": 2,
            "sms code": 2, "otp code": 3, "otp scam": 3,
        },
        "aliases": ["otp", "one time password"],
        "responses": [
            "An OTP (One-Time Password) is a temporary code sent to your phone or email. **Never share it with anyone — EVER.** Not with 'support', not with a 'bank employee', not with anyone. Legitimate companies will never ask for your OTP.",
            "OTP theft is a common social engineering tactic. Scammers call pretending to be your bank and ask for the code 'to verify your account'. Hang up — it's a scam. Your real bank already has access to your account without needing your OTP.",
        ],
    },
    # ─── Hacked / Compromised ───
    {
        "name": "hacked",
        "keywords": {
            "hacked": 3, "hack": 2, "compromised": 3, "breach": 3,
            "data breach": 3, "infiltrated": 3, "takeover": 3,
            "account hacked": 3, "email hacked": 3, "email compromised": 3,
            "password stolen": 3, "identity theft": 3, "account takeover": 3,
            "unauthorized access": 3, "login alert": 2, "suspicious activity": 2,
        },
        "aliases": ["hacked account", "compromised account", "data breach"],
        "responses": [
            "**If you've been hacked, act immediately:** 1) Change your password from a different device 2) Sign out all sessions (most services have 'sign out everywhere') 3) Enable 2FA 4) Check for email forwarding rules attackers may have added 5) Check login history for unknown locations 6) Run a full antivirus scan 7) Visit our Recovery Center for step-by-step help",
            "**After a data breach:** Check haveibeenpwned.com to see what data was leaked. Change that password immediately and anywhere you reused it. Enable 2FA. Watch for phishing emails pretending to be the breached company — attackers often send follow-up scams after a breach.",
        ],
    },
    # ─── Safe Browsing ───
    {
        "name": "safe browsing",
        "keywords": {
            "browser security": 3, "safe browsing": 3, "secure browsing": 3,
            "private browsing": 2, "incognito": 2, "ad blocker": 3,
            "ublock": 3, "tracker blocker": 3, "browser extension": 2,
            "browser safety": 3, "browser protection": 3,
        },
        "aliases": ["safe browsing", "browser security", "secure browsing"],
        "responses": [
            "**Safe browsing tips:** 1) Keep your browser updated 2) Use uBlock Origin (blocks ads AND malware domains) 3) Enable HTTPS-only mode 4) Don't save passwords in browser — use a password manager 5) Clear cookies regularly 6) Use Firefox or Brave for better privacy.",
            "**Warning:** Malicious ads (malvertising) can infect your device just by loading the page — no click needed. Use an ad-blocker like uBlock Origin. Also, fake browser update alerts are a common malware delivery method.",
        ],
    },
    # ─── HTTPS / SSL ───
    {
        "name": "https",
        "keywords": {
            "https": 3, "ssl": 3, "tls": 3, "secure socket layer": 3,
            "transport layer security": 3, "padlock": 2, "ssl certificate": 2,
            "encryption": 2, "tls certificate": 2,
        },
        "aliases": ["https", "ssl", "tls", "encryption"],
        "responses": [
            "HTTPS encrypts data between your browser and the website. It prevents eavesdropping, especially on public Wi-Fi. **But remember:** HTTPS only means the connection is encrypted — it does NOT mean the site is legitimate. Phishing sites use HTTPS too.",
            "The padlock icon means the connection is private, not that the website is safe. Always check the full domain name. A site like 'https://www.secure-bank-login.xyz' is likely a phishing site despite having HTTPS.",
        ],
    },
    # ─── Malware / Virus / Ransomware ───
    {
        "name": "malware",
        "keywords": {
            "malware": 3, "virus": 3, "ransomware": 4, "trojan": 3,
            "spyware": 3, "keylogger": 3, "keylog": 3, "rootkit": 3,
            "worm": 2, "ransom": 3, "malwarebytes": 2, "windows defender": 2,
            "antivirus": 2, "virus scan": 2, "malware scan": 2,
            "remove virus": 3, "remove malware": 3, "malware infection": 3,
        },
        "aliases": ["malware", "virus", "ransomware", "trojan", "antivirus"],
        "responses": [
            "**If you suspect malware:** 1) Disconnect from the internet 2) Run a full scan with Windows Defender or Malwarebytes 3) Boot into Safe Mode and scan again 4) Change passwords from a clean device 5) If ransomware: DO NOT pay — disconnect and report to law enforcement.",
            "**Prevent malware by:** keeping everything updated (Windows, apps, drivers), not opening suspicious attachments, using uBlock Origin, avoiding pirated software (common malware vector), and running periodic antivirus scans.",
            "Ransomware encrypts your files and demands payment. The 3-2-1 backup rule protects you: 3 copies of data, 2 different storage types, 1 copy off-site. If infected, disconnect immediately and DO NOT pay — paying doesn't guarantee you'll get your files back.",
        ],
    },
    # ─── Public Wi-Fi ───
    {
        "name": "public wifi",
        "keywords": {
            "public wifi": 3, "public wi-fi": 3, "public wi fi": 3,
            "open wifi": 2, "free wifi": 2, "hotspot": 2,
            "coffee shop wifi": 3, "airport wifi": 3, "hotel wifi": 3,
        },
        "aliases": ["public wifi", "public wi-fi", "hotspot"],
        "responses": [
            "Public Wi-Fi is risky — attackers can intercept traffic on the same network. **Protect yourself:** 1) Use a VPN (Mullvad, ProtonVPN) 2) Avoid logging into banking/email 3) Use your phone's hotspot instead 4) Ensure websites use HTTPS 5) Turn off file sharing and AirDrop.",
            "**Avoid:** logging into sensitive accounts, making purchases, or accessing work systems on public Wi-Fi without a VPN. Attackers can set up fake 'free Wi-Fi' hotspots to capture everything you do.",
        ],
    },
    # ─── VPN ───
    {
        "name": "vpn",
        "keywords": {
            "vpn": 3, "virtual private network": 3, "vpn service": 2,
            "vpn provider": 2, "best vpn": 2, "free vpn": 2,
            "mullvad": 4, "protonvpn": 4, "ivpn": 4,
        },
        "aliases": ["vpn", "virtual private network"],
        "responses": [
            "A VPN encrypts all your internet traffic and routes it through a server elsewhere. It hides your IP and protects privacy on public Wi-Fi. **Recommended:** Mullvad, ProtonVPN, IVPN (all audited, no-logs policy). Avoid free VPNs — they often sell your data.",
            "A VPN does NOT make you anonymous — the VPN provider can see your traffic. Choose a provider with a strict no-logs policy. Also, a VPN won't protect you from phishing or malware — it only encrypts your connection.",
        ],
    },
    # ─── Social Engineering ───
    {
        "name": "social engineering",
        "keywords": {
            "social engineering": 3, "pretexting": 3, "baiting": 3,
            "tailgating": 3, "shoulder surfing": 3, "social engineer": 3,
            "human hacking": 3, "manipulation": 2, "psychological trick": 2,
        },
        "aliases": ["social engineering", "pretexting", "social engineer"],
        "responses": [
            "Social engineering is manipulating people into revealing information or performing actions. **Common techniques:** 1) Pretexting — creating a fake scenario 2) Baiting — leaving infected USB drives 3) Tailgating — following into restricted areas 4) Shoulder surfing — watching you type passwords. **Defense:** Always verify identity, don't let strangers follow you in.",
        ],
    },
    # ─── Firewall ───
    {
        "name": "firewall",
        "keywords": {
            "firewall": 3, "network security": 2, "windows firewall": 3,
            "hardware firewall": 3, "software firewall": 3,
        },
        "aliases": ["firewall", "firewall security"],
        "responses": [
            "A firewall monitors and controls network traffic. Windows has a built-in firewall that's sufficient for most users — make sure it's enabled (Control Panel > Windows Defender Firewall). For extra protection, enable your router's built-in firewall too.",
        ],
    },
    # ─── Privacy / Cookies ───
    {
        "name": "privacy",
        "keywords": {
            "privacy": 2, "cookie": 2, "cookies": 2, "tracker": 2,
            "tracking": 2, "third party cookies": 3, "private": 2,
            "anonymous": 2, "incognito": 2, "duckduckgo": 3,
            "browser privacy": 3, "online privacy": 3,
        },
        "aliases": ["privacy", "online privacy", "cookies", "tracking"],
        "responses": [
            "**Privacy tips:** 1) Use Firefox or Brave browser 2) Block third-party cookies 3) Use DuckDuckGo for private searches 4) Consider a VPN 5) Limit social media sharing 6) Review app permissions 7) Incognito mode only hides browsing from local users — your ISP can still see your activity.",
            "Cookies are files websites store on your browser. Third-party cookies track you across sites for advertising. Block them in browser settings, use Privacy Badger extension, and clear cookies regularly.",
        ],
    },
    # ─── Backups ───
    {
        "name": "backup",
        "keywords": {
            "backup": 3, "backups": 3, "back up": 3, "data backup": 3,
            "cloud backup": 2, "external backup": 2, "restore": 2,
            "data loss": 2, "backup strategy": 3, "3-2-1": 4,
        },
        "aliases": ["backup", "data backup", "backups"],
        "responses": [
            "**3-2-1 backup rule:** 3 copies of your data, 2 different storage types (external drive + cloud), 1 copy off-site. Use tools like Backblaze, Duplicati, or Veeam. **Crucial:** test your restores periodically — a backup you can't restore is worthless. Protect backups from ransomware by keeping one copy offline.",
        ],
    },
    # ─── Email Security ───
    {
        "name": "email security",
        "keywords": {
            "email security": 3, "email safety": 3, "protect email": 3,
            "secure email": 3, "email privacy": 2, "email encryption": 3,
            "encrypted email": 3, "email alias": 3, "spoofing": 3,
            "email spoofing": 3, "dmarc": 4, "dkim": 4, "spf": 4,
        },
        "aliases": ["email security", "email safety", "email protection"],
        "responses": [
            "**Email security essentials:** 1) Use spam filtering 2) Never click links in unsolicited emails 3) Check the full sender address, not just the display name (display names can be faked) 4) Be suspicious of unexpected attachments (.docm, .xlsm, .js, .exe) 5) Use a separate email for sign-ups 6) Enable email aliases for different services.",
            "Email spoofing is when attackers forge the 'From' address to look like someone you trust. Modern email security (SPF, DKIM, DMARC) helps prevent this, but not all domains have them configured. Always verify surprising requests via a phone call or separate message.",
        ],
    },
    # ─── Mobile Security ───
    {
        "name": "mobile security",
        "keywords": {
            "mobile security": 3, "phone security": 3, "smartphone security": 3,
            "android security": 3, "iphone security": 3, "ios security": 3,
            "phone virus": 2, "mobile malware": 3, "app permissions": 3,
            "sideloading": 3, "apk": 2,
        },
        "aliases": ["mobile security", "phone security", "smartphone security", "android security", "iphone security"],
        "responses": [
            "**Mobile security tips:** 1) Only install apps from official stores (Play Store / App Store) 2) Keep OS and apps updated 3) Don't sideload APKs on Android 4) Review app permissions — does a flashlight app really need your contacts? 5) Use biometric lock + strong PIN 6) Beware of SMS phishing (smishing).",
        ],
    },
    # ─── Smishing ───
    {
        "name": "smishing",
        "keywords": {
            "smishing": 4, "sms phishing": 4, "text scam": 3,
            "sms scam": 3, "text message scam": 3, "sms fraud": 3,
        },
        "aliases": ["smishing", "sms phishing", "text scam"],
        "responses": [
            "Smishing is phishing via SMS. Attackers send texts with malicious links or requests for info. **Red flags:** 'Your package is waiting — click here' 'Account suspended — verify now' 'You won a prize!'. **Never click links in unsolicited texts.** Report and delete.",
        ],
    },
    # ─── Vishing ───
    {
        "name": "vishing",
        "keywords": {
            "vishing": 4, "voice phishing": 4, "phone scam": 3,
            "call scam": 3, "phone fraud": 3, "caller id spoofing": 4,
        },
        "aliases": ["vishing", "voice phishing", "phone scam"],
        "responses": [
            "Vishing is voice phishing — scammers call pretending to be your bank, IRS, Microsoft, etc. **Rules:** 1) Never give personal info over an incoming call 2) Hang up and call the official number back 3) Governments never demand payment by phone 4) Caller ID can be spoofed — don't trust it.",
        ],
    },
    # ─── AI Scams / Deepfakes ───
    {
        "name": "AI scams",
        "keywords": {
            "deepfake": 4, "ai scam": 3, "ai phishing": 3,
            "ai voice scam": 4, "deepfake voice": 4, "deepfake video": 4,
            "ai generated": 3, "ai attack": 3,
        },
        "aliases": ["deepfake", "ai scams", "ai phishing"],
        "responses": [
            "AI-powered scams are rising — deepfake voice calls imitating family members, AI-generated phishing emails with perfect grammar, and realistic fake profiles. **Defense:** Have a verbal safe word with family, be skeptical of emotional pleas, verify through a separate channel. AI text often lacks personal details or makes subtle errors.",
        ],
    },
    # ─── IoT Security ───
    {
        "name": "IoT security",
        "keywords": {
            "iot": 3, "internet of things": 3, "smart home": 2,
            "smart device": 2, "smart tv": 2, "smart speaker": 2,
            "smart camera": 2, "smart thermostat": 2, "iot security": 3,
        },
        "aliases": ["iot", "internet of things", "smart home security"],
        "responses": [
            "IoT devices (smart cameras, speakers, thermostats) are often insecure. **Secure them:** 1) Change default passwords immediately 2) Keep firmware updated 3) Put IoT on a separate Wi-Fi network 4) Disable unused features (remote access, UPnP) 5) Check manufacturer security history before buying.",
        ],
    },
    # ─── Zero Day ───
    {
        "name": "zero day",
        "keywords": {
            "zero day": 4, "0 day": 4, "zero-day": 4,
            "unpatched vulnerability": 3, "unknown vulnerability": 3,
        },
        "aliases": ["zero day", "zero-day exploit"],
        "responses": [
            "A zero-day is a vulnerability the vendor doesn't know about yet — so there's no patch. Attackers exploit them before a fix exists. **Protection:** Keep everything updated, use antivirus with behavioral detection (not just signature-based), minimize attack surface by disabling unused services.",
        ],
    },
    # ─── DDoS ───
    {
        "name": "ddos",
        "keywords": {"ddos": 3, "denial of service": 3, "botnet": 3, "dos attack": 2},
        "aliases": ["ddos", "denial of service", "botnet"],
        "responses": [
            "A DDoS (Distributed Denial of Service) attack floods a server with traffic from many computers (a botnet) to take it offline. You can help prevent botnets by securing your own devices — compromised IoT devices are often recruited into botnets.",
        ],
    },
    # ─── Social Media Safety ───
    {
        "name": "social media safety",
        "keywords": {
            "social media": 2, "facebook": 2, "instagram": 2,
            "twitter": 2, "linkedin": 2, "tiktok": 2,
            "social media safety": 3, "social media privacy": 3,
        },
        "aliases": ["social media safety", "social media privacy"],
        "responses": [
            "**Social media safety:** 1) Set profiles to private 2) Don't post travel plans in real-time 3) Limit personal info (birthday, address, phone) 4) Enable login alerts and 2FA 5) Review connected apps and revoke unused ones 6) Don't accept friend requests from strangers. What happens in Vegas stays on Facebook forever.",
        ],
    },
    # ─── General Safety Tips ───
    {
        "name": "general tips",
        "keywords": {
            "tips": 1, "advice": 1, "safety tips": 2, "stay safe": 2,
            "protect yourself": 2, "cybersecurity tips": 2, "best practices": 2,
            "how to stay safe": 2, "security tips": 2, "online safety": 2,
        },
        "aliases": ["safety tips", "cybersecurity tips", "online safety"],
        "responses": [
            "**Top 10 cybersecurity tips:** 1) Use a password manager 2) Enable 2FA everywhere 3) Keep everything updated 4) Think before you click 5) Back up data (3-2-1 rule) 6) Use a VPN on public Wi-Fi 7) Lock your screen when away 8) Never reuse passwords 9) Be skeptical of unsolicited messages 10) Trust your instincts — if it feels off, it probably is.",
            "The **golden rules of online safety:** 1) If you didn't expect it, don't click it 2) If it sounds too good to be true, it is 3) If someone creates urgency, they're manipulating you 4) When in doubt, verify through a trusted channel.",
        ],
    },
    # ─── About the System ───
    {
        "name": "about system",
        "keywords": {
            "wti": 3, "web threat intelligence": 3, "this website": 2,
            "this system": 2, "this tool": 2, "this platform": 2,
            "features": 1, "what can you do": 2,
        },
        "aliases": ["wti", "web threat intelligence", "system features"],
        "responses": [
            "**Web Threat Intelligence System** scans URLs, emails, and SMS for phishing, spam, and malware using a hybrid ML + rules engine. Features: threat scanning, PDF reports, AI chatbot, recovery center, safety tips, full scan history with search & filter. All data is private to your account.",
        ],
    },
    # ─── Greetings ───
    {
        "name": "greeting",
        "keywords": {"hello": 1, "hi": 1, "hey": 1, "greetings": 1, "howdy": 1},
        "aliases": [],
        "responses": [
            "Hello! I'm your cybersecurity assistant. Ask me about phishing, passwords, 2FA, malware, safe browsing — I can help with all things online security!",
            "Hi there! Ready to help you stay safe online. What would you like to know about cybersecurity?",
        ],
    },
    # ─── Thanks ───
    {
        "name": "thanks",
        "keywords": {"thanks": 1, "thank": 1, "thank you": 1, "thx": 1},
        "aliases": [],
        "responses": [
            "You're welcome! Stay safe out there.",
            "Glad I could help! Remember: think before you click.",
            "Anytime! Come back if you have more questions.",
        ],
    },
    # ─── Bye ───
    {
        "name": "bye",
        "keywords": {"bye": 1, "goodbye": 1, "see you": 1, "cya": 1, "farewell": 1},
        "aliases": [],
        "responses": [
            "Goodbye! Stay secure and don't hesitate to ask if you need anything.",
            "Take care! Remember: a moment of caution saves hours of recovery.",
        ],
    },
    # ─── Recovery / What to do after clicking ───
    {
        "name": "recovery",
        "keywords": {
            "recovery": 3, "clicked": 2, "already clicked": 3, "i clicked": 3,
            "i fell for": 3, "i fell": 2, "scammed": 3, "got scammed": 3,
            "entered password": 3, "gave password": 3, "entered details": 3,
            "recover": 2, "recovery center": 3, "recovery plan": 3,
        },
        "aliases": ["recovery", "after clicking", "recovery center", "got scammed"],
        "responses": [
            "**If you clicked a phishing link or entered your credentials:** 1) Change that password immediately 2) Enable 2FA if you haven't 3) Check for suspicious account activity 4) Run an antivirus scan 5) If you entered financial info, contact your bank 6) Visit our Recovery Center for a detailed checklist. Don't panic — acting fast limits the damage.",
        ],
    },
    # ─── Identity Theft ───
    {
        "name": "identity theft",
        "keywords": {
            "identity theft": 3, "identity fraud": 3, "stolen identity": 3,
            "credit freeze": 3, "credit report": 2,
        },
        "aliases": ["identity theft", "identity fraud"],
        "responses": [
            "**If your identity is stolen:** 1) Place a fraud alert on your credit reports (Equifax, Experian, TransUnion) 2) Consider a credit freeze (free, prevents new accounts in your name) 3) File a report with the FTC at IdentityTheft.gov 4) Check your bank and credit card statements 5) Change passwords and enable 2FA on financial accounts.",
        ],
    },
    # ─── Ad Blockers ───
    {
        "name": "ad blocker",
        "keywords": {
            "ad blocker": 3, "adblock": 3, "ad block": 3,
            "ublock origin": 4, "ublock": 3, "adblock plus": 3,
            "block ads": 2,
        },
        "aliases": ["ad blocker", "ublock", "adblock"],
        "responses": [
            "uBlock Origin is the best ad blocker — it's free, open-source, and uses minimal memory. It blocks ads, trackers, and known malware domains. Available for Chrome, Firefox, Edge, and Brave. Avoid AdBlock Plus which allows 'acceptable ads' by default.",
        ],
    },
    # ─── Browser Choice ───
    {
        "name": "browser choice",
        "keywords": {
            "best browser": 2, "secure browser": 3, "privacy browser": 3,
            "which browser": 2, "browser recommend": 2, "firefox": 2,
            "brave": 2, "chrome": 1,
        },
        "aliases": ["browser", "secure browser", "privacy browser"],
        "responses": [
            "**For privacy & security:** Firefox (with uBlock Origin) or Brave (built-in blockers). Both are fast, respect privacy, and have strong security features. Chrome works fine but Google's business is data collection. Avoid Edge if privacy matters.",
        ],
    },
    # ─── Secure Messaging ───
    {
        "name": "secure messaging",
        "keywords": {
            "secure messaging": 3, "encrypted messaging": 3, "signal": 3,
            "whatsapp": 2, "telegram": 2, "end to end encrypted": 3,
            "e2ee": 3, "encrypted chat": 3, "private message": 2,
        },
        "aliases": ["secure messaging", "encrypted messaging", "signal", "whatsapp security"],
        "responses": [
            "For private messaging, use Signal (gold standard, open-source, end-to-end encrypted by default). WhatsApp also has E2E encryption but is owned by Meta (data concerns). Telegram has E2E encryption only in 'secret chats'. Never discuss sensitive info on unencrypted platforms.",
        ],
    },
    # ─── USB / Physical Security ───
    {
        "name": "usb security",
        "keywords": {
            "usb": 2, "flash drive": 2, "usb stick": 2,
            "usb attack": 3, "usb drop": 3, "usb killer": 3,
            "found usb": 2, "unknown usb": 2,
        },
        "aliases": ["usb security", "usb attack"],
        "responses": [
            "Never plug an unknown USB drive into your computer. Attackers leave infected USB drives in parking lots ('USB dropping') — plugging them in can install malware automatically. Also beware of USB charging stations in public places (use a data blocker or your own charger).",
        ],
    },
]

# ── Question-specific fallbacks for topics ──
# These handle "tell me about X" or "explain X" where X is the topic name
TOPIC_LOOKUP = {}
for t in TOPICS:
    name = t["name"].lower()
    TOPIC_LOOKUP[name] = t
    for alias in t.get("aliases", []):
        TOPIC_LOOKUP[alias.lower()] = t


# ── Direct phrase→topic overrides (high priority) ──
DIRECT_MATCHES = [
    (["clicked", "phishing"], "recovery"),
    (["clicked", "link"], "recovery"),
    (["fell for", "phishing"], "recovery"),
    (["secure", "phone"], "mobile security"),
    (["secure", "mobile"], "mobile security"),
    (["protect", "email"], "email security"),
    (["email", "safe"], "email security"),
    (["safe browsing"], "safe browsing"),
    (["secure", "browser"], "safe browsing"),
    (["cybersecur"], "general tips"),
    (["help", "secur"], "general tips"),
    (["about", "cybersecur"], "general tips"),
    (["tell", "something", "cybersecur"], "general tips"),
    (["security", "tip"], "general tips"),
    (["public", "wifi"], "public wifi"),
    (["public", "wi-fi"], "public wifi"),
    (["ransomware"], "malware"),
]

def _direct_match(msg: str) -> Any:
    """Check if message matches any direct override pattern."""
    ml = msg.lower()
    for keywords, topic_name in DIRECT_MATCHES:
        if all(kw in ml for kw in keywords):
            for t in TOPICS:
                if t["name"] == topic_name:
                    return t
    return None

def score_message(msg: str, topic: dict[str, Any]) -> tuple[float, list[str]]:
    """Score a message against a topic's keywords.
    Prefer topics that match MORE distinct keywords over fewer high-weight ones.
    """
    msg_lower = msg.lower()
    score: float = 0.0
    matched: list[str] = []
    unique_count: int = 0
    for kw, weight in topic["keywords"].items():
        if kw in msg_lower:
            score += weight
            matched.append(kw)
            unique_count += 1
    # Boost score when many different keywords match (specific topic)
    if unique_count > 1:
        score *= (1 + (unique_count - 1) * 0.5)
    return score, matched


def reply(msg: str) -> str:
    m = (msg or "").strip()
    if not m:
        return "I'm here to help with cybersecurity! Ask me anything about phishing, passwords, 2FA, malware, safe browsing, etc."

    # Check for direct phrase matches first
    direct = _direct_match(m)
    if direct:
        return random.choice(direct["responses"])

    # Detect question type
    qtype, target = tokenize_question(m)

    # "what is X" / "explain X" — find the BEST matching topic
    if qtype in ("what_is", "explain", "recommend", "advice") and target:
        best_t = None; best_score = 0
        for t in TOPICS:
            name = t["name"].lower()
            # Check alias match
            for alias in t.get("aliases", []):
                if alias.lower() in target or target in alias.lower():
                    best_t = t; best_score = 99; break
            if best_score > 90: break
            # Check name match
            if name in target or target in name:
                if 50 > best_score:
                    best_t = t; best_score = 50
            # Check keyword match (use highest weight)
            for kw, wt in t["keywords"].items():
                if target in kw or kw in target:
                    if wt > best_score:
                        best_t = t; best_score = wt
        if best_t:
            return random.choice(best_t["responses"])

    # Score against all topics
    best_score = 0.0
    best_topic = None
    best_matched = []

    for t in TOPICS:
        score, matched = score_message(m, t)
        if score > best_score:
            best_score = score
            best_topic = t
            best_matched = matched

    # Also check for partial matches — if keywords overlap but no single topic wins,
    # try combining related topics
    if best_score >= 1.0 and best_topic:
        return random.choice(best_topic["responses"])

    # If we have a target from question but no match, try fuzzy matching
    if target:
        target_kws = extract_keywords(target)
        for t in TOPICS:
            for kw in t["keywords"]:
                for tw in target_kws:
                    if tw in kw or kw in tw:
                        return random.choice(t["responses"])

    # For "how to" questions without match, extract action and respond
    if qtype == "how_to" and target:
        action_kws = extract_keywords(target)
        if any(w in action_kws for w in ["secure", "protect", "safe", "stay"]):
            return random.choice(TOPICS[-5]["responses"])  # general tips
        if any(w in action_kws for w in ["create", "make", "set", "choose", "generate"]):
            return random.choice(TOPICS[2]["responses"])  # passwords
        if any(w in action_kws for w in ["detect", "spot", "identify", "recognize"]):
            return random.choice(TOPICS[0]["responses"])  # phishing
        if any(w in action_kws for w in ["remove", "clean", "delete", "fix"]):
            return random.choice(TOPICS[8]["responses"])  # malware

    # Extract keywords from the message and try to find best match
    kws = extract_keywords(m)
    if kws:
        # Count how many keywords each topic matches
        topic_scores = {}
        for t in TOPICS:
            count = 0
            for kw in kws:
                for tkw in t["keywords"]:
                    if kw in tkw or tkw in kw:
                        count += 1
                        break
            if count > 0:
                topic_scores[t["name"]] = (count, t)

        if topic_scores:
            best_name = max(topic_scores, key=lambda k: topic_scores[k][0])
            _, best_t = topic_scores[best_name]
            return random.choice(best_t["responses"])

    # Final fallback — try to give meaningful help based on any word in the message
    word_topics = {}
    for w in kws:
        for t in TOPICS:
            for kw in t["keywords"]:
                if w in kw or kw in w:
                    word_topics[t["name"]] = t
    if word_topics:
        # Return the topic with most keyword overlap
        return random.choice(list(word_topics.values())[0]["responses"])

    # Ultimate fallback
    fallbacks = [
        "I can help with: phishing, spam, passwords, 2FA, malware, ransomware, VPNs, safe browsing, privacy, and more. Try asking a specific question like 'what is phishing?' or 'how to create a strong password?'",
        "I specialize in cybersecurity. Ask me about: password security, spotting phishing, protecting your privacy, securing your devices, recovering from hacks, and online safety tips.",
        "Good question! Let me help you with cybersecurity. Try: 'how to spot phishing', 'what is 2FA', 'how to create strong password', 'what to do if hacked', or 'safe browsing tips'.",
    ]
    return random.choice(fallbacks)
