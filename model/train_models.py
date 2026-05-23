"""
Train TF-IDF + (LogisticRegression, MultinomialNB, RandomForest, ComplementNB)
models for URL phishing, text spam, and email phishing detection.
Uses a synthetic seed dataset so the project works out-of-the-box;
replace SEED_* with real CSVs (e.g., PhishTank, SMS Spam Collection) for
production-grade accuracy.
"""
import os
import random
import json
import logging
from typing import Any

import joblib

logger = logging.getLogger(__name__)
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB, ComplementNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

HERE = os.path.dirname(__file__)
random.seed(42)

SAFE_URLS = [
    "https://www.google.com","https://github.com/login","https://www.wikipedia.org",
    "https://stackoverflow.com/questions","https://www.python.org/downloads",
    "https://news.ycombinator.com","https://www.amazon.in/your-orders",
    "https://www.microsoft.com/en-us","https://www.apple.com/shop",
    "https://flask.palletsprojects.com/en/3.0.x/","https://docs.python.org/3/",
    "https://www.linkedin.com/in/someone","https://mail.google.com",
    "https://web.whatsapp.com","https://www.netflix.com/browse",
    "https://www.bbc.com/news","https://www.cloudflare.com",
    "https://about.gitlab.com","https://www.djangoproject.com",
    "https://reactjs.org/docs/getting-started.html",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ","https://www.forbes.com",
    "https://www.nytimes.com","https://www.udemy.com/course/python",
    "https://www.coursera.org/learn/machine-learning",
    "https://www.reddit.com/r/programming","https://medium.com/@user/post",
    "https://www.w3schools.com/python","https://dev.to/articles",
    "https://realpython.com/flask-intro","https://www.kaggle.com/datasets",
]
PHISH_URLS = [
    "http://192.168.1.10/login.php?user=admin","http://paypa1-secure-login.com/verify",
    "http://bit.ly/free-gift-card","https://account-update-amaz0n.com/signin",
    "http://secure-bank-login.tk/confirm","http://apple.id-verify-account.ru/",
    "http://faceb00k-security.com/login.html","http://login-microsoft365.support/auth",
    "https://chase-online-verify.com/account/update","http://netflix-billing-update.info/login",
    "http://tinyurl.com/win-iphone15","http://googl.com.evil.ru/secure",
    "http://1drv-onedrive.com/share/login","http://instagram-verify-badge.net/auth",
    "http://gov-tax-refund-claim.com/now","http://dhl-package-tracking.click/redeliver",
    "http://wa-business-verify.com/login","http://crypto-airdrop-free.io/claim",
    "http://yourbank.co.in@evil.ru/login","http://xn--pple-43d.com/id",
    "https://secure-google-login.xyz/verify","http://free-iphone15.top/claim",
    "http://amaz0n-prime-renew.ml/account","https://netflix-renew.club/payment",
    "http://faceboook-login.ga/security","https://www.googel.com/auth",
    "http://instaggram.com/verify-badge","https://paypa1.com/secure/update",
    "http://support-microsoft.tk/reset","https://1password-login.xyz/auth",
    "http://dh1-package.men/tracking","http://income-tax-refund.tk/claim",
]

SAFE_TXT = [
    "Hi team, sharing the meeting notes from today.","Your Amazon order has shipped and will arrive tomorrow.",
    "Reminder: dentist appointment at 4pm.","Please review the attached proposal when you have time.",
    "Happy birthday! Hope you have a great day.","Lunch at 1? Let me know.",
    "The build passed on CI, ready to merge.","Mom called, please call her back.",
    "Here are the photos from the trip.","Your electricity bill receipt is attached.",
    "Class is rescheduled to Friday 10 AM.","Please find the invoice for last month attached.",
    "Project deadline extended by one week.","Welcome aboard! Looking forward to working with you.",
    "Your package was delivered to the front desk.",
]
SPAM_TXT = [
    "CONGRATULATIONS! You have WON a free iPhone. Click here to claim now!",
    "URGENT: Your account will be suspended. Verify your password at http://bit.ly/x",
    "You are the lucky winner of $5000 lottery. Send your bank details to claim.",
    "Get rich quick! Work from home and earn $300/day guaranteed!!!",
    "Hot singles in your area waiting. Click here now.",
    "FREE crypto airdrop. Connect your wallet to receive 2 ETH instantly.",
    "Your tax refund is ready. Confirm your identity here: http://gov-refund.click",
    "Limited offer! 90% OFF designer watches — order today!",
    "Your OTP is 482910. Share with our agent to verify.",
    "Click to unsubscribe and claim your free gift card now.",
    "ACT NOW: investment opportunity guaranteed 200% return.",
    "Cheap loans approved instantly, no credit check.",
    "Re-confirm your bank account or it will be frozen within 24 hours.",
    "You have unclaimed parcel. Pay shipping fee to release.",
    "Free Netflix subscription forever! Visit http://netfli-x.tk",
]

CLF_MAP = {
    "lr": ("Logistic Regression", LogisticRegression(max_iter=1000, class_weight="balanced")),
    "nb": ("Multinomial Naive Bayes", MultinomialNB()),
    "rf": ("Random Forest", RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)),
    "cnb": ("Complement Naive Bayes", ComplementNB()),
}
CLF_ORDER = ["lr", "nb", "rf", "cnb"]

SAFE_EMAILS = [
    "Hi John, please find the quarterly report attached. Let me know if you have questions.",
    "Your meeting invite for tomorrow at 2 PM has been confirmed.",
    "The deployment completed successfully. All tests passed.",
    "Please review the pull request when you get a chance.",
    "Thanks for your application. We will be in touch within 5 business days.",
    "Your password has been changed successfully. If this wasn't you, contact support.",
    "Receipt for your recent purchase: Order #12345. Thank you for your business.",
    "Your subscription renewal is scheduled for next month. Manage your settings here.",
    "Weekly newsletter: Top stories in tech this week.",
    "Your package has been shipped. Tracking number: 1Z999AA10123456784.",
    "Team outing on Saturday! Please RSVP by Thursday.",
    "Your invoice for March 2025 is now available for viewing.",
    "Thank you for registering. Please verify your email address.",
    "Your support ticket #45678 has been resolved.",
    "Reminder: Performance reviews due by end of month.",
]
PHISH_EMAILS = [
    "Dear customer, your account has been compromised. Click here to verify your identity immediately.",
    "URGENT: Your PayPal account is limited. Sign in to confirm your details.",
    "Your Amazon order has been suspended. Update your payment information now.",
    "Unusual sign-in detected from a new device. Confirm your account to prevent suspension.",
    "Your Netflix subscription has expired. Update billing to continue watching.",
    "Dear user, you have an unclaimed tax refund. Submit your details to receive $1200.",
    "Microsoft security alert: We detected a virus on your computer. Download antivirus now.",
    "Your email has been selected for a $500,000 lottery grant. Send fees to release funds.",
    "IT Helpdesk: Update your email password immediately to avoid account deletion.",
    "Your DHL package is waiting. Pay shipping fee of $2.99 to release.",
    "Dear valued customer, we need to verify your account information. Click the link below.",
    "You have a new voice message. Listen here: [malicious link]",
    "Your Instagram account will be deleted due to copyright violation. Appeal now.",
    "Job offer: Work from home and earn $5000/week. Limited positions.",
    "Your Apple ID was used to sign in on a new iPhone. If not you, secure your account.",
    "Urgent: Your electricity bill is overdue. Disconnection in 24 hours if not paid.",
    "Congratulations! You are our lucky winner. Claim your prize before it expires.",
    "Invoice from your mobile carrier — payment overdue. Settle now to avoid late fee.",
    "Your Google Drive storage is full. Upgrade now to keep your files.",
    "Security alert: Someone tried to access your account from Russia. Secure now.",
]


def train_pair(X: list[str], y: list[int], name: str) -> dict[str, float]:
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    vec = TfidfVectorizer(ngram_range=(1, 3), min_df=1, sublinear_tf=True, analyzer="char_wb" if name == "url" else "word")
    Xtr_v = vec.fit_transform(Xtr)
    Xte_v = vec.transform(Xte)
    accs: dict[str, float] = {}
    for key in CLF_ORDER:
        label, clf = CLF_MAP[key]
        clf.fit(Xtr_v, ytr)
        acc = accuracy_score(yte, clf.predict(Xte_v))
        accs[key] = round(acc, 4)
        joblib.dump(clf, os.path.join(HERE, f"{name}_{key}.pkl"))
    joblib.dump(vec, os.path.join(HERE, f"{name}_vec.pkl"))
    logger.info("%s] %s", name, "  ".join(f"{k}={v:.3f}" for k, v in accs.items()))
    return accs


def main() -> None:
    logger.info("Training URL models (%d safe + %d phishing)…", len(SAFE_URLS), len(PHISH_URLS))
    url_acc = train_pair(SAFE_URLS + PHISH_URLS, [0] * len(SAFE_URLS) + [1] * len(PHISH_URLS), "url")
    logger.info("Training text models (%d safe + %d spam)…", len(SAFE_TXT), len(SPAM_TXT))
    txt_acc = train_pair(SAFE_TXT + SPAM_TXT, [0] * len(SAFE_TXT) + [1] * len(SPAM_TXT), "txt")
    logger.info("Training email models (%d safe + %d phishing)…", len(SAFE_EMAILS), len(PHISH_EMAILS))
    email_acc = train_pair(SAFE_EMAILS + PHISH_EMAILS, [0] * len(SAFE_EMAILS) + [1] * len(PHISH_EMAILS), "email")

    best_url = max(url_acc, key=url_acc.get)
    best_txt = max(txt_acc, key=txt_acc.get)
    best_email = max(email_acc, key=email_acc.get)
    logger.info("=" * 50)
    logger.info("Best URL model: %s (%.4f)", best_url, url_acc[best_url])
    logger.info("Best text model: %s (%.4f)", best_txt, txt_acc[best_txt])
    logger.info("Best email model: %s (%.4f)", best_email, email_acc[best_email])
    logger.info("Models saved to %s", HERE)


if __name__ == "__main__":
    main()
