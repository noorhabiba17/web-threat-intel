"""
Train TF-IDF + (LogisticRegression, MultinomialNB) models for URL phishing
and text spam detection. Uses a synthetic seed dataset so the project works
out-of-the-box; replace SEED_* with real CSVs (e.g., PhishTank, SMS Spam
Collection) for production-grade accuracy.
"""
import os, random, joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
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

def train_pair(X, y, name):
    Xtr,Xte,ytr,yte = train_test_split(X,y,test_size=0.25,random_state=42,stratify=y)
    vec = TfidfVectorizer(ngram_range=(1,3), min_df=1, sublinear_tf=True, analyzer="char_wb" if name=="url" else "word")
    Xtr_v = vec.fit_transform(Xtr); Xte_v = vec.transform(Xte)
    lr = LogisticRegression(max_iter=1000, class_weight="balanced").fit(Xtr_v, ytr)
    nb = MultinomialNB().fit(Xtr_v, ytr)
    # ensemble: average probs, pick LR as primary (saved) + log NB acc
    print(f"[{name}] LR acc={accuracy_score(yte, lr.predict(Xte_v)):.3f}  NB acc={accuracy_score(yte, nb.predict(Xte_v)):.3f}")
    joblib.dump(vec, os.path.join(HERE, f"{name}_vec.pkl"))
    joblib.dump(lr,  os.path.join(HERE, f"{name}_clf.pkl"))

def main():
    X_url = SAFE_URLS + PHISH_URLS
    y_url = [0]*len(SAFE_URLS) + [1]*len(PHISH_URLS)
    train_pair(X_url, y_url, "url")
    X_txt = SAFE_TXT + SPAM_TXT
    y_txt = [0]*len(SAFE_TXT) + [1]*len(SPAM_TXT)
    train_pair(X_txt, y_txt, "txt")
    print("Models saved to", HERE)

if __name__ == "__main__":
    main()
