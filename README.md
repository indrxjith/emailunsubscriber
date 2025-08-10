#Taming inbox overload: I built a desktop tool that streamlines unsubscribing from marketing emails in Gmail.
What it does:
Identifies “unsubscribe” links in recent emails and groups them by sender
Lets you review first, then batch-unsubscribe with clear progress and logs
Skips trusted domains (e.g., GitHub, LinkedIn, PayPal) by default
Caches results for faster subsequent runs; credentials are stored locally via .env
Tech stack:
 Python, Tkinter, IMAP (imaplib), BeautifulSoup, Requests, python-dotenv, logging
Why:
 To reduce inbox noise and make unsubscribe workflows faster, safer, and more transparent—without relying on third‑party services.
