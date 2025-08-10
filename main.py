import os
import imaplib
import email
import getpass
import json
import logging
import time
from pathlib import Path
from urllib.parse import urlparse
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import concurrent.futures
from threading import Thread
from datetime import datetime, timedelta

from dotenv import load_dotenv, set_key, find_dotenv, dotenv_values
from bs4 import BeautifulSoup
import requests

# ---------------------- Config & Constants ----------------------
CACHE_FILE = "unsubscribe_cache.json"
LOG_FILE = "unsubscribe.log"
BATCH_SIZE = 10  # IMAP fetch batch size
MAX_WORKERS = 4  # Thread pool size for link-clicking
CLICK_DELAY = 1.0  # Seconds between link clicks (anti-flood)
IMAP_RETRIES = 3  # Number of retries for IMAP connection
IMAP_RETRY_DELAY = 2  # Seconds between retries

# Define and allow user to override in settings.py
try:
    from settings import TRUSTED_DOMAINS, CACHE_FILE, LOG_FILE
except ImportError:
    TRUSTED_DOMAINS = {"github.com", "linkedin.com", "paypal.com"}

# ---------------------- Logging Setup ----------------------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("EmailUnsubscribe")

# ---------------------- Utility Functions ----------------------
def ensure_credentials():
    """Ensure and save Gmail credentials."""
    load_dotenv()
    email_user = os.getenv("EMAIL")
    email_pass = os.getenv("PASSWORD")

    if not email_user:
        email_user = input("Enter your Gmail address: ").strip()

    if not email_pass:
        email_pass = getpass.getpass("Enter your Gmail app password (input hidden): ").strip()

    env_path = find_dotenv()
    if not env_path:
        env_path = ".env"  # default in current directory

    if not Path(env_path).exists():
        with open(env_path, "w", encoding="utf-8") as f:
            pass  # create empty file

    current_env = dotenv_values(env_path)
    if current_env.get("EMAIL") != email_user:
        set_key(env_path, "EMAIL", email_user)
    if current_env.get("PASSWORD") != email_pass:
        set_key(env_path, "PASSWORD", email_pass)

    return email_user, email_pass

def load_cache():
    """Load cached sender/link info."""
    if Path(CACHE_FILE).exists():
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error("Failed to load cache: %s", e)
            return {}
    return {}

def save_cache(cache):
    """Save sender/link info to cache."""
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except IOError as e:
        logger.error("Failed to save cache: %s", e)

# ---------------------- IMAP & Link Logic ----------------------
def connect_to_email(email_user, email_pass, retries=IMAP_RETRIES, delay=IMAP_RETRY_DELAY):
    """IMAP connection helper with retries."""
    if not email_user or not email_pass:
        raise ValueError("EMAIL or PASSWORD not set.")
    for attempt in range(retries):
        try:
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login(email_user, email_pass)
            mail.select("inbox")
            logger.info("Successfully connected to IMAP server")
            return mail
        except imaplib.IMAP4.error as e:
            if attempt == retries - 1:
                logger.error("Login failed after %d attempts: %s", retries, e)
                messagebox.showerror("Login Failed", f"Error: {e}")
                raise
            logger.warning("IMAP connection attempt %d failed: %s", attempt + 1, e)
            time.sleep(delay)

def fetch_emails(mail, since_days=30):
    """Fetch email IDs containing 'unsubscribe', newest first."""
    since_date = (datetime.now() - timedelta(days=since_days)).strftime("%d-%b-%Y")
    _, search_data = mail.search(None, f'(BODY "unsubscribe" SINCE "{since_date}")')
    email_ids = search_data[0].split()
    logger.info("Found %d emails with 'unsubscribe'", len(email_ids))
    return email_ids

def fetch_batch(mail, batch):
    """Fetch a batch of emails by ID. Handles both bytes and str IDs."""
    batch_str = ",".join(
        x.decode("utf-8") if isinstance(x, bytes) else str(x)
        for x in batch
    )
    _, msg_data = mail.fetch(batch_str, "(RFC822)")
    return msg_data

def extract_links_from_html(html_content):
    """Extract unsubscribe/opt-out links from HTML."""
    soup = BeautifulSoup(html_content, "html.parser")
    keywords = ["unsubscribe", "opt out", "manage preferences"]
    return [
        a["href"] for a in soup.find_all("a", href=True)
        if any(kw in a["href"].lower() for kw in keywords)
    ]

def process_emails(mail, email_ids, cache, progress_callback=None):
    """Process email batches to find unsubscribe links."""
    sender_links = cache.copy()
    total = len(email_ids)
    for idx in range(0, total, BATCH_SIZE):
        batch = email_ids[idx : idx + BATCH_SIZE]
        msg_data = fetch_batch(mail, batch)
        for i in range(0, len(msg_data), 2):
            if not isinstance(msg_data[i], tuple):
                continue
            raw_email = msg_data[i][1]
            msg = email.message_from_bytes(raw_email)
            
            sender = msg.get("From", "Unknown Sender")
            sender_email = sender.split("<")[-1].rstrip(">").strip() if "<" in sender else sender

            links = []
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/html":
                        try:
                            html_content = part.get_payload(decode=True).decode(errors="ignore")
                            links.extend(extract_links_from_html(html_content))
                        except Exception as e:
                            logger.warning("Failed to process part for %s: %s", sender_email, e)
            else:
                if msg.get_content_type() == "text/html":
                    try:
                        html_content = msg.get_payload(decode=True).decode(errors="ignore")
                        links.extend(extract_links_from_html(html_content))
                    except Exception as e:
                        logger.warning("Failed to process email for %s: %s", sender_email, e)

            if links:
                current_links = set(sender_links.get(sender_email, []))
                current_links.update(links)
                sender_links[sender_email] = list(current_links)
                logger.info("Found %d unsubscribe links for %s", len(links), sender_email)

        if progress_callback:
            progress_callback(min(idx + BATCH_SIZE, total) / total * 100)
    return sender_links

def click_link(link, trusted_domains, delay=0):
    """Visit a link unless it's from a trusted domain."""
    if delay > 0:
        time.sleep(delay)
    try:
        parsed = urlparse(link)
        if not parsed.scheme or not parsed.netloc:
            logger.warning("Invalid URL: %s", link)
            return False, f"Invalid URL: {link}"
        domain = parsed.netloc
        if domain in trusted_domains:
            logger.info("Skipped trusted domain: %s", domain)
            return False, f"Skipped trusted domain: {domain}"
        response = requests.get(link, timeout=10)
        if response.status_code == 200:
            logger.info("Unsubscribed via %s", link)
            return True, f"Unsubscribed via {link}"
        else:
            logger.warning("Failed (%d): %s", response.status_code, link)
            return False, f"Failed ({response.status_code}): {link}"
    except requests.RequestException as e:
        logger.error("Error clicking link %s: %s", link, e)
        return False, f"Error: {e}"

def unsubscribe_selected_links(links, trusted_domains, status_callback=None, max_workers=MAX_WORKERS, click_delay=CLICK_DELAY):
    """Unsubscribe from selected links in parallel."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(click_link, link, trusted_domains, i * click_delay)
            for i, link in enumerate(links)
        ]
        for future in concurrent.futures.as_completed(futures):
            success, msg = future.result()
            results.append((success, msg))
            if status_callback:
                status_callback(msg)
    return results

# ---------------------- Tkinter GUI ----------------------
class UnsubscribeApp(tk.Tk):
    """GUI for Email Unsubscribe Assistant."""

    def __init__(self):
        super().__init__()
        self.title("Email Unsubscribe Assistant (Enhanced)")
        self.geometry("800x600")
        self.sender_links = {}
        self.var_dict = {}
        self.clicking = False

        # Left frame for senders
        left_frame = ttk.Frame(self)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        self.tree = ttk.Treeview(left_frame, columns=("Links",), selectmode="extended")
        self.tree.heading("#0", text="Sender")
        self.tree.heading("Links", text="Links")
        self.tree.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(left_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Right frame for actions
        right_frame = ttk.Frame(self)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Fetch button
        fetch_btn = ttk.Button(right_frame, text="Fetch Emails", command=self.fetch_and_process_emails)
        fetch_btn.pack(fill=tk.X, pady=2)

        # Preview button
        preview_btn = ttk.Button(right_frame, text="Preview Links", command=self.preview_links)
        preview_btn.pack(fill=tk.X, pady=2)

        # Trusted domains editor
        trusted_btn = ttk.Button(right_frame, text="Edit Trusted Domains", command=self.edit_trusted_domains)
        trusted_btn.pack(fill=tk.X, pady=2)

        # Global checkbox for select all
        self.select_all_var = tk.BooleanVar()
        select_all_cb = ttk.Checkbutton(
            right_frame, text="Select All Senders", variable=self.select_all_var, command=self.toggle_select_all
        )
        select_all_cb.pack(fill=tk.X, pady=2)

        # Unsubscribe button
        self.unsub_btn = ttk.Button(
            right_frame,
            text="Unsubscribe Selected (Confirm)",
            command=self.confirm_unsubscribe,
        )
        self.unsub_btn.pack(fill=tk.X, pady=2)

        # Sandbox warning
        sandbox_lbl = ttk.Label(
            right_frame,
            text="WARNING: Clicking links is NOT sandboxed!",
            foreground="red",
        )
        sandbox_lbl.pack(fill=tk.X, pady=2)

        # Status/progress area
        status_frame = ttk.LabelFrame(right_frame, text="Status")
        status_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.status_box = scrolledtext.ScrolledText(status_frame, height=10, wrap="word")
        self.status_box.pack(fill=tk.BOTH, expand=True)

        self.progress = ttk.Progressbar(status_frame, orient="horizontal", mode="determinate")
        self.progress.pack(fill=tk.X, pady=2, padx=2)

        self.status_box.tag_config("success", foreground="green")
        self.status_box.tag_config("fail", foreground="red")
        self.status_box.tag_config("skip", foreground="orange")

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def populate_sender_tree(self):
        """Fill the sender tree with cached data."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        for sender in sorted(self.sender_links):
            link_count = len(self.sender_links[sender])
            self.tree.insert("", "end", text=sender, values=(f"{link_count} links",))

    def get_selected_senders(self):
        """Get currently selected senders from the tree."""
        sender_ids = self.tree.selection()
        return [self.tree.item(sid, "text") for sid in sender_ids]

    def preview_links(self):
        """Preview unsubscribe links for selected senders."""
        selected = self.get_selected_senders()
        if not selected:
            messagebox.showinfo("No Selection", "Please select at least one sender.")
            return
        preview_text = ""
        for sender in selected:
            preview_text += f"\nSender: {sender}\n"
            for link in self.sender_links[sender]:
                preview_text += f"  - {link}\n"
        self.print_status(preview_text)

    def toggle_select_all(self):
        """Toggle select all/none in the sender tree."""
        all_items = self.tree.get_children()
        for item in all_items:
            if self.select_all_var.get():
                self.tree.selection_add(item)
            else:
                self.tree.selection_remove(item)

    def edit_trusted_domains(self):
        """Open a dialog to edit trusted domains."""
        dialog = tk.Toplevel(self)
        dialog.title("Edit Trusted Domains")
        dialog.geometry("300x400")
        text = tk.Text(dialog, height=15)
        text.insert(tk.END, "\n".join(TRUSTED_DOMAINS))
        text.pack(fill=tk.BOTH, padx=5, pady=5)
        def save():
            new_domains = set(text.get("1.0", tk.END).strip().splitlines())
            try:
                with open("settings.py", "w", encoding="utf-8") as f:
                    f.write(f"TRUSTED_DOMAINS = {new_domains}\n")
                    f.write(f"CACHE_FILE = '{CACHE_FILE}'\n")
                    f.write(f"LOG_FILE = '{LOG_FILE}'\n")
                dialog.destroy()
                messagebox.showinfo("Success", "Trusted domains updated. Restart the app to apply.")
            except IOError as e:
                logger.error("Failed to save settings.py: %s", e)
                messagebox.showerror("Error", f"Failed to save settings: {e}")
        ttk.Button(dialog, text="Save", command=save).pack(pady=5)

    def confirm_unsubscribe(self):
        """Ask user to confirm before clicking links."""
        selected = self.get_selected_senders()
        if not selected:
            messagebox.showinfo("No Selection", "Please select at least one sender.")
            return
        to_unsub = sum(len(self.sender_links[s]) for s in selected)
        confirm = messagebox.askokcancel(
            "Confirm Unsubscribe",
            f"Do you really want to visit {to_unsub} unsubscribe links?\n\n"
            "WARNING: This will directly visit the links in your browser session. "
            "Only proceed if you are certain the senders are safe.",
        )
        if confirm:
            self.unsubscribe_selected()

    def unsubscribe_selected(self):
        """Unsubscribe parallel from selected senders."""
        if self.clicking:
            return
        self.clicking = True
        self.unsub_btn.config(state="disabled")
        self.print_status("\nStarting unsubscribe process...\n")
        selected = self.get_selected_senders()
        links = []
        for sender in selected:
            links.extend(self.sender_links[sender])
        Thread(
            target=self._unsubscribe_thread,
            args=(links, MAX_WORKERS, CLICK_DELAY),
            daemon=True
        ).start()

    def _unsubscribe_thread(self, links, max_workers, click_delay):
        """Run unsubscribe in a separate thread to keep GUI responsive."""
        def status_callback(msg):
            self.print_status(msg)
        results = unsubscribe_selected_links(links, TRUSTED_DOMAINS, status_callback, max_workers, click_delay)
        for success, msg in results:
            tag = "success" if success else "fail" if "Failed" in msg else "skip"
            self.print_status(msg, tag=tag)
        self.clicking = False
        self.unsub_btn.config(state="normal")
        self.print_status("\nUnsubscribe process completed.\n")
        save_cache(self.sender_links)

    def fetch_and_process_emails(self):
        """Fetch and process emails, updating progress bar."""
        self.progress["value"] = 0
        self.print_status("Fetching emails...\n")
        def update_progress(value):
            self.progress["value"] = value
            self.update_idletasks()
        try:
            email_user, email_pass = ensure_credentials()
            mail = connect_to_email(email_user, email_pass)
            email_ids = fetch_emails(mail, since_days=30)
            if not email_ids:
                self.print_status("No emails with 'unsubscribe' found.\n")
                mail.logout()
                return
            cache = load_cache()
            self.sender_links = process_emails(mail, email_ids, cache, update_progress)
            self.populate_sender_tree()
            save_cache(self.sender_links)
            self.print_status("Email processing completed.\n")
            mail.logout()
        except Exception as e:
            logger.error("Error fetching/processing emails: %s", e)
            self.print_status(f"Error: {e}\n", tag="fail")
            messagebox.showerror("Error", f"Failed to fetch/process emails: {e}")

    def print_status(self, message, tag="normal"):
        """Print to status box with optional tag."""
        self.status_box.insert(tk.END, message + "\n", tag)
        self.status_box.see(tk.END)
        self.update_idletasks()

    def on_close(self):
        """Handle window close."""
        save_cache(self.sender_links)
        self.destroy()

if __name__ == "__main__":
    app = UnsubscribeApp()
    app.mainloop()