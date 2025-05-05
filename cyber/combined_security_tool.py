import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import hashlib
import os
import nmap

# --- Dark Web Exposure Finder Functions ---
breach_set = set()
try:
    with open("breach_dataset.txt", "r", encoding="utf-8") as file:
        for line in file:
            breach_info = line.strip().split(",")
            if breach_info[0]:
                breach_set.add(breach_info[0].lower())
except FileNotFoundError:
    messagebox.showerror("Error", "Breach dataset file not found.")
    breach_set = set()

def hash_email(email):
    return hashlib.sha1(email.lower().encode()).hexdigest()

def check_email(email_entry, output_text):
    email = email_entry.get().strip()
    if not email:
        messagebox.showwarning("Input Error", "Please enter an email address.")
        return

    hashed_email = hash_email(email)
    output_text.insert(tk.END, f"Checking breaches for {email} (hashed: {hashed_email})...\n")
    
    found = False
    for line in open("breach_dataset.txt", "r", encoding="utf-8"):
        breach_info = line.strip().split(",")
        if len(breach_info) > 0 and breach_info[0].lower() == hashed_email:
            output_text.insert(
                tk.END,
                f"⚠️ ALERT: {email} was found in a breach!\n"
                f"Source: {breach_info[1] if len(breach_info) > 1 else 'Unknown'}\n"
                f"Date: {breach_info[2] if len(breach_info) > 2 else 'Unknown'}\n\n"
            )
            found = True
            break

    if not found:
        output_text.insert(tk.END, f"No breaches found for {email}. ✅\n\n")

def clear_output(output_text):
    output_text.delete(1.0, tk.END)

# --- Vulnerability Scanner Functions ---
def scan_target(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, '1-65535')
    return scanner

def generate_report(scan_data, output_file):
    try:
        with open(output_file, 'w') as f:
            for host in scan_data.all_hosts():
                f.write(f"Host: {host} ({scan_data[host].hostname()})\n")
                f.write(f"State: {scan_data[host].state()}\n")
                f.write(f"Server Type: {scan_data[host]['hostscript']['http-title'] if 'hostscript' in scan_data[host] else 'N/A'}\n")
                for proto in scan_data[host].all_protocols():
                    f.write(f"Protocol: {proto}\n")
                    ports = scan_data[host][proto].keys()
                    for port in ports:
                        f.write(f"Port: {port}\tState: {scan_data[host][proto][port]['state']}\n")
                f.write("\n")
        messagebox.showinfo("Success", f"Report saved to {output_file}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while saving the report: {e}")

def start_scan(target_entry):
    target = target_entry.get().strip()
    if not target:
        messagebox.showwarning("Warning", "Please enter a target")
        return
    try:
        scan_data = scan_target(target)
        output_file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if output_file:
            generate_report(scan_data, output_file)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during scanning: {e}")

# --- GUI Setup with Tabs ---
root = tk.Tk()
root.title("Combined Security Tool")
root.geometry("800x600")
root.configure(bg="#f0f0f0")

# Title Frame
title_frame = tk.Frame(root, bg="#003366", height=50)
title_frame.pack(fill="x")
title_label = tk.Label(title_frame, text="Combined Security Tool", bg="#003366", fg="white", font=("Helvetica", 16))
title_label.pack(pady=10)

# Notebook (Tabs)
notebook = ttk.Notebook(root)
notebook.pack(pady=10, fill="both", expand=True)

# --- Dark Web Exposure Finder Tab ---
exposure_frame = tk.Frame(notebook, bg="#f0f0f0")
notebook.add(exposure_frame, text="Dark Web Exposure Finder")

email_label = tk.Label(exposure_frame, text="Enter Email Address:", bg="#f0f0f0", font=("Helvetica", 12))
email_label.pack(pady=10)

email_entry = tk.Entry(exposure_frame, width=50, font=("Helvetica", 12))
email_entry.pack(pady=10)

check_button = tk.Button(exposure_frame, text="Check Breach", command=lambda: check_email(email_entry, output_text), bg="green", fg="white", width=15, font=("Helvetica", 12))
check_button.pack(pady=10)

clear_button = tk.Button(exposure_frame, text="Clear Output", command=lambda: clear_output(output_text), bg="red", fg="white", width=15, font=("Helvetica", 12))
clear_button.pack(pady=10)

output_text = scrolledtext.ScrolledText(exposure_frame, wrap=tk.WORD, width=95, height=20, bg="black", fg="white")
output_text.pack(pady=10)

# --- Vulnerability Scanner Tab ---
scanner_frame = tk.Frame(notebook, bg="#f0f0f0")
notebook.add(scanner_frame, text="Vulnerability Scanner")

input_frame = tk.Frame(scanner_frame, bg="#f0f0f0")
input_frame.pack(pady=20)
target_label = tk.Label(input_frame, text="Target IP or URL:", bg="#f0f0f0", font=("Helvetica", 12))
target_label.grid(row=0, column=0, padx=10, pady=10)
target_entry = tk.Entry(input_frame, width=40, font=("Helvetica", 12))
target_entry.grid(row=0, column=1, padx=10, pady=10)

scan_button = tk.Button(scanner_frame, text="Start Scan", command=lambda: start_scan(target_entry), bg="#003366", fg="white", font=("Helvetica", 12))
scan_button.pack(pady=10)

# Footer
footer_frame = tk.Frame(root, bg="#f0f0f0")
footer_frame.pack(fill="x", pady=20)

credits_label = tk.Label(footer_frame, text="Made by Eng.Omar Hany & Job Zaak", bg="#f0f0f0", font=("Helvetica", 10))
credits_label.pack(side=tk.LEFT, padx=10)

social_media_label = tk.Label(footer_frame, text="Follow me on:", bg="#f0f0f0", font=("Helvetica", 10, "italic"))
social_media_label.pack(side=tk.LEFT, padx=10)

facebook_link = tk.Label(footer_frame, text="📘 Facebook", fg="blue", cursor="hand2", bg="#f0f0f0", font=("Helvetica", 10, "underline"))
facebook_link.pack(side=tk.LEFT, padx=5)
instagram_link = tk.Label(footer_frame, text="📷 Instagram", fg="blue", cursor="hand2", bg="#f0f0f0", font=("Helvetica", 10, "underline"))
instagram_link.pack(side=tk.LEFT, padx=5)

facebook_link.bind("<Button-1>", lambda e: os.system(f"start https://facebook.com/Omar.Hany.850"))
instagram_link.bind("<Button-1>", lambda e: os.system(f"start https://instagram.com/omar.hany.850/"))

root.mainloop()