import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import hashlib
import os
import nmap
import threading

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
def scan_target(target, port_range, scan_status_label):
    scanner = nmap.PortScanner()
    scan_status_label.config(text="Scanning... Please wait ⏳")
    scanner.scan(target, port_range, arguments='-T4')  # -T4 for faster scanning
    scan_status_label.config(text="Scan Complete ✅")
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

def start_scan(target_entry, port_entry, scan_status_label):
    target = target_entry.get().strip()
    port_range = port_entry.get().strip() or "1-1024"  # Default to common ports
    if not target:
        messagebox.showwarning("Warning", "Please enter a target")
        return

    # Run scan in a separate thread to prevent freezing
    def scan_thread():
        try:
            scan_data = scan_target(target, port_range, scan_status_label)
            output_file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if output_file:
                generate_report(scan_data, output_file)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during scanning: {e}")

    threading.Thread(target=scan_thread, daemon=True).start()

# --- GUI Setup with Tabs ---
root = tk.Tk()
root.title("Combined Security Tool")
root.geometry("900x700")
root.configure(bg="#e6e6e6")

# Title Frame
title_frame = tk.Frame(root, bg="#003087", height=60)
title_frame.pack(fill="x")
title_label = tk.Label(title_frame, text="🔒 Combined Security Tool 🔒", bg="#003087", fg="white", font=("Arial", 20, "bold"))
title_label.pack(pady=15)

# Notebook (Tabs)
notebook = ttk.Notebook(root)
notebook.pack(pady=10, fill="both", expand=True)

# --- Dark Web Exposure Finder Tab ---
exposure_frame = tk.Frame(notebook, bg="#f5f5f5")
notebook.add(exposure_frame, text="Dark Web Exposure Finder")

email_label = tk.Label(exposure_frame, text="Enter Email Address:", bg="#f5f5f5", font=("Arial", 14, "bold"))
email_label.pack(pady=15)

email_entry = tk.Entry(exposure_frame, width=50, font=("Arial", 12))
email_entry.pack(pady=10)

button_frame = tk.Frame(exposure_frame, bg="#f5f5f5")
button_frame.pack(pady=10)
check_button = tk.Button(button_frame, text="Check Breach", command=lambda: check_email(email_entry, output_text), bg="#006400", fg="white", width=15, font=("Arial", 12, "bold"))
check_button.pack(side=tk.LEFT, padx=10)
clear_button = tk.Button(button_frame, text="Clear Output", command=lambda: clear_output(output_text), bg="#8B0000", fg="white", width=15, font=("Arial", 12, "bold"))
clear_button.pack(side=tk.LEFT, padx=10)

output_text = scrolledtext.ScrolledText(exposure_frame, wrap=tk.WORD, width=100, height=20, bg="#1c2526", fg="#00FF00", font=("Courier", 12))
output_text.pack(pady=15, padx=10)

# --- Vulnerability Scanner Tab ---
scanner_frame = tk.Frame(notebook, bg="#f5f5f5")
notebook.add(scanner_frame, text="Vulnerability Scanner")

input_frame = tk.Frame(scanner_frame, bg="#f5f5f5")
input_frame.pack(pady=20)
target_label = tk.Label(input_frame, text="Target IP or URL:", bg="#f5f5f5", font=("Arial", 14, "bold"))
target_label.grid(row=0, column=0, padx=10, pady=10)
target_entry = tk.Entry(input_frame, width=40, font=("Arial", 12))
target_entry.grid(row=0, column=1, padx=10, pady=10)

port_label = tk.Label(input_frame, text="Port Range (e.g., 1-1024):", bg="#f5f5f5", font=("Arial", 14, "bold"))
port_label.grid(row=1, column=0, padx=10, pady=10)
port_entry = tk.Entry(input_frame, width=40, font=("Arial", 12))
port_entry.grid(row=1, column=1, padx=10, pady=10)
port_entry.insert(0, "1-1024")  # Default value

scan_status_label = tk.Label(scanner_frame, text="", bg="#f5f5f5", font=("Arial", 12, "italic"))
scan_status_label.pack(pady=5)

scan_button = tk.Button(scanner_frame, text="Start Scan", command=lambda: start_scan(target_entry, port_entry, scan_status_label), bg="#003087", fg="white", font=("Arial", 12, "bold"))
scan_button.pack(pady=15)

# Footer
footer_frame = tk.Frame(root, bg="#003087")
footer_frame.pack(fill="x", pady=10)

credits_label = tk.Label(footer_frame, text="Developed by Eng.Omar Hany", bg="#003087", fg="white", font=("Arial", 12, "bold"))
credits_label.pack(side=tk.LEFT, padx=20)

social_frame = tk.Frame(footer_frame, bg="#003087")
social_frame.pack(side=tk.RIGHT, padx=20)
social_media_label = tk.Label(social_frame, text="Follow Me: ", bg="#003087", fg="white", font=("Arial", 12, "italic"))
social_media_label.pack(side=tk.LEFT)

facebook_link = tk.Label(social_frame, text="📘 Facebook", fg="#87CEEB", cursor="hand2", bg="#003087", font=("Arial", 12, "bold underline"))
facebook_link.pack(side=tk.LEFT, padx=10)
instagram_link = tk.Label(social_frame, text="📷 Instagram", fg="#87CEEB", cursor="hand2", bg="#003087", font=("Arial", 12, "bold underline"))
instagram_link.pack(side=tk.LEFT, padx=10)

facebook_link.bind("<Button-1>", lambda e: os.system(f"start https://facebook.com/Omar.Hany.850"))
instagram_link.bind("<Button-1>", lambda e: os.system(f"start https://instagram.com/omar.hany.850/"))

root.mainloop()
