import os
import time
import logging

from watchdog.observers import Observer
from dotenv import load_dotenv
load_dotenv()

import detect_ransomware

# --- logging setup: prints to terminal AND writes to a file ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),                          # terminal output
        logging.FileHandler("ransomware_detector.log"),   # persistent log file
    ]
)

if __name__ == "__main__":
    path_to_watch = "./ransomware_test"   # change to whatever folder you want to monitor

    banner = detect_ransomware.Banner()
    banner.Print_Version()

    # --- detectors ---
    entropy_logger = detect_ransomware.EntropyLogger()
    extension_logger = detect_ransomware.ExtensionLogger()
    responder = detect_ransomware.IncidentResponder()
    handler = detect_ransomware.ActivityLogger(entropy_logger, extension_logger, responder)

    backup_handler = detect_ransomware.BackupLogger()
    process_tree_handler = detect_ransomware.ProcessTreeLogger()


    # --- prompt for recipient first ---
    smtp_password = os.environ.get("SMTP_APP_PASSWORD")
    sender_email = os.environ.get("ALERT_SENDER_EMAIL")
    recipient_email = None

    if smtp_password and sender_email:
        user_input = input(
            "Enter the email address that should receive ransomware alerts "
            "(leave blank to disable email alerts): "
        ).strip()
        recipient_email = user_input if user_input else None

    mailer = None
    if smtp_password and sender_email and recipient_email:
        mailer = detect_ransomware.AlertMailer(
            smtp_server="smtp.gmail.com",
            smtp_port=587,
            sender_email=sender_email,
            sender_password=smtp_password,
            recipient_email=recipient_email,
        )
        logging.info(f"[DEBUG] email alerts will be sent to {recipient_email}")
    else:
        logging.info("[DEBUG] SMTP_APP_PASSWORD / ALERT_SENDER_EMAIL / recipient not fully set — email alerts disabled")

    # --- ONE responder, created once, used everywhere ---
    responder = detect_ransomware.IncidentResponder(mailer=mailer, dry_run=True)

    # --- detectors, all sharing the same responder ---
    entropy_logger = detect_ransomware.EntropyLogger()
    extension_logger = detect_ransomware.ExtensionLogger()
    handler = detect_ransomware.ActivityLogger(entropy_logger, extension_logger, responder)

    backup_handler = detect_ransomware.BackupLogger(responder=responder)
    process_tree_handler = detect_ransomware.ProcessTreeLogger(responder=responder)
    # --- start the file watcher ---
    observer = Observer()
    observer.schedule(handler, path_to_watch, recursive=True)
    observer.start()
    logging.info(f"Watching {path_to_watch}...")

    try:
        while True:
            backup_handler.Check_Process()
            process_tree_handler.Check_Process_Trees()
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()