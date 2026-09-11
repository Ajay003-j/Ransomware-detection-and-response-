import os
import time
import smtplib
import psutil
import logging
import math
from collections import Counter, deque
from email.mime.text import MIMEText
from watchdog.events import FileSystemEventHandler

ENTROPY_THRESHOLD = 7.5

SUSPICIOUS_PARENTS = ["libreoffice", "soffice.bin", "acroread", "evince", "thunderbird"]
SUSPICIOUS_CHILDREN = ["bash", "sh", "python3", "python", "perl", "curl", "wget", "nc"]


class Banner():
    def Print_Version(self):
        print("Ransomware Behavior Detector v0.1")


# ---------------------------------------------------------------------------
# DETECTORS
# ---------------------------------------------------------------------------

class ActivityLogger(FileSystemEventHandler):


    def __init__(self, entropy_logger, extension_logger, responder):
        self.entropy_logger = entropy_logger
        self.extension_logger = extension_logger
        self.responder = responder

    def _check_entropy(self, filepath):
        entropy = self.entropy_logger.Check_File_Entropy(filepath)
        logging.info(f"[DEBUG] entropy for {filepath} = {entropy}")
        if entropy >= ENTROPY_THRESHOLD:
            reason = f"high entropy write ({entropy:.2f}) on {filepath}"
            logging.warning(f"HIGH ENTROPY: {filepath} ({entropy:.2f})")
            if self.responder:
                self.responder.respond_to_file_threat(filepath, reason)

    def on_created(self, event):
        if not event.is_directory:
            filepath = event.src_path
            logging.info(f"CREATED {filepath}")
            self._check_entropy(filepath)

    def on_modified(self, event):
        if not event.is_directory:
            filepath = event.src_path
            logging.info(f"MODIFIED {filepath}")
            self._check_entropy(filepath)

    def on_deleted(self, event):
        filepath = event.src_path
        logging.info(f"DELETED {filepath}")

    def on_moved(self, event):
        logging.info(f"RENAMED {event.src_path} -> {event.dest_path}")
        if not event.is_directory:
            changed = self.extension_logger.Check_Extension_Change(
                event.src_path, event.dest_path, responder=self.responder
            )
            self._check_entropy(event.dest_path)


class EntropyLogger():

    def Calculate_Entropy(self, data: bytes):
        if not data:
            return 0.0
        Bytes_Count = Counter(data)
        Total_Bytes = len(data)
        Entropy = 0.0
        for byte in Bytes_Count.values():
            Probability = byte / Total_Bytes
            Entropy -= Probability * math.log2(Probability)
        return Entropy

    def Check_File_Entropy(self, filepath, sample_size: int = 8192):
        try:
            with open(filepath, "rb") as file:
                data = file.read(sample_size)
            return self.Calculate_Entropy(data)
        except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
            logging.info(f"[DEBUG] could not read {filepath}: {e}")
            return -1.0


class ExtensionLogger():

    def __init__(self, window_seconds=10, threshold=5):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.recent_changes = deque()  # (timestamp, extension) pairs
        self.KNOWN_EXTENSIONS = {
            ".txt", ".docx", ".pdf", ".jpg", ".jpeg", ".png", ".svg",
            ".xlsx", ".pptx", ".csv", ".py", ".md", ".json", ".bin",
        }

    def Check_Extension_Change(self, src_path, dest_path, responder=None):
        old_ext = os.path.splitext(src_path)[1].lower()
        new_ext = os.path.splitext(dest_path)[1].lower()

        if old_ext != new_ext and new_ext not in self.KNOWN_EXTENSIONS:
            now = time.time()
            self.recent_changes.append((now, new_ext))
            self._prune_old_entries(now)

            logging.info(
                f"[DEBUG] unfamiliar extension change: {old_ext or '(none)'} -> "
                f"{new_ext or '(none)'} | {len(self.recent_changes)} in last "
                f"{self.window_seconds}s"
            )

            if len(self.recent_changes) >= self.threshold:
                reason = (
                    f"{len(self.recent_changes)} files renamed to unfamiliar "
                    f"extensions within {self.window_seconds}s (latest: "
                    f"{dest_path} -> {new_ext})"
                )
                logging.warning(f"MASS EXTENSION CHANGE DETECTED: {reason}")
                if responder:
                    responder.respond_to_file_threat(dest_path, reason)
                return True
        return False

    def _prune_old_entries(self, now):
        while self.recent_changes and now - self.recent_changes[0][0] > self.window_seconds:
            self.recent_changes.popleft()


class BackupLogger():

    def __init__(self, responder=None):
        self.responder = responder
        self.SUSPICIOUS_COMMANDS = [
            "lvremove",
            "btrfs subvolume delete",
            "zfs destroy",
            "timeshift --delete",
            "restic forget",
            "restic prune",
            "borg delete",
            "crontab -r",
        ]
        self.SUSPICIOUS_PATH_WIPES = [
            "/backup",
            "/mnt/backup",
            "/var/backups",
        ]

    def Check_Process(self):
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                Cmdline = " ".join(proc.info['cmdline'] or []).lower()

                for pattern in self.SUSPICIOUS_COMMANDS:
                    if pattern in Cmdline:
                        reason = f"backup deletion command ({pattern}): {Cmdline}"
                        logging.warning(
                            f"BACKUP DELETION ATTEMPT: PID {proc.info['pid']} "
                            f"({proc.info['name']}) ran: {Cmdline}"
                        )
                        if self.responder:
                            self.responder.respond_to_process_threat(proc.info['pid'], reason)

                if "rm" in Cmdline:
                    for path in self.SUSPICIOUS_PATH_WIPES:
                        if path in Cmdline:
                            reason = f"backup directory wipe ({path}): {Cmdline}"
                            logging.warning(
                                f"BACKUP DIRECTORY WIPE: PID {proc.info['pid']} "
                                f"ran: {Cmdline}"
                            )
                            if self.responder:
                                self.responder.respond_to_process_threat(proc.info['pid'], reason)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue


class ProcessTreeLogger():

    def __init__(self, responder=None):
        self.responder = responder

    def Check_Process_Trees(self):
        for proc in psutil.process_iter(['pid', 'name', 'ppid']):
            try:
                name = (proc.info['name'] or "").lower()
                if any(child in name for child in SUSPICIOUS_CHILDREN):
                    parent = psutil.Process(proc.info['ppid'])
                    parent_name = parent.name().lower()
                    if any(susp in parent_name for susp in SUSPICIOUS_PARENTS):
                        reason = f"{parent_name} (PID {parent.pid}) spawned {name} (PID {proc.info['pid']})"
                        logging.warning(f"SUSPICIOUS PROCESS TREE: {reason}")
                        if self.responder:
                            self.responder.respond_to_process_threat(proc.info['pid'], reason)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue


# ---------------------------------------------------------------------------
# RESPONSE / ALERTING
# ---------------------------------------------------------------------------

class AlertMailer():

    def __init__(self, smtp_server, smtp_port, sender_email, sender_password, recipient_email):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.recipient_email = recipient_email

    def send_alert(self, subject, body):
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.sender_email
        msg["To"] = self.recipient_email

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            logging.info(f"[DEBUG] alert email sent: {subject}")
        except Exception as e:
            logging.warning(f"[DEBUG] failed to send alert email: {e}")


class IncidentResponder():

    def __init__(self, mailer=None, dry_run=True, alert_cooldown_seconds=30):
        self.mailer = mailer
        self.dry_run = dry_run
        self.alert_cooldown_seconds = alert_cooldown_seconds
        self._last_alert_time = {}

    def _should_alert(self, key):
        now = time.time()
        last = self._last_alert_time.get(key, 0)
        if now - last >= self.alert_cooldown_seconds:
            self._last_alert_time[key] = now
            return True
        return False

    def _send_alert(self, subject, body, cooldown_key):
        if not self.mailer:
            return
        if not self._should_alert(cooldown_key):
            logging.info(f"[DEBUG] suppressing duplicate alert for {cooldown_key} (cooldown active)")
            return
        self.mailer.send_alert(subject=subject, body=body)

    def kill_process(self, pid):
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            proc.kill()
        except psutil.NoSuchProcess:
            pass

    def respond_to_process_threat(self, pid, reason):

        if self.dry_run:
            logging.warning(f"[DRY RUN] would terminate PID {pid} — reason: {reason}")
        else:
            self.kill_process(pid)
            logging.warning(f"TERMINATED PID {pid} — reason: {reason}")

        self._send_alert(
            subject="Ransomware Behavior Detected — Process",
            body=f"Detected suspicious process activity (PID {pid}): {reason}",
            cooldown_key=("process", pid),
        )

    def respond_to_file_threat(self, filepath, reason):

        logging.warning(f"FILE THREAT — {filepath}: {reason}")
        self._send_alert(
            subject="Ransomware Behavior Detected — File Activity",
            body=f"Detected suspicious file activity on {filepath}: {reason}",
            cooldown_key=("file", filepath),
        )

    # Kept for backward compatibility with any old call sites.
    def respond_to_threat(self, pid, reason):
        self.respond_to_process_threat(pid, reason)