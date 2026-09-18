from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import deque
from datetime import datetime
import time
import os
import json
import shutil


PROTECTED_FOLDER = "protected_folder"

TIME_WINDOW = 10

MODIFICATION_THRESHOLD = 10
RENAME_THRESHOLD = 5
EXTENSION_THRESHOLD = 5

INCIDENT_FOLDER = "incidents"
QUARANTINE_FOLDER = "quarantine"
LIVE_STATUS_FILE = "live_status.json"


class RansomShieldHandler(FileSystemEventHandler):

    def __init__(self):
        self.events = deque()
        self.incident_active = False

        self.update_live_status(
            "MONITORING",
            0,
            [],
            []
        )

    # ---------------------------------
    # LIVE DASHBOARD STATUS
    # ---------------------------------

    def update_live_status(
        self,
        status,
        score,
        reasons,
        affected_files
    ):

        data = {
            "status": status,
            "risk_score": score,
            "reasons": reasons,
            "affected_files": list(affected_files),
            "updated_at": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        }

        with open(LIVE_STATUS_FILE, "w") as file:
            json.dump(data, file, indent=4)

    # ---------------------------------
    # REMOVE OLD EVENTS
    # ---------------------------------

    def clean_old_events(self):

        current_time = time.time()

        while (
            self.events
            and current_time - self.events[0][0] > TIME_WINDOW
        ):
            self.events.popleft()

    # ---------------------------------
    # ADD EVENT
    # ---------------------------------

    def add_event(self, event_type, path):

        self.events.append(
            (time.time(), event_type, path)
        )

        self.analyze_behavior()

    # ---------------------------------
    # SAFE QUARANTINE
    # ---------------------------------

    def quarantine_files(self, affected_files):

        if not os.path.exists(QUARANTINE_FOLDER):
            os.makedirs(QUARANTINE_FOLDER)

        quarantined_files = []

        for file_path in affected_files:

            try:

                if not os.path.isfile(file_path):
                    continue

                filename = os.path.basename(file_path)

                timestamp = datetime.now().strftime(
                    "%Y%m%d_%H%M%S_%f"
                )

                quarantine_name = (
                    timestamp + "_" + filename
                )

                destination = os.path.join(
                    QUARANTINE_FOLDER,
                    quarantine_name
                )

                # SAFE ACTION:
                # Copy only. Original file remains untouched.
                shutil.copy2(
                    file_path,
                    destination
                )

                quarantined_files.append(
                    destination
                )

                print(
                    f"📦 QUARANTINED COPY: "
                    f"{file_path}"
                )

            except Exception as error:

                print(
                    f"⚠ Could not quarantine "
                    f"{file_path}: {error}"
                )

        return quarantined_files

    # ---------------------------------
    # INCIDENT REPORT
    # ---------------------------------

    def create_incident_report(
        self,
        score,
        modifications,
        renames,
        extension_changes,
        affected_files,
        reasons,
        quarantined_files
    ):

        if not os.path.exists(INCIDENT_FOLDER):
            os.makedirs(INCIDENT_FOLDER)

        timestamp = datetime.now()

        report = {

            "incident_id": timestamp.strftime(
                "INC-%Y%m%d-%H%M%S"
            ),

            "timestamp": timestamp.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            "threat": "Possible Ransomware Activity",

            "risk_score": score,

            "severity": "CRITICAL",

            "activity": {

                "modifications": modifications,

                "renames": renames,

                "extension_changes": extension_changes,

                "affected_files": len(affected_files)

            },

            "reasons": reasons,

            "response": {

                "status":
                    "PROTECTION MODE ACTIVATED",

                "action":
                    "Affected files copied to quarantine for investigation",

                "quarantine_count":
                    len(quarantined_files)

            },

            "affected_file_list":
                list(affected_files),

            "quarantined_file_list":
                quarantined_files
        }

        filename = os.path.join(
            INCIDENT_FOLDER,
            report["incident_id"] + ".json"
        )

        with open(filename, "w") as file:

            json.dump(
                report,
                file,
                indent=4
            )

        print("\n📄 INCIDENT REPORT CREATED")

        print(
            f"📁 Report: {filename}"
        )

    # ---------------------------------
    # BEHAVIOR ANALYSIS
    # ---------------------------------

    def analyze_behavior(self):

        self.clean_old_events()

        modifications = 0
        renames = 0
        extension_changes = 0

        affected_files = set()

        for _, event_type, path in self.events:

            if event_type == "modified":

                modifications += 1

                affected_files.add(path)

            elif event_type == "renamed":

                renames += 1

                affected_files.add(path)

            elif event_type == "extension":

                extension_changes += 1

                affected_files.add(path)

        # ---------------------------------
        # RISK SCORE
        # ---------------------------------

        score = 0

        reasons = []

        if modifications >= MODIFICATION_THRESHOLD:

            score += 30

            reasons.append(
                f"Rapid file modifications: {modifications}"
            )

        if renames >= RENAME_THRESHOLD:

            score += 25

            reasons.append(
                f"Mass file renaming: {renames}"
            )

        if extension_changes >= EXTENSION_THRESHOLD:

            score += 25

            reasons.append(
                f"Multiple extension changes: "
                f"{extension_changes}"
            )

        total_activity = (
            modifications
            + renames
            + extension_changes
        )

        if total_activity >= 20:

            score += 20

            reasons.append(
                f"High activity rate: "
                f"{total_activity} events"
            )

        score = min(score, 100)

        # ---------------------------------
        # STATUS
        # ---------------------------------

        live_status = "MONITORING"

        if score >= 80:

            live_status = "CRITICAL"

        elif score >= 50:

            live_status = "SUSPICIOUS"

        self.update_live_status(
            live_status,
            score,
            reasons,
            affected_files
        )

        # ---------------------------------
        # NORMAL
        # ---------------------------------

        if score < 50:

            if self.incident_active:

                print("\n" + "=" * 60)

                print(
                    "✅ INCIDENT CLEARED"
                )

                print(
                    "Activity returned to normal."
                )

                print("=" * 60)

                self.incident_active = False

            print(
                f"\n🟢 NORMAL ACTIVITY | "
                f"Risk Score: {score}/100"
            )

        # ---------------------------------
        # SUSPICIOUS
        # ---------------------------------

        elif score < 80:

            print("\n" + "-" * 55)

            print(
                "⚠ SUSPICIOUS ACTIVITY"
            )

            print(
                f"Risk Score: {score}/100"
            )

            for reason in reasons:

                print(
                    f"  • {reason}"
                )

            print("-" * 55)

        # ---------------------------------
        # CRITICAL
        # ---------------------------------

        else:

            if not self.incident_active:

                self.incident_active = True

                print("\n")

                print("=" * 60)

                print(
                    "🚨 RANSHIELD INCIDENT DETECTED 🚨"
                )

                print("=" * 60)

                print(
                    f"Risk Score: {score}/100"
                )

                print("\nActivity:")

                print(
                    f"  Modified files/events : "
                    f"{modifications}"
                )

                print(
                    f"  Renamed files/events  : "
                    f"{renames}"
                )

                print(
                    f"  Extension changes     : "
                    f"{extension_changes}"
                )

                print(
                    f"  Affected files        : "
                    f"{len(affected_files)}"
                )

                print("\nReasons:")

                for reason in reasons:

                    print(
                        f"  ⚠ {reason}"
                    )

                print(
                    "\n🚨 POSSIBLE RANSOMWARE "
                    "BEHAVIOR DETECTED"
                )

                # ---------------------------------
                # SAFE PROTECTION ACTION
                # ---------------------------------

                print(
                    "\n🛡️ PROTECTION MODE ACTIVATED"
                )

                print(
                    "Creating safe quarantine copies..."
                )

                quarantined_files = (
                    self.quarantine_files(
                        affected_files
                    )
                )

                print(
                    f"\n📦 Quarantine copies created: "
                    f"{len(quarantined_files)}"
                )

                # ---------------------------------
                # CREATE REPORT
                # ---------------------------------

                self.create_incident_report(

                    score,

                    modifications,

                    renames,

                    extension_changes,

                    affected_files,

                    reasons,

                    quarantined_files
                )

                print(
                    "\n🛡️ Protection action complete."
                )

                print(
                    "Original files were NOT deleted "
                    "or modified by RansomShield."
                )

                print("=" * 60)

            else:

                print(
                    f"🚨 Threat ongoing | "
                    f"Risk Score: {score}/100"
                )

    # ---------------------------------
    # FILE EVENTS
    # ---------------------------------

    def on_modified(self, event):

        if not event.is_directory:

            print(
                f"[*] MODIFIED: "
                f"{event.src_path}"
            )

            self.add_event(
                "modified",
                event.src_path
            )

    def on_created(self, event):

        if not event.is_directory:

            print(
                f"[+] CREATED: "
                f"{event.src_path}"
            )

    def on_deleted(self, event):

        if not event.is_directory:

            print(
                f"[-] DELETED: "
                f"{event.src_path}"
            )

    def on_moved(self, event):

        if not event.is_directory:

            old_extension = os.path.splitext(
                event.src_path
            )[1].lower()

            new_extension = os.path.splitext(
                event.dest_path
            )[1].lower()

            print(
                f"[!] RENAMED: "
                f"{event.src_path} -> "
                f"{event.dest_path}"
            )

            self.add_event(
                "renamed",
                event.dest_path
            )

            if old_extension != new_extension:

                print(
                    f"[!] EXTENSION CHANGE: "
                    f"{old_extension} -> "
                    f"{new_extension}"
                )

                self.add_event(
                    "extension",
                    event.dest_path
                )


# ---------------------------------
# START RANSHIELD
# ---------------------------------

if not os.path.exists(PROTECTED_FOLDER):

    os.makedirs(PROTECTED_FOLDER)

if not os.path.exists(INCIDENT_FOLDER):

    os.makedirs(INCIDENT_FOLDER)

if not os.path.exists(QUARANTINE_FOLDER):

    os.makedirs(QUARANTINE_FOLDER)


event_handler = RansomShieldHandler()

observer = Observer()

observer.schedule(
    event_handler,
    PROTECTED_FOLDER,
    recursive=True
)

observer.start()


print("=" * 60)

print(
    "                 RANSHIELD"
)

print(
    "       BEHAVIOR-BASED RANSOMWARE DETECTOR"
)

print("=" * 60)

print(
    f"Monitoring: "
    f"{os.path.abspath(PROTECTED_FOLDER)}"
)

print(
    "Status: 🟢 MONITORING"
)

print(
    f"Detection window: "
    f"{TIME_WINDOW} seconds"
)

print(
    "Press CTRL+C to stop."
)

print("=" * 60)


try:

    while True:

        time.sleep(1)

except KeyboardInterrupt:

    print(
        "\nStopping RansomShield..."
    )

    observer.stop()


observer.join()