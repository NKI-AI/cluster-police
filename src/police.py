#!/usr/bin/env python3
import grp
import logging
import re
import subprocess

import pyinotify
import yaml


# Load configuration from YAML file
def load_config():
    with open("config.yaml", "r") as file:
        return yaml.safe_load(file)


config = load_config()
whitelisted_commands = config["whitelisted_commands"]
blacklisted_commands = config["blacklisted_commands"]
sudo_group_name = "sudo"

# Initialize logging
logging.basicConfig(
    filename="/var/log/cluster_police.log",
    level=logging.INFO,
    format="%(asctime)s:%(levelname)s:%(message)s",
)


class AuditLogEventHandler(pyinotify.ProcessEvent):
    command_regex = re.compile(r'exe="([^"]+)"')
    user_regex = re.compile(r"uid=([\w-]+)")

    def is_user_privileged(self, username):
        """Check if the user is root or in the sudo group"""
        if username == "root":
            return True

        try:
            sudo_gid = grp.getgrnam(sudo_group_name).gr_gid
        except KeyError:
            return False  # Group doesn't exist

        user_groups = [g.gr_gid for g in grp.getgrall() if username in g.gr_mem]
        return sudo_gid in user_groups

    def apply_cgroup(self, pid):
        subprocess.run(["cgclassify", "-g", "cpu,cpuacct:/limited", str(pid)])

    def kill_process(self, pid):
        subprocess.run(["kill", "-9", str(pid)])

    def notify_user(self, username, message):
        subprocess.run(["wall", f"User {username}: {message}"])

    def process_IN_MODIFY(self, event):
        with open(event.pathname, "r") as log_file:
            for line in log_file.readlines():
                command_match = self.command_regex.search(line)
                user_match = self.user_regex.search(line)
                if command_match and user_match:
                    command_path = command_match.group(1)
                    username = user_match.group(1)
                    pid = int(
                        line.split()[1]
                    )  # Assuming PID is the second element in the log line
                    if command_path in blacklisted_commands:
                        self.notify_user(
                            username,
                            f"Your process {command_path} has been terminated due to policy restrictions.",
                        )
                        self.kill_process(pid)
                    elif (
                        command_path not in whitelisted_commands
                        and not self.is_user_privileged(username)
                    ):
                        self.apply_cgroup(pid)

    def process_IN_MOVED_TO(self, event):
        # A new file has been moved into the directory, likely due to log rotation
        if event.pathname.endswith("audit.log"):
            logging.info("Detected new audit.log due to log rotation. Updating watch.")
            wm.update_watch(wm.get_wd(event.path), "/var/log/audit/audit.log")


# Set up watch manager
wm = pyinotify.WatchManager()
handler = AuditLogEventHandler()
notifier = pyinotify.Notifier(wm, handler)

# Add a watch on the audit log directory for MODIFY and MOVE events
audit_log_path = "/var/log/audit/audit.log"
audit_dir_path = "/var/log/audit"
wm.add_watch(audit_log_path, pyinotify.IN_MODIFY)
wm.add_watch(audit_dir_path, pyinotify.IN_MOVED_TO)

# Loop forever, processing events
notifier.loop()
