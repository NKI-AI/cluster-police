# cluster-police
Python utilities to prevent over usage of resources by cluster users

Step 1: Configure cgroups to limit CPU time
--------------------------------------------
You need to create a cgroup that sets the CPU time limit for user processes. You can use the cpuacct controller to 
monitor and the cpu controller to limit the CPU usage.

```bash
sudo cgcreate -g cpu,cpuacct:/limited
sudo cgset -r cpu.cfs_period_us=100000 limited  # 100ms
sudo cgset -r cpu.cfs_quota_us=50000 limited  # 50ms of CPU time on all cores per 100ms
```

Step 2: Install and Configure auditd
------------------------------------
1. Install auditd if it is not yet installed
    ```bash
    sudo apt-get update
    sudo apt-get install auditd
    ```
2. Configure auditd to monitor the `execve` system call, which is used whenever a new process is started:
    `sudo auditctl -a always,exit -F arch=b64 -S execve -k process-monitor`
    The -k option adds a key to the rule that you can use to search the audit logs for relevant entries.


Step 3: Install and Configure cluster-police
# To add as a service:
1. Copy the cluster-police.service file to /etc/systemd/system/
2. Run the following commands:
    `systemctl daemon-reload`
    `systemctl enable cluster-police.service`
    `systemctl start cluster-police.service`
3. To check the status of the service, run:
    `systemctl status cluster-police.service`