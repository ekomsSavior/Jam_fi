#!/usr/bin/env python3
"""
Cloud Environment Detector for ROGUE
Detects AWS, Azure, GCP, DigitalOcean, and other cloud platforms
AUTHOR: Rogue Red Team
"""

import os, sys, subprocess, json, requests, socket, re
from urllib.request import Request, urlopen
from urllib.error import URLError

class CloudDetector:
    def __init__(self):
        self.cloud_provider = None
        self.cloud_metadata = {}
        self.cloud_features = {}
        self.detection_methods = []
        
    def detect_all(self):
        """Run all detection methods"""
        providers = [
            self.detect_aws,
            self.detect_azure,
            self.detect_gcp,
            self.detect_digitalocean,
            self.detect_oracle_cloud,
            self.detect_linode,
            self.detect_vultr,
            self.detect_hetzner,
            self.detect_docker,
            self.detect_kubernetes,
            self.detect_container,
            self.detect_vm
        ]
        
        for method in providers:
            result = method()
            if result:
                self.detection_methods.append(method.__name__)
        
        return self.cloud_provider
    
    def detect_aws(self):
        """Detect AWS EC2 instance"""
        try:
            # Check AWS metadata service
            req = Request("http://169.254.169.254/latest/meta-data/")
            req.add_header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            
            # First get token
            try:
                token_req = Request("http://169.254.169.254/latest/api/token")
                token_req.add_header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
                token_req.method = "PUT"
                
                token = urlopen(token_req, timeout=2).read().decode()
                req.add_header("X-aws-ec2-metadata-token", token)
            except:
                pass
            
            response = urlopen(req, timeout=2)
            if response.getcode() == 200:
                self.cloud_provider = "aws"
                
                # Collect AWS metadata
                metadata_urls = {
                    'instance-id': 'instance-id',
                    'instance-type': 'instance-type',
                    'ami-id': 'ami-id',
                    'region': 'placement/availability-zone',
                    'account-id': 'identity-credentials/ec2/info',
                    'vpc-id': 'network/interfaces/macs/0/vpc-id',
                    'subnet-id': 'network/interfaces/macs/0/subnet-id',
                    'security-groups': 'security-groups'
                }
                
                for key, path in metadata_urls.items():
                    try:
                        meta_req = Request(f"http://169.254.169.254/latest/meta-data/{path}")
                        if 'token' in locals():
                            meta_req.add_header("X-aws-ec2-metadata-token", token)
                        data = urlopen(meta_req, timeout=2).read().decode()
                        self.cloud_metadata[f"aws_{key}"] = data
                    except:
                        pass
                
                # Check for AWS-specific files
                if os.path.exists('/sys/hypervisor/uuid'):
                    with open('/sys/hypervisor/uuid', 'r') as f:
                        if f.read().startswith('ec2'):
                            self.cloud_metadata['aws_uuid'] = True
                
                # Check for cloud-init AWS datasource
                if os.path.exists('/var/lib/cloud/instance/datasource'):
                    with open('/var/lib/cloud/instance/datasource', 'r') as f:
                        if 'aws' in f.read().lower():
                            self.cloud_metadata['aws_cloud_init'] = True
                
                # Check IMDSv2 capability
                self.cloud_features['aws_imdsv2'] = 'token' in locals()
                
                print(f"[CLOUD] Detected AWS EC2 instance")
                print(f"       Instance Type: {self.cloud_metadata.get('aws_instance-type', 'Unknown')}")
                print(f"       Region: {self.cloud_metadata.get('aws_region', 'Unknown')}")
                return True
                
        except Exception as e:
            pass
        
        # Additional AWS checks
        aws_indicators = [
            ('/sys/devices/virtual/dmi/id/product_name', lambda x: 'amazon' in x.lower()),
            ('/sys/devices/virtual/dmi/id/bios_version', lambda x: 'amazon' in x.lower()),
            ('/sys/class/dmi/id/chassis_vendor', lambda x: 'amazon' in x.lower()),
            ('/sys/class/dmi/id/product_version', lambda x: 'amazon' in x.lower()),
        ]
        
        for file_path, check_func in aws_indicators:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read().lower()
                    if check_func(content):
                        self.cloud_provider = "aws"
                        print("[CLOUD] Detected AWS via DMI")
                        return True
        
        return False
    
    def detect_azure(self):
        """Detect Azure VM"""
        try:
            # Azure metadata service
            req = Request("http://169.254.169.254/metadata/instance?api-version=2021-02-01")
            req.add_header("Metadata", "true")
            
            response = urlopen(req, timeout=2)
            if response.getcode() == 200:
                data = json.loads(response.read().decode())
                self.cloud_provider = "azure"
                self.cloud_metadata['azure_full'] = data
                
                # Extract key metadata
                if 'compute' in data:
                    compute = data['compute']
                    self.cloud_metadata['azure_vmId'] = compute.get('vmId')
                    self.cloud_metadata['azure_vmSize'] = compute.get('vmSize')
                    self.cloud_metadata['azure_location'] = compute.get('location')
                    self.cloud_metadata['azure_subscriptionId'] = compute.get('subscriptionId')
                    self.cloud_metadata['azure_resourceGroupName'] = compute.get('resourceGroupName')
                
                print(f"[CLOUD] Detected Azure VM")
                print(f"       VM Size: {self.cloud_metadata.get('azure_vmSize', 'Unknown')}")
                print(f"       Location: {self.cloud_metadata.get('azure_location', 'Unknown')}")
                return True
                
        except Exception as e:
            pass
        
        # Check for Azure-specific files
        azure_indicators = [
            ('/sys/class/dmi/id/chassis_asset_tag', lambda x: '7783-7084-3265-9085-8269-3286-77' in x),
            ('/sys/class/dmi/id/sys_vendor', lambda x: 'microsoft' in x.lower()),
            ('/sys/class/dmi/id/product_name', lambda x: 'virtual machine' in x.lower() and 'microsoft' in x.lower()),
            ('/var/lib/cloud/instance/datasource', lambda x: 'azure' in x.lower()),
        ]
        
        for file_path, check_func in azure_indicators:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                    if check_func(content):
                        self.cloud_provider = "azure"
                        print("[CLOUD] Detected Azure via system files")
                        return True
        
        return False
    
    def detect_gcp(self):
        """Detect Google Cloud Platform"""
        try:
            # GCP metadata service
            req = Request("http://metadata.google.internal/computeMetadata/v1/")
            req.add_header("Metadata-Flavor", "Google")
            
            response = urlopen(req, timeout=2)
            if response.getcode() == 200:
                self.cloud_provider = "gcp"
                
                # Collect GCP metadata
                metadata_endpoints = [
                    ('instance/id', 'gcp_instance_id'),
                    ('instance/machine-type', 'gcp_machine_type'),
                    ('instance/zone', 'gcp_zone'),
                    ('project/project-id', 'gcp_project_id'),
                    ('instance/network-interfaces/0/ip', 'gcp_internal_ip'),
                    ('instance/service-accounts/default/email', 'gcp_service_account'),
                ]
                
                for endpoint, key in metadata_endpoints:
                    try:
                        meta_req = Request(f"http://metadata.google.internal/computeMetadata/v1/{endpoint}")
                        meta_req.add_header("Metadata-Flavor", "Google")
                        data = urlopen(meta_req, timeout=2).read().decode()
                        self.cloud_metadata[key] = data
                    except:
                        pass
                
                print(f"[CLOUD] Detected Google Cloud Platform")
                print(f"       Project: {self.cloud_metadata.get('gcp_project_id', 'Unknown')}")
                print(f"       Zone: {self.cloud_metadata.get('gcp_zone', 'Unknown')}")
                return True
                
        except Exception as e:
            pass
        
        # Check for GCP-specific indicators
        gcp_indicators = [
            ('/sys/class/dmi/id/product_name', lambda x: 'google' in x.lower()),
            ('/sys/class/dmi/id/sys_vendor', lambda x: 'google' in x.lower()),
            ('/sys/class/dmi/id/bios_vendor', lambda x: 'google' in x.lower()),
            ('/var/lib/cloud/instance/datasource', lambda x: 'gcp' in x.lower() or 'google' in x.lower()),
        ]
        
        for file_path, check_func in gcp_indicators:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read().lower()
                    if check_func(content):
                        self.cloud_provider = "gcp"
                        print("[CLOUD] Detected GCP via system files")
                        return True
        
        return False
    
    def detect_digitalocean(self):
        """Detect DigitalOcean droplet"""
        try:
            req = Request("http://169.254.169.254/metadata/v1.json")
            response = urlopen(req, timeout=2)
            if response.getcode() == 200:
                data = json.loads(response.read().decode())
                self.cloud_provider = "digitalocean"
                self.cloud_metadata['digitalocean_full'] = data
                
                print(f"[CLOUD] Detected DigitalOcean droplet")
                print(f"       Droplet ID: {data.get('droplet_id', 'Unknown')}")
                print(f"       Region: {data.get('region', 'Unknown')}")
                return True
                
        except Exception as e:
            pass
        
        # Check DO-specific files
        if os.path.exists('/etc/digitalocean'):
            self.cloud_provider = "digitalocean"
            print("[CLOUD] Detected DigitalOcean via /etc/digitalocean")
            return True
        
        return False
    
    def detect_oracle_cloud(self):
        """Detect Oracle Cloud Infrastructure"""
        try:
            req = Request("http://169.254.169.254/opc/v1/instance/")
            response = urlopen(req, timeout=2)
            if response.getcode() == 200:
                data = json.loads(response.read().decode())
                self.cloud_provider = "oracle"
                self.cloud_metadata['oracle_full'] = data
                
                print(f"[CLOUD] Detected Oracle Cloud Infrastructure")
                print(f"       Compartment: {data.get('compartmentId', 'Unknown')}")
                return True
                
        except Exception as e:
            pass
        
        return False
    
    def detect_linode(self):
        """Detect Linode instance"""
        try:
            # Linode uses a specific metadata endpoint
            req = Request("http://169.254.169.254/v1")
            response = urlopen(req, timeout=2)
            if response.getcode() == 200:
                # Check if response contains Linode-like data
                data = response.read().decode()
                if 'linode' in data.lower():
                    self.cloud_provider = "linode"
                    print("[CLOUD] Detected Linode")
                    return True
        except:
            pass
        
        # Check for Linode kernel
        result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
        if 'linode' in result.stdout.lower():
            self.cloud_provider = "linode"
            print("[CLOUD] Detected Linode via kernel")
            return True
        
        return False
    
    def detect_vultr(self):
        """Detect Vultr instance"""
        try:
            req = Request("http://169.254.169.254/v1.json")
            response = urlopen(req, timeout=2)
            if response.getcode() == 200:
                data = json.loads(response.read().decode())
                if 'vultr' in str(data).lower():
                    self.cloud_provider = "vultr"
                    print("[CLOUD] Detected Vultr")
                    return True
        except:
            pass
        
        return False
    
    def detect_hetzner(self):
        """Detect Hetzner Cloud"""
        try:
            req = Request("http://169.254.169.254/hetzner/v1/metadata")
            response = urlopen(req, timeout=2)
            if response.getcode() == 200:
                data = json.loads(response.read().decode())
                self.cloud_provider = "hetzner"
                self.cloud_metadata['hetzner_full'] = data
                print("[CLOUD] Detected Hetzner Cloud")
                return True
        except:
            pass
        
        # Check for Hetzner-specific files
        if os.path.exists('/etc/hetzner'):
            self.cloud_provider = "hetzner"
            print("[CLOUD] Detected Hetzner via /etc/hetzner")
            return True
        
        return False
    
    def detect_docker(self):
        """Detect Docker container"""
        # Check for .dockerenv file
        if os.path.exists('/.dockerenv'):
            self.cloud_provider = "docker"
            self.cloud_features['container'] = True
            print("[CLOUD] Detected Docker container")
            return True
        
        # Check cgroups
        if os.path.exists('/proc/1/cgroup'):
            with open('/proc/1/cgroup', 'r') as f:
                content = f.read()
                if 'docker' in content:
                    self.cloud_provider = "docker"
                    self.cloud_features['container'] = True
                    print("[CLOUD] Detected Docker via cgroups")
                    return True
        
        return False
    
    def detect_kubernetes(self):
        """Detect Kubernetes pod"""
        # Check for Kubernetes service account
        if os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount'):
            self.cloud_provider = "kubernetes"
            self.cloud_features['container'] = True
            self.cloud_features['orchestrated'] = True
            
            # Try to get pod info
            try:
                with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace', 'r') as f:
                    namespace = f.read().strip()
                    self.cloud_metadata['k8s_namespace'] = namespace
            except:
                pass
            
            print("[CLOUD] Detected Kubernetes pod")
            return True
        
        # Check environment variables
        env_vars = os.environ
        k8s_vars = ['KUBERNETES_SERVICE_HOST', 'KUBERNETES_SERVICE_PORT']
        if any(var in env_vars for var in k8s_vars):
            self.cloud_provider = "kubernetes"
            self.cloud_features['container'] = True
            self.cloud_features['orchestrated'] = True
            print("[CLOUD] Detected Kubernetes via environment")
            return True
        
        return False
    
    def detect_container(self):
        """Generic container detection"""
        # Check various container indicators
        container_indicators = [
            ('/proc/self/cgroup', lambda x: any(indicator in x for indicator in 
                ['docker', 'containerd', 'crio', 'podman', 'kubepods'])),
            ('/proc/1/sched', lambda x: 'bash' not in x and 'init' not in x),  # Non-standard init process
        ]
        
        for file_path, check_func in container_indicators:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                    if check_func(content):
                        if not self.cloud_provider:  # Only set if not already detected
                            self.cloud_provider = "container"
                        self.cloud_features['container'] = True
                        print("[CLOUD] Detected generic container")
                        return True
        
        return False
    
    def detect_vm(self):
        """Detect if running in any VM (including cloud VMs)"""
        vm_indicators = [
            ('/sys/class/dmi/id/product_name', lambda x: any(vm_indicator in x.lower() for vm_indicator in 
                ['virtualbox', 'vmware', 'kvm', 'qemu', 'virtual', 'xen', 'hyper-v'])),
            ('/sys/class/dmi/id/sys_vendor', lambda x: any(vendor in x.lower() for vendor in 
                ['vmware', 'innotek', 'qemu', 'microsoft', 'xen'])),
            ('/proc/cpuinfo', lambda x: 'hypervisor' in x.lower()),
        ]
        
        for file_path, check_func in vm_indicators:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read().lower()
                    if check_func(content):
                        self.cloud_features['virtual_machine'] = True
                        print("[CLOUD] Detected virtualization")
                        return True
        
        return False
    
    def get_cloud_info(self):
        """Get comprehensive cloud information"""
        info = {
            'provider': self.cloud_provider,
            'metadata': self.cloud_metadata,
            'features': self.cloud_features,
            'detection_methods': self.detection_methods,
            'is_cloud': bool(self.cloud_provider),
            'is_container': self.cloud_features.get('container', False),
            'is_vm': self.cloud_features.get('virtual_machine', False),
            'is_orchestrated': self.cloud_features.get('orchestrated', False),
        }
        
        # Add network information
        try:
            hostname = socket.gethostname()
            info['hostname'] = hostname
            
            # Try to get public IP
            try:
                public_ip = requests.get('https://api.ipify.org', timeout=3).text
                info['public_ip'] = public_ip
            except:
                pass
        except:
            pass
        
        return info
    
    def get_recommended_tactics(self):
        """Get recommended tactics based on cloud environment"""
        tactics = {
            'persistence': [],
            'collection': [],
            'lateral': [],
            'evasion': [],
            'payloads': [],
        }
        
        if not self.cloud_provider:
            return tactics
        
        # Common cloud tactics
        tactics['persistence'].extend([
            'cloud_init_modification',
            'cron_cloud_metadata',
            'service_account_persistence',
        ])
        
        tactics['collection'].extend([
            'cloud_metadata_collection',
            'credential_harvesting',
            'configuration_dumping',
        ])
        
        tactics['evasion'].extend([
            'low_profile_beaconing',
            'encrypted_storage',
            'container_aware_hiding',
        ])
        
        # Provider-specific tactics
        if self.cloud_provider == 'aws':
            tactics['collection'].extend([
                'aws_credential_harvesting',
                'aws_metadata_exfiltration',
                's3_bucket_enumeration',
            ])
            tactics['lateral'].extend([
                'aws_instance_profile_abuse',
                'vpc_peer_hijacking',
                'security_group_modification',
            ])
            tactics['payloads'].extend([
                'aws_credential_stealer.py',
                's3_scanner.py',
                'aws_lateral.py',
            ])
        
        elif self.cloud_provider == 'azure':
            tactics['collection'].extend([
                'azure_managed_identity_harvesting',
                'azure_metadata_collection',
                'key_vault_access',
            ])
            tactics['lateral'].extend([
                'azure_vnet_lateral',
                'managed_identity_abuse',
                'automation_account_access',
            ])
            tactics['payloads'].extend([
                'azure_cred_harvester.py',
                'key_vault_scanner.py',
                'azure_lateral.py',
            ])
        
        elif self.cloud_provider == 'gcp':
            tactics['collection'].extend([
                'gcp_service_account_harvesting',
                'gcp_metadata_collection',
                'cloud_storage_access',
            ])
            tactics['lateral'].extend([
                'gcp_project_lateral',
                'service_account_impersonation',
                'vpc_peering_abuse',
            ])
            tactics['payloads'].extend([
                'gcp_cred_harvester.py',
                'gcp_bucket_scanner.py',
                'gcp_lateral.py',
            ])
        
        elif self.cloud_provider in ['docker', 'kubernetes', 'container']:
            tactics['persistence'].extend([
                'container_image_modification',
                'kubernetes_cronjob',
                'docker_socket_persistence',
            ])
            tactics['collection'].extend([
                'container_breakout_attempt',
                'kubernetes_secret_harvesting',
                'docker_config_harvesting',
            ])
            tactics['lateral'].extend([
                'kubernetes_pod_lateral',
                'container_escape',
                'cluster_role_abuse',
            ])
            tactics['evasion'].extend([
                'container_fileless_execution',
                'memory_only_persistence',
                'ephemeral_storage_abuse',
            ])
            tactics['payloads'].extend([
                'container_escape.py',
                'k8s_secret_stealer.py',
                'docker_breakout.py',
            ])
        
        return tactics

# Quick test function
def test_detection():
    detector = CloudDetector()
    detector.detect_all()
    
    print("\n" + "="*60)
    print("CLOUD DETECTION RESULTS")
    print("="*60)
    
    if detector.cloud_provider:
        print(f"Provider: {detector.cloud_provider.upper()}")
        print(f"Metadata: {json.dumps(detector.cloud_metadata, indent=2)}")
        print(f"Features: {json.dumps(detector.cloud_features, indent=2)}")
        
        # Get recommendations
        tactics = detector.get_recommended_tactics()
        print("\nRecommended Tactics:")
        for category, items in tactics.items():
            if items:
                print(f"  {category.upper()}:")
                for item in items:
                    print(f"    - {item}")
    else:
        print("No cloud environment detected (likely bare metal or undetected VM)")
    
    print("="*60)

if __name__ == "__main__":
    test_detection()
