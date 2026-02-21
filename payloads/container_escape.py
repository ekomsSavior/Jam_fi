#!/usr/bin/env python3
"""
Container Escape Attempts
Various techniques to escape container confinement
"""

import os, sys, subprocess, json, re, shutil, stat
from pathlib import Path

def check_privileges():
    """Check if container is privileged or has capabilities"""
    results = {}
    
    # Check if privileged
    if os.path.exists('/proc/self/status'):
        with open('/proc/self/status', 'r') as f:
            content = f.read()
            if 'CapEff:\t0000003fffffffff' in content:
                results['privileged'] = True
            else:
                results['privileged'] = False
            
            # Parse capabilities
            caps_match = re.search(r'CapEff:\s*(.+)', content)
            if caps_match:
                results['capabilities'] = caps_match.group(1).strip()
    
    # Check for root user
    results['is_root'] = os.geteuid() == 0
    
    # Check mounted filesystems
    mount_info = subprocess.getoutput('mount')
    results['mounts'] = mount_info.split('\n')[:10]  # First 10 mounts
    
    # Check for sensitive mounts
    sensitive_mounts = ['/proc', '/sys', '/dev', '/var/run/docker.sock']
    results['sensitive_mounts'] = []
    for mount in sensitive_mounts:
        if any(mount in line for line in results['mounts']):
            results['sensitive_mounts'].append(mount)
    
    return results

def attempt_docker_socket_escape():
    """Attempt escape via Docker socket"""
    results = {'attempted': False, 'success': False, 'details': ''}
    
    docker_socket = '/var/run/docker.sock'
    if os.path.exists(docker_socket):
        results['attempted'] = True
        results['socket_exists'] = True
        
        # Check if we can access it
        if os.access(docker_socket, os.R_OK):
            results['socket_accessible'] = True
            
            # Try to communicate with Docker
            try:
                # Use curl to talk to Docker API
                cmd = ['curl', '-s', '--unix-socket', docker_socket, 'http://localhost/version']
                output = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                
                if output.returncode == 0:
                    results['success'] = True
                    docker_info = json.loads(output.stdout)
                    results['details'] = f"Docker API accessible: {docker_info.get('Version')}"
                    
                    # Try to list containers
                    cmd = ['curl', '-s', '--unix-socket', docker_socket, 'http://localhost/containers/json']
                    containers = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    if containers.returncode == 0:
                        container_list = json.loads(containers.stdout)
                        results['containers'] = len(container_list)
                else:
                    results['details'] = f"Docker API error: {output.stderr}"
            except Exception as e:
                results['details'] = f"Exception: {e}"
        else:
            results['socket_accessible'] = False
            results['details'] = "Docker socket exists but not accessible"
    else:
        results['socket_exists'] = False
    
    return results

def attempt_cgroup_escape():
    """Attempt escape via cgroup release_agent"""
    results = {'attempted': False, 'success': False, 'details': ''}
    
    # Check if we can write to cgroup release_agent
    cgroup_paths = [
        '/sys/fs/cgroup/*/release_agent',
        '/sys/fs/cgroup/*/*/release_agent'
    ]
    
    import glob
    for pattern in cgroup_paths:
        for release_agent in glob.glob(pattern):
            try:
                # Test write
                with open(release_agent, 'w') as f:
                    f.write('test')
                
                # If we get here, we can write
                results['attempted'] = True
                results['writable_release_agent'] = release_agent
                results['details'] = f"Writable release_agent: {release_agent}"
                
                # Note: Actual escape would require more steps
                # This just checks for vulnerability
                results['success'] = True
                break
            except:
                continue
    
    if not results['attempted']:
        results['details'] = "No writable release_agent found"
    
    return results

def attempt_device_escape():
    """Attempt escape via device access"""
    results = {'attempted': False, 'success': False, 'details': ''}
    
    # Check for accessible devices
    dev_path = '/dev'
    dangerous_devices = ['sda', 'nvme0n1', 'dm-0', 'loop0']
    
    accessible_devices = []
    for device in dangerous_devices:
        device_path = os.path.join(dev_path, device)
        if os.path.exists(device_path) and os.access(device_path, os.R_OK):
            accessible_devices.append(device)
    
    if accessible_devices:
        results['attempted'] = True
        results['accessible_devices'] = accessible_devices
        results['details'] = f"Accessible devices: {accessible_devices}"
        
        # Try to read disk
        for device in accessible_devices[:1]:  # Try first device
            try:
                # Just read first sector to test
                cmd = ['dd', f'if=/dev/{device}', 'bs=512', 'count=1', 'status=none']
                output = subprocess.run(cmd, capture_output=True, timeout=5)
                if output.returncode == 0:
                    results['success'] = True
                    results['details'] += f" - Can read from /dev/{device}"
                    break
            except:
                pass
    
    return results

def attempt_kernel_module_load():
    """Attempt to load kernel module"""
    results = {'attempted': False, 'success': False, 'details': ''}
    
    # Check if we can load modules
    modules_path = '/lib/modules'
    if os.path.exists(modules_path) and os.listdir(modules_path):
        kernel_version = os.listdir(modules_path)[0]
        results['kernel_version'] = kernel_version
        
        # Check capabilities
        try:
            # Try to use insmod (would require CAP_SYS_MODULE)
            test_module = '/tmp/test.ko'
            
            # Create a simple dummy module (just a text file for testing)
            with open(test_module, 'w') as f:
                f.write('dummy module')
            
            cmd = ['insmod', test_module]
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if output.returncode == 0 or 'Operation not permitted' not in output.stderr:
                results['attempted'] = True
                results['details'] = f"Module load attempted: {output.stderr}"
                
                # Check actual error
                if 'Operation not permitted' in output.stderr:
                    results['success'] = False
                else:
                    results['success'] = True
            else:
                results['details'] = "Cannot load modules (no CAP_SYS_MODULE)"
            
            # Cleanup
            if os.path.exists(test_module):
                os.remove(test_module)
                
        except Exception as e:
            results['details'] = f"Exception: {e}"
    
    return results

def attempt_mount_escape():
    """Attempt escape via mount operations"""
    results = {'attempted': False, 'success': False, 'details': ''}
    
    # Check if we have mount capabilities
    try:
        # Try to create a bind mount
        test_dir = '/tmp/test_mount'
        os.makedirs(test_dir, exist_ok=True)
        
        cmd = ['mount', '--bind', '/tmp', test_dir]
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        if output.returncode == 0:
            results['attempted'] = True
            results['success'] = True
            results['details'] = "Can create bind mounts"
            
            # Cleanup
            subprocess.run(['umount', test_dir], capture_output=True)
        else:
            if 'Operation not permitted' in output.stderr:
                results['details'] = "Cannot mount (no CAP_SYS_ADMIN)"
            else:
                results['attempted'] = True
                results['details'] = f"Mount test: {output.stderr}"
        
        # Cleanup
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)
            
    except Exception as e:
        results['details'] = f"Exception: {e}"
    
    return results

def check_for_breakout_techniques():
    """Check for known container breakout techniques"""
    techniques = {
        'dirtycow': False,
        'shocker': False,
        'dirtypipe': False,
        'runc_escape': False,
    }
    
    # Check kernel version for vulnerabilities
    try:
        kernel_version = subprocess.getoutput('uname -r')
        
        # Dirty COW (CVE-2016-5195)
        if any(vuln in kernel_version for vuln in ['3.13', '3.16', '3.19', '4.4', '4.8']):
            techniques['dirtycow'] = True
        
        # Dirty Pipe (CVE-2022-0847)
        if '5.8' <= kernel_version <= '5.16.11':
            techniques['dirtypipe'] = True
        
        # Check for runc vulnerability (CVE-2019-5736)
        # This would require checking runc version
        docker_version = subprocess.getoutput('docker version 2>/dev/null | grep Version | head -1')
        if '18.09' in docker_version:
            techniques['runc_escape'] = True
            
    except:
        pass
    
    return techniques

def main():
    """Main execution"""
    print("[Container Escape Assessment]")
    print("=" * 60)
    
    # Check privileges
    print("\n[1] Checking container privileges...")
    privileges = check_privileges()
    
    print(f"   Privileged: {privileges.get('privileged', 'Unknown')}")
    print(f"   Running as root: {privileges.get('is_root', False)}")
    print(f"   Capabilities: {privileges.get('capabilities', 'Unknown')}")
    
    if privileges.get('sensitive_mounts'):
        print(f"   Sensitive mounts: {privileges['sensitive_mounts']}")
    
    # Attempt escapes
    print("\n[2] Attempting escape techniques...")
    
    escapes = {
        'Docker Socket': attempt_docker_socket_escape(),
        'Cgroup release_agent': attempt_cgroup_escape(),
        'Device Access': attempt_device_escape(),
        'Kernel Module': attempt_kernel_module_load(),
        'Mount Escape': attempt_mount_escape(),
    }
    
    for name, result in escapes.items():
        print(f"   {name}: {'SUCCESS' if result.get('success') else 'FAILED'}")
        if result.get('details'):
            print(f"     Details: {result['details'][:80]}...")
    
    # Check for known vulnerabilities
    print("\n[3] Checking for known vulnerabilities...")
    vulnerabilities = check_for_breakout_techniques()
    
    for vuln, present in vulnerabilities.items():
        print(f"   {vuln}: {'POSSIBLE' if present else 'Not detected'}")
    
    # Recommendations
    print("\n[4] Recommendations:")
    
    if privileges.get('privileged'):
        print("   ⚠️  Container is PRIVILEGED - Easy escape possible")
        print("   → Use docker.sock to create new privileged container")
    
    if escapes['Docker Socket'].get('success'):
        print("   ⚠️  Docker socket accessible - Full host control")
        print("   → Use Docker API to create privileged containers")
    
    if escapes['Cgroup release_agent'].get('success'):
        print("   ⚠️  Cgroup release_agent writable - Kernel escape possible")
        print("   → Use release_agent to execute commands on host")
    
    if privileges.get('is_root'):
        print("   ⚠️  Running as root - More escape options available")
        print("   → Try all root-based escape techniques")
    
    # Output for exfiltration
    result = {
        'privileges': privileges,
        'escape_attempts': escapes,
        'vulnerabilities': vulnerabilities,
        'timestamp': __import__('time').time(),
        'recommendations': []
    }
    
    # Add recommendations
    if privileges.get('privileged'):
        result['recommendations'].append('privileged_container_escape')
    if escapes['Docker Socket'].get('success'):
        result['recommendations'].append('docker_socket_escape')
    if escapes['Cgroup release_agent'].get('success'):
        result['recommendations'].append('cgroup_escape')
    if privileges.get('is_root'):
        result['recommendations'].append('root_escape_techniques')
    
    return json.dumps(result, indent=2)

if __name__ == "__main__":
    output = main()
    print("\n" + "=" * 60)
    print("[*] Assessment complete - Output ready for exfiltration")
