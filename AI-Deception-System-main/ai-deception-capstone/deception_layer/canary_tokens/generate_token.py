import requests

def create_aws_canary_token(webhook_url, alert_email):
    """
    Generates a fake AWS API key using Canarytokens API.
    """
    url = "https://canarytokens.org/generate"
    payload = {
        "type": "aws_keys",
        "email": alert_email,
        "memo": "Decoy AWS Key on Production Server",
        "webhook_url": webhook_url
    }
    
    try:
        response = requests.post(url, data=payload, timeout=10)
        token_data = response.json()
        
        print("\n[+] Decoy Token Generated Successfully!")
        print("--------------------------------------------------")
        print(f"aws_access_key_id = {token_data.get('access_key_id', 'ACCESS_KEY_PLACEHOLDER')}")
        print(f"aws_secret_access_key = {token_data.get('secret_access_key', 'SECRET_KEY_PLACEHOLDER')}")
        print("--------------------------------------------------")
        
    except Exception as e:
        print(f"[!] Error connecting to Canarytokens API: {e}")

if __name__ == "__main__":
    create_aws_canary_token("https://your-soc-webhook.com", "security@company.com")