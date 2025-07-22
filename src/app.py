from flask import Flask, request, jsonify
import requests
import logging
import os
from openai import OpenAI
from config import SLACK_WEBHOOK_URL, OPENAI_API_KEY, REGEXP, SLACK_BOT_TOKEN, SLACK_CHANNELS, GITHUB_WEBHOOK_SECRET, USER_PROMPT, SYSTEM_PROMPT
import re
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import hmac
import hashlib
import json
# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Debug: Check what we get from environment
# Debug log removed for security
SLACK_CHANNELS = [f"#{channel.strip()}" for channel in SLACK_CHANNELS.split(",") if channel.strip()]


# OpenAI client initialization with new API
try:
    openai_client = OpenAI(api_key=OPENAI_API_KEY)
    logger.info("OpenAI client initialized successfully")
except Exception as e:
    logger.error(f"OpenAI client initialization failed: {e}")
    openai_client = None

# Slack Bot client initialization (çoklu kanal için)
try:
    slack_client = WebClient(token=SLACK_BOT_TOKEN) if SLACK_BOT_TOKEN else None
    if slack_client:
        logger.info("Slack Bot client initialized successfully")
    else:
        logger.warning("Slack Bot Token not found, using webhook fallback")
except Exception as e:
    logger.error(f"Slack Bot client initialization failed: {e}")
    slack_client = None


def verify_github_signature(request, secret):
    signature_header = request.headers.get('X-Hub-Signature-256')
    if signature_header is None:
        return False  # Signature header yoksa geçersiz
    
    sha_name, signature = signature_header.split('=')
    if sha_name != 'sha256':
        return False  # Sadece sha256 destekleniyor
    
    # Raw payload bytes
    payload = request.data
    
    # HMAC SHA256 hesapla
    mac = hmac.new(secret.encode(), msg=payload, digestmod=hashlib.sha256)
    expected_signature = mac.hexdigest()
    
    # Güvenli karşılaştırma
    return hmac.compare_digest(expected_signature, signature)

@app.route('/github-webhook', methods=['POST'])
def github_webhook():
    try:
        if not GITHUB_WEBHOOK_SECRET:
            logger.error("GITHUB_WEBHOOK_SECRET environment variable is not set")
            return jsonify({"error": "Server misconfiguration"}), 500

        # Debug: Log important headers
        # Validate GitHub webhook headers
        github_event = request.headers.get('X-GitHub-Event')
        logger.info(f"Received GitHub webhook: {github_event} event")
        
        if not verify_github_signature(request, GITHUB_WEBHOOK_SECRET):
            logger.warning("Invalid GitHub webhook signature")
            return jsonify({"error": "Invalid signature"}), 403
        # Request validation
        if not request.json:
            logger.warning("Empty request received")
            return jsonify({"error": "Empty request"}), 400
        
        data = request.json
        
        # Debug: Log FULL incoming payload structure (WARNING: Can be large!)

        # full_payload = json.dumps(data, indent=2, ensure_ascii=False)
        # logger.info(f"GitHub Webhook FULL Payload:\n{full_payload}")
        # logger.info(f"Payload size: {len(full_payload)} characters")
        
        logger.info(f"Webhook received for repository: {data.get('repository', {}).get('name', 'unknown')}")
        
        # Data validation
        if 'commits' not in data:
            logger.warning("No commits found in webhook data")
            return jsonify({"error": "No commits found"}), 400
        
        commits = data.get("commits", [])
        repo = data.get("repository", {}).get("name", "unknown repo")
        
        if not commits:
            logger.info("No commits to process")
            return jsonify({"status": "no commits to process"}), 200
        
        processed_commits = 0
        
        for commit in commits:
            try:
                author = commit.get("author", {}).get("name", "unknown")
                message = commit.get("message", "")
                url = commit.get("url", "")
                commit_id = commit.get("id", "unknown")[:7]  # Short commit hash
                
                # Process commit details
                logger.info(f"Processing commit: {commit_id}")
                
                if not re.search(REGEXP, message, re.IGNORECASE):
                    logger.warning(f"Commit message does not match the regexp: {message}")
                    continue
                
                # Skip if no message
                if not message.strip():
                    logger.warning(f"Empty commit message for commit {commit_id}")
                    continue
                
                # Her kanal için ayrı işlem yap
                for channel in SLACK_CHANNELS:
                    # Kanal ismine göre farklı analyzer tipi seç
                    ai_analysis = analyze_commit_with_ai(message)
                    
                    slack_text = f"""
🚀 *Type* (Commit Analizi - {channel})
👤 *Yazar:* {author}
🔗 *Commit:* `{commit_id}`
💬 *Mesaj:* {message}
🤖 *AI Analizi:* {ai_analysis}
🌐 *Link:* {url}
"""
                    
                    if send_to_channel(slack_text, channel):
                        logger.info(f"Successfully sent commit {commit_id} to {channel}")
                    else:
                        logger.error(f"Failed to send commit {commit_id} to {channel}")
                
                processed_commits += 1
                    
            except Exception as e:
                logger.error(f"Error processing commit: {e}")
                continue
        
        logger.info(f"Processed {processed_commits} out of {len(commits)} commits")
        return jsonify({
            "status": "success", 
            "processed_commits": processed_commits,
            "total_commits": len(commits),
            "active_channels": SLACK_CHANNELS
        }), 200
        
    except Exception as e:
        logger.error(f"Webhook processing error: {e}")
        return jsonify({"error": "Internal server error"}), 500

def send_to_channel(text, channel):
    """
    Belirli bir kanala mesaj gönder - Bot API varsa onu kullan, yoksa webhook
    """
    if slack_client:
        # Bot API kullan
        try:
            response = slack_client.chat_postMessage(
                channel=channel,
                text=text
            )
            
            if response["ok"]:
                logger.info(f"Message sent to {channel} via Bot API")
                return True
            else:
                logger.error(f"Bot API error for {channel}: {response.get('error')}")
                return False
                
        except SlackApiError as e:
            logger.error(f"Slack API error for {channel}: {e.response['error']}")
            return False
    else:
        # Webhook kullan (fallback)
        return send_to_slack(text)

def analyze_commit_with_ai(message):
    """
    Analyze commit message using OpenAI GPT-4
    """
    if not openai_client:
        logger.error("OpenAI client not available")
        return "AI analizi yapılamadı: OpenAI bağlantısı kurulamadı"
    
    try:
        USER_PROMPT += "\n" + message
        
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system", 
                    "content": SYSTEM_PROMPT
                },
                {"role": "user", "content": USER_PROMPT}
            ],
            max_tokens=300,
            temperature=0.3
        )
        
        analysis = response.choices[0].message.content.strip()
        logger.info(f"AI analysis completed")
        return analysis
        
    except Exception as e:
        logger.error(f"AI analysis error: {e}")
        return f"AI analizi yapılamadı: {str(e)}"

def send_to_slack(text):
    """
    Send message to Slack webhook (fallback method)
    """
    try:
        if not SLACK_WEBHOOK_URL:
            logger.error("Slack webhook URL not configured")
            return False
        
        response = requests.post(
            SLACK_WEBHOOK_URL, 
            json={"text": text},
            timeout=10
        )
        
        if response.status_code == 200:
            logger.info("Message sent to Slack webhook successfully")
            return True
        else:
            logger.error(f"Slack webhook error: {response.status_code} - {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Slack request error: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected Slack error: {e}")
        return False

@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint
    """
    status = {
        "status": "healthy",
        "openai_available": openai_client is not None,
        "slack_bot_available": slack_client is not None,
        "slack_webhook_available": bool(SLACK_WEBHOOK_URL),
        "active_channels": SLACK_CHANNELS
    }
    return jsonify(status), 200

if __name__ == '__main__':
    logger.info("Starting AI Commit Notifier application")
    logger.info(f"Active channels: {SLACK_CHANNELS}")
    app.run(host='0.0.0.0', port=5000, debug=False)
