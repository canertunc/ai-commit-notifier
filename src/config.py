import os
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from .env file in project root
project_root = Path(__file__).parent.parent
load_dotenv(project_root / '.env')
print("sss: ",project_root)

# Slack Bot Token (Environment variable'dan alınacak) - Çoklu kanal için
SLACK_BOT_TOKEN = os.getenv('SLACK_BOT_TOKEN')

# Slack Webhook URL (Environment variable'dan alınacak) - Fallback için
SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL')

# OpenAI API Key (Environment variable'dan alınacak)
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

REGEXP = os.getenv('REGEXP')

SLACK_CHANNELS = os.getenv('SLACK_CHANNELS')

GITHUB_WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET')

USER_PROMPT = f"""
Aşağıda bir commit mesajı verilmiştir. Lütfen mesajda anlatılan değişikliğin **özünü** çıkar ve yalnızca mesajın gerçekten içerdiği bilgilere dayalı, sade ama bağlamsal bir özet ver.

- Gereksiz tanımlar (örneğin "Merge", "Pull Request", "feature branch" gibi terimlerin ne olduğunu açıklamak) verme.
- Eğer commit mesajı anlamlı değilse, bunu belirt ve nedenini açıkla.
- Eğer anlamlıysa, yapılan işin **amacını ve etkisini** kısa ama teknik olarak açıkla.

Commit mesajı:
"""

SYSTEM_PROMPT = "Sen yazılım geliştirici aktivitelerini analiz eden uzman bir asistansın. Kısa ve net cevaplar verirsin."

# Configuration validation
def validate_config():
    """
    Validate that required configuration is present
    """
    errors = []
    
    if not SLACK_BOT_TOKEN and not SLACK_WEBHOOK_URL:
        errors.append("Either SLACK_BOT_TOKEN or SLACK_WEBHOOK_URL environment variable is required")
    
    if not OPENAI_API_KEY:
        errors.append("OPENAI_API_KEY environment variable is required")
    
    if not REGEXP:
        errors.append("REGEXP environment variable is required")
    
    if not SLACK_CHANNELS:
        errors.append("SLACK_CHANNELS environment variable is required")
    
    if not GITHUB_WEBHOOK_SECRET:
        errors.append("GITHUB_WEBHOOK_SECRET environment variable is required")
    
    if errors:
        print("Configuration errors:")
        for error in errors:
            print(f"  - {error}")
        print("\nPlease set the required environment variables in your .env file")
        return False
    
    return True

# Validate configuration on import
if __name__ != '__main__':
    validate_config()
