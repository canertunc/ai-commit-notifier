# 🤖📝 AI Commit Notifier

GitHub commit'lerinizi AI ile analiz edip Slack'e bildirim gönderen webhook sistemi.

## ✨ Özellikler

### **GitHub Integration**
- GitHub webhook receiver ile real-time commit takibi
- HMAC-SHA256 signature validation ile güvenli webhook
- Push event'leri otomatik yakalama

### **AI-Powered Analysis**
- OpenAI GPT-4o-mini ile commit message analizi
- Otomatik commit kategorilendirme
- İnsan dostu açıklamalar

### **Slack Notifications**
- Multi-channel Slack bildirileri
- Slack Bot API ile zengin mesaj formatı
- Customizable notification channels

### **Security Features**
- GitHub webhook signature validation
- Environment variable configuration
- Secure API key management

## 📋 Sistem Gereksinimleri

- **Python 3.10+**

---

## 🔧 Local Kurulum (venv ile)

### 1. Repository'yi Klonlayın
```bash
git clone https://github.com/canertunc/ai-commit-notifier.git
cd ai-commit-notifier
```

### 2. Virtual Environment Oluşturun
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Dependencies Kurulumu
```bash
# Package'ları yükleyin
pip install -r requirements.txt
```

### 4. Environment Variables Ayarlayın

`.env` dosyası oluşturun:
```env
# Slack Configuration
SLACK_BOT_TOKEN=xoxb-your-bot-token-here
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
SLACK_CHANNELS=new-channel,social

# OpenAI Configuration  
OPENAI_API_KEY=sk-proj-your-openai-key-here

# Commit Filtering
REGEXP="\\b[Mm]erg(e|ed|ing)?\\b"

# GitHub Webhook Security
GITHUB_WEBHOOK_SECRET=your-webhook-secret-key
```

### 5. Uygulamayı Başlatın
```bash
# Organize yapıda:
python src/app.py

# Veya Python module olarak:
python -m src.app
```

**Başarılı çıktı:**
```
INFO - OpenAI client initialized successfully
INFO - Slack Bot client initialized successfully  
INFO - Starting AI Commit Notifier application
INFO - Active channels: ['#new-channel', '#social']
* Running on http://127.0.0.1:5000/
```

**Log dosyaları:**
- Console output: Terminal'de görünür
- File output: `logs/app.log` dosyasında kaydedilir

---

## 🧪 Postman ile Local Test

### Hızlı Test Setup
```bash
# 1. Postman'ı aç ve collection'ı import et
AI_Commit_Notifier.postman_collection.json

# 2. Environment oluştur:
base_url = http://127.0.0.1:5000
github_secret = your-webhook-secret-key (.env dosyandaki değer)

# 3. Testleri sırayla çalıştır
```

### Test Case'leri
| Test | Amaç | Beklenen Sonuç |
|------|------|----------------|
| **Health Check** | Sistem durumu | 200 - Healthy status |
| **Valid Webhook** | Geçerli webhook simülasyonu | 200 - Commit işlendi |
| **Invalid Signature** | Güvenlik testi | 403 - Signature hatası |
| **Missing Header** | Authentication eksik | 403 - Header eksik |
| **Empty Payload** | Boş veri testi | 400 - Parse hatası |
| **No Commits** | Commit olmayan durum | 400 - Commit bulunamadı |

### Quick Test
```bash
# Terminal'de app'i başlat (organize yapı)
python src/app.py

# Postman'da Health Check testi çalıştır
GET http://127.0.0.1:5000/health
# Beklenen: {"status": "healthy"}

# Veya Docker ile test
./docker/docker-build.sh
curl http://localhost:5000/health
```

---

## 📁 Proje Yapısı

```
ai-commit-notifier/
├── src/                                   # Application Code
│   ├── __init__.py                        # Package initialization
│   ├── app.py                             # Main Flask application
│   └── config.py                          # Configuration management
├── docker/                                # Container Configuration
│   ├── Dockerfile                         # Container image definition
│   ├── docker-compose.yml                 # Service orchestration
│   ├── .dockerignore                      # Build optimization
│   └── docker-build.sh                    # Build & run script
├── tests/                                 # Test Files
│   └── AI_Commit_Notifier.postman_collection.json
├── logs/                                  # Application Logs
│   └── app.log                            # Runtime logs
├── .env                                   # Environment Variables
├── env.template                           # Environment template
├── requirements.txt                       # Python dependencies
└── README.md                              
```

---

## 🐳 Docker ile Kurulum

### 1. Hızlı Başlangıç
```bash
# Environment dosyasını kopyala
cp env.template .env

# .env dosyasını düzenle (API key'leri ekle)
nano .env  # Linux/macOS
notepad .env  # Windows

# Docker ile başlat (organize yapı)
chmod +x docker/docker-build.sh  # Linux/macOS (sadece ilk kez)
./docker/docker-build.sh

# Kontrol et
curl http://localhost:5000/health
```

### ⚠️ Python 3.12+ Distutils Sorunu
Python 3.12 ve sonrasında `distutils` modülü kaldırılmıştır. Ubuntu 24.04+ sistemlerde Docker Compose hatası alırsanız:
```bash
sudo apt install python3-setuptools
```

### 2. Manuel Docker Komutları (Organize Yapı)
```bash
# Build (root klasöründen)
docker build -f docker/Dockerfile -t ai-commit-notifier:latest .

# Run
docker-compose -f docker/docker-compose.yml up -d

# Logs
docker-compose -f docker/docker-compose.yml logs -f

# Stop
docker-compose -f docker/docker-compose.yml down

# Health check
curl http://localhost:5000/health
```

### 3. Development vs Production
```bash
# Development (local)
cp env.template .env
# API key'leri development values ile doldur
./docker/docker-build.sh

# Production (server)
# Production API key'leri ile .env doldur
./docker/docker-build.sh
# GitHub webhook: https://your-server.com/github-webhook
```

---

## 🔗 GitHub Webhook Kurulumu (Production)

### 1. Server Deployment
Uygulamanızı bir sunucuya deploy edin:
- **Heroku**, **DigitalOcean**, **AWS**, **Azure** vb.
- Public erişilebilir URL gerekli (örn: `https://your-app.herokuapp.com`)

### 2. GitHub Repository Webhook Ayarları

1. **GitHub Repository'nize gidin**
2. **Settings** → **Webhooks** → **Add webhook**

### 3. Webhook Configuration

```
Payload URL: https://your-app.herokuapp.com/github-webhook
Content type: application/json
Secret: your-webhook-secret-key (env dosyandaki GITHUB_WEBHOOK_SECRET)
```

### 4. Event Selection
**"Just the push event." seçin:**
- ✅ **Push** events

### 5. SSL Verification
- ✅ **Enable SSL verification**

### 6. Webhook Test
GitHub'da **Recent Deliveries** bölümünden test edin:
```bash
# Başarılı Response
Status: 200 OK
Response: {"status": "success", "processed_commits": 1, ...}
```

### 7. Environment Variables (Production)
```env
# Production URL'inize göre ayarlayın
SLACK_BOT_TOKEN=xoxb-production-token
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SLACK_CHANNELS=production-commits,dev-team

# Aynı secret GitHub webhook'ta kullanın
GITHUB_WEBHOOK_SECRET=production-webhook-secret-key

# Production OpenAI key
OPENAI_API_KEY=sk-proj-production-key
```

### ⚠️ Güvenlik Notları
- **GITHUB_WEBHOOK_SECRET** hem GitHub webhook ayarlarında hem .env dosyasında aynı olmalı
- Production'da güçlü secret kullanın (minimum 32 karakter)

---

## 📚 API Endpoints

### `GET /health`
System health check.
```json
{"status": "healthy", "active_channels": ["#channel1"]}
```

### `POST /github-webhook`  
GitHub webhook receiver with HMAC-SHA256 validation.
- `X-Hub-Signature-256: sha256=<signature>`
- `X-GitHub-Event: push`

**Body:** GitHub push event payload

**Response:**
```json
{
  "status": "success",
  "processed_commits": number,
  "total_commits": number,
  "active_channels": ["#channel1", "#channel2"]
}
```

---

## 📨 Örnek Slack Mesajı

Sistem bir commit'i analiz ettiğinde Slack'e şu formatta mesaj gönderir:

```
🚀 Type (Commit Analizi - #new-channel)
👤 Yazar: Test User
🔗 Commit: 911027c
💬 Mesaj: Merge pull request #123 from feature/new-feature
🤖 AI Analizi: Bu commit, "feature/new-feature" adlı bir özellik dalından gelen değişikliklerin ana dal ile birleştirilmesini (merge) içerir. Amaç, yeni özelliğin kod tabanına dahil edilmesi ve bu sayede projenin işlevselliğini artırmaktır. Etkisi, projenin güncellenmesi ve yeni özelliklerin kullanıma sunulmasıdır.
🌐 Link: https://github.com/testuser/test-repo/commit/911027c233a92ad5df703819196703b836522a8c
```

Bu mesaj formatı sayesinde:
- **Commit türü** ve **hedef kanal** bilgisi
- **Yazar** ve **commit hash** bilgileri
- **Commit mesajı** orijinal haliyle
- **AI analizi** ile anlaşılır açıklama
- **Direct link** ile commit'e kolay erişim

---
