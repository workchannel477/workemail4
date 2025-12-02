# Enhanced Email Management System

A comprehensive full-stack email management platform with user management, IP rotation, rate limiting, and batch processing capabilities. Built with Node.js/Express backend, Python SMTP engine, and modern frontend technologies.

## 🚀 Features

### Core Capabilities
- **Multi-User System**: Role-based access (Admin/User) with user management
- **Email Campaign Management**: Create, schedule, and send email campaigns
- **IP Rotation**: Automatic proxy rotation to prevent IP blocking
- **Rate Limiting**: Configurable rate limits for API and email sending
- **Batch Processing**: Send emails in batches with configurable delays
- **Retry Logic**: Automatic retry with exponential backoff

### Advanced Features
- **Connection Pooling**: Efficient SMTP connection reuse
- **Email Validation**: Validate email addresses before sending
- **Template System**: Reusable email templates with variables
- **Scheduling**: Cron-like job scheduling for automated sending
- **Comprehensive Logging**: Detailed logging at multiple levels
- **Health Monitoring**: System health checks and statistics
- **Docker Support**: Containerized deployment with Docker Compose

## 🏗️ Architecture

### Technology Stack
- **Frontend**: Alpine.js + Tailwind CSS (SPA dashboard)
- **Backend**: Node.js/Express REST API
- **Email Engine**: Python SMTP with proxy support
- **Storage**: JSON files with optional database migration
- **Containerization**: Docker + Docker Compose

### Directory Structure
```
email-system/
├── server.js              # Node.js Express server
├── main.py               # Enhanced Python email sender
├── scripts.js            # Frontend JavaScript
├── requirements.txt      # Python dependencies
├── package.json         # Node.js dependencies
├── Dockerfile           # Container configuration
├── docker-compose.yml   # Multi-container orchestration
├── setup.sh            # Initialization script
├── data/               # JSON data storage
│   ├── auth.json       # User authentication
│   ├── email-jobs.json # Email jobs queue
│   ├── ip-rotation.json # Proxy configuration
│   └── rate-limit.json # Rate limit tracking
├── public/             # Static frontend files
│   ├── index.html      # Landing page
│   ├── user.html       # User dashboard
│   ├── admin.html      # Admin control panel
│   └── scripts.js      # Frontend logic
└── logs/               # Application logs
```

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ and npm
- Python 3.11+
- Docker and Docker Compose (optional)

### Method 1: Local Installation

1. **Clone and setup**
   ```bash
   git clone <repository-url>
   cd email-system
   ```

2. **Run setup script**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. **Install dependencies**
   ```bash
   npm install
   pip install -r requirements.txt
   ```

4. **Start the server**
   ```bash
   npm start
   # or
   node server.js
   ```

5. **Access the application**
   - Main URL: http://localhost:4000
   - User Dashboard: http://localhost:4000/user.html
   - Admin Panel: http://localhost:4000/admin.html

### Method 2: Docker Deployment

1. **Build and start with Docker Compose**
   ```bash
   docker-compose up -d
   ```

2. **View logs**
   ```bash
   docker-compose logs -f
   ```

3. **Stop services**
   ```bash
   docker-compose down
   ```

## 👥 Default Credentials

After initial setup, a default admin user is created:

- **Username**: `admin`
- **Password**: `admin123`

**⚠️ IMPORTANT**: Change the default password immediately after first login!

## 📊 Admin Panel Features

### User Management
- Create, edit, and delete users
- Assign roles (Admin/User)
- Set user status (Active/Suspended)
- Change passwords
- View user statistics

### IP Rotation Management
- Configure proxy lists
- Automatic proxy rotation
- Support for HTTP, SOCKS4, SOCKS5 proxies
- Proxy authentication support

### Rate Limit Control
- Monitor email sending rates
- Reset rate limits per user
- Configure global rate limits
- Real-time rate tracking

### Job Management
- View all email jobs
- Filter by status (Pending/Sent/Failed)
- Manual job triggering
- Job statistics and analytics

## 📧 Email Configuration

### SMTP Settings
Default SMTP configuration (configurable per job):

- **Host**: `smtp.gmail.com`
- **Port**: `587` (TLS)
- **Authentication**: Username/Password or App Password

### Proxy Format
Proxies can be configured in various formats:
```
http://username:password@proxyhost:port
socks5://proxyhost:port
http://proxyhost:8080
```

### Batch Processing
- **Batch Size**: Configurable (default: 50 recipients per batch)
- **Batch Delay**: Configurable delay between batches
- **Retry Logic**: Automatic retry on failure
- **Connection Pooling**: Efficient SMTP connection reuse

## 🔐 Security Features

### Authentication
- SHA-256 password hashing with unique salts
- Session-based authentication with JWT-like tokens
- Role-based access control
- Session timeout management

### Rate Limiting
- API rate limiting: 30 requests/minute per IP
- Email rate limiting: 10 emails/minute per user
- Configurable limits per user role

### Data Protection
- Password hashing with salts
- Secure session management
- Input validation and sanitization
- CORS configuration

## 🛠️ API Endpoints

### Authentication
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `GET /auth/me` - Get current user info

### User Management (Admin only)
- `GET /admin/users` - List all users
- `POST /admin/users` - Create new user
- `PUT /admin/users/:id` - Update user
- `DELETE /admin/users/:id` - Delete user
- `POST /admin/users/:id/change-password` - Change user password

### Email Jobs
- `GET /api/jobs` - List jobs (user's or all for admin)
- `POST /api/jobs` - Create new job
- `DELETE /api/jobs/:id` - Delete job
- `POST /api/jobs/:id/send` - Send job immediately

### System Management (Admin only)
- `GET /admin/overview` - System overview and statistics
- `GET /admin/ip-rotation` - Get IP rotation config
- `POST /admin/ip-rotation` - Update IP rotation config
- `GET /admin/rate-limits` - Get rate limit status
- `POST /admin/rate-limits/reset` - Reset rate limits

### Health Check
- `GET /healthz` - System health status

## 🐍 Python Email Sender

### Usage Examples

**Basic usage:**
```bash
python main.py --username you@example.com --password 'app-password' \
  --recipients 'recipient1@example.com,recipient2@example.com' \
  --subject 'Test Email' \
  --text 'Plain text body' \
  --html '<strong>HTML body</strong>'
```

**With proxy:**
```bash
python main.py --payload job.json --proxy 'socks5://proxyhost:1080'
```

**Using JSON payload:**
```bash
python main.py --payload data/payload-123.json
```

### Payload JSON Format
```json
{
  "username": "sender@example.com",
  "password": "app-password",
  "recipients": ["recipient1@example.com", "recipient2@example.com"],
  "subject": "Email Subject",
  "textBody": "Plain text content",
  "htmlBody": "<p>HTML content</p>",
  "smtpHost": "smtp.gmail.com",
  "smtpPort": 587,
  "proxy": "http://proxyhost:8080",
  "batchSize": 50,
  "delayBetweenBatches": 2,
  "maxRetries": 3
}
```

## ⚙️ Configuration

### Environment Variables
Create a `.env` file in the root directory:

```env
# Server Configuration
PORT=4000
NODE_ENV=production
SECRET_KEY=your-secret-key-here
SESSION_TIMEOUT=3600

# Rate Limits
MAX_EMAILS_PER_MINUTE=30
MAX_REQUESTS_PER_MINUTE=60
EMAIL_BATCH_SIZE=50

# Directories
DATA_DIR=./data
LOG_DIR=./logs

# Proxy Configuration
DEFAULT_PROXY=
PROXY_ROTATION_ENABLED=true

# SMTP Defaults
DEFAULT_SMTP_HOST=smtp.gmail.com
DEFAULT_SMTP_PORT=587

# Security
REQUIRE_HTTPS=false
CORS_ORIGINS=http://localhost:3000,http://localhost:4000
```

### Rate Limit Configuration
- **API Rate Limit**: 30 requests/minute per IP
- **Email Rate Limit**: 10 emails/minute per user
- Configurable via environment variables

## 📈 Monitoring & Logging

### Log Files
- Application logs in `logs/` directory
- JSON data files in `data/` directory
- Detailed email sending logs

### Health Monitoring
- Health check endpoint: `/healthz`
- System statistics in admin panel
- Email success/failure tracking

## 🔧 Maintenance

### Backup Data
```bash
# Backup all data
cp -r data/ backup-data-$(date +%Y%m%d)
```

### Reset System
```bash
# Reset all data (caution: irreversible)
rm -rf data/*.json
./setup.sh
```

### View Logs
```bash
# Docker logs
docker-compose logs -f

# Local logs
tail -f logs/*.log
```

## 🚨 Troubleshooting

### Common Issues

1. **SMTP Connection Failed**
   - Verify SMTP credentials
   - Check firewall settings
   - Try different SMTP port (587/465)

2. **Proxy Not Working**
   - Verify proxy format and credentials
   - Test proxy connectivity manually
   - Check proxy server status

3. **Rate Limit Issues**
   - Check rate limit configuration
   - Reset rate limits in admin panel
   - Adjust batch size and delays

4. **Authentication Errors**
   - Verify password hashes in auth.json
   - Check session timeout settings
   - Clear browser cookies

### Debug Mode
Enable debug logging:
```bash
NODE_ENV=development npm start
# or
python main.py --log-level DEBUG
```

## 📚 Development

### Adding New Features
1. Extend the `server.js` with new endpoints
2. Update `scripts.js` for frontend functionality
3. Add new JSON schemas in `data/` directory
4. Extend Python email sender as needed

### Testing
```bash
# Test API endpoints
curl -X POST http://localhost:4000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Test Python sender
python main.py --help
```

### Code Structure
- **Modular Design**: Separate concerns for maintainability
- **Error Handling**: Comprehensive error handling throughout
- **Validation**: Input validation at all levels
- **Documentation**: Inline comments and clear naming

## 📄 License

This project is for educational and demonstration purposes. Use responsibly and in compliance with applicable laws and regulations regarding email sending.

## ⚠️ Disclaimer

This tool is intended for legitimate email marketing and communication purposes only. Users are responsible for:
- Complying with anti-spam laws (CAN-SPAM, GDPR, etc.)
- Obtaining proper consent from recipients
- Respecting email sending limits and best practices
- Using appropriate unsubscribe mechanisms

The developers assume no liability for misuse of this software.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review the documentation
3. Create a GitHub issue
4. Contact the maintainers

---

**Version**: 2.0.0  
**Last Updated**: November 2024  
**Requirements**: Node.js 18+, Python 3.11+, Docker (optional)