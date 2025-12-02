#!/bin/bash

echo "Setting up Enhanced Email Sender..."

# Create required directories
mkdir -p data logs

# Install Node.js dependencies (if needed)
if [ -f "package.json" ]; then
    echo "Installing Node.js dependencies..."
    npm install
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Create default admin user
echo "Creating default admin user..."
python -c "
import json
import os
from pathlib import Path

data_dir = Path('./data')
data_dir.mkdir(exist_ok=True)

auth_file = data_dir / 'auth.json'
if not auth_file.exists():
    import hashlib
    import secrets
    
    salt = secrets.token_hex(16)
    password = 'admin123'  # Change this in production!
    password_hash = hashlib.sha256(f'{salt}{password}'.encode()).hexdigest()
    
    users = [{
        'id': 'admin-001',
        'username': 'admin',
        'passwordHash': password_hash,
        'salt': salt,
        'role': 'admin',
        'status': 'active',
        'mailboxes': [],
        'createdAt': '2024-01-01T00:00:00.000Z',
        'updatedAt': '2024-01-01T00:00:00.000Z'
    }]
    
    with open(auth_file, 'w') as f:
        json.dump({'users': users}, f, indent=2)
    
    print('Default admin created: username=admin, password=admin123')
else:
    print('Auth file already exists')
"

# Create initial IP rotation config
echo "Creating IP rotation configuration..."
python -c "
import json
from pathlib import Path

data_dir = Path('./data')
ip_file = data_dir / 'ip-rotation.json'

if not ip_file.exists():
    config = {
        'proxies': [],
        'currentIndex': 0,
        'updatedAt': '2024-01-01T00:00:00.000Z'
    }
    
    with open(ip_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    print('IP rotation config created')
else:
    print('IP rotation config already exists')
"

echo "Setup complete!"
echo ""
echo "To start the server:"
echo "  Node.js: npm start"
echo "  Python: python server.py"
echo "  Docker: docker-compose up"
echo ""
echo "Default admin credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo ""
echo "IMPORTANT: Change the default password immediately!"