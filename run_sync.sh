#!/bin/bash

# Google Calendar ICS Sync Runner Script

# Check if virtual environment exists, create if not
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    uv venv 
fi

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Install/update dependencies
echo "Installing dependencies..."
uv pip install -r requirements.txt

# Check if credentials.json exists
if [ ! -f "credentials.json" ]; then
    echo "Warning: credentials.json not found!"
    echo "Please download your Google OAuth credentials and save as 'credentials.json'"
    echo "See README.md for detailed setup instructions"
fi

# Configuration is now handled by the Python script itself
echo "Configuration will be loaded from config.env by the Python script"

# Run the sync script
echo "Starting Google Calendar ICS Sync..."
uv run calendar_sync.py
