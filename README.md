# Google Calendar ICS Sync

A Python script that automatically downloads ICS (iCalendar) files from a given URL and imports them to a Google Calendar. The script runs continuously, checking for updates every minute.

## Features

- Downloads ICS files from any accessible URL
- Automatically authenticates with Google Calendar API
- Creates or finds the target Google Calendar
- Delta-based synchronization (only processes changed events for maximum speed)
- Runs continuously with configurable intervals
- Comprehensive logging and error handling

## Setup

### 1. Install Dependencies
We manage the project with `uv`. Please refer to its [official document](https://docs.astral.sh/uv/) for how to install it.

```bash
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

### 2. Google Calendar API Setup

#### Step 1: Create OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Select your project or create a new one
3. Enable the Google Calendar API
4. Go to 'Credentials' in the left sidebar
5. Click 'Create Credentials' -> 'OAuth client ID'
6. Choose 'Desktop application' as the application type
7. Download the credentials JSON file
8. Save it as 'credentials.json' in this directory

#### Step 2: Granting Access

If you get 'access_denied' or 'testing mode' errors:

**OPTION A: Add yourself as a test user (Recommended)**
1. Go to: APIs & Services > OAuth consent screen
2. Scroll to 'Test users' section
3. Click 'ADD USERS' and add your Google email
4. Save changes

**OPTION B: Publish the application**
1. Go to: APIs & Services > OAuth consent screen
2. Click 'PUBLISH APP' button
3. Confirm publication

### 3. Calendar URL Setup

#### For Outlook/Office365 Calendars:
- Open Outlook Web Access in your browser
- Go to your calendar
- Click Settings (gear icon) → Calendar
- Find "Publish a calendar" or "Share calendar"
- Copy the ICS subscription URL (not the sharing URL)

### 4. Configuration

1. Copy the example configuration file:
   ```bash
   cp config.env.example config.env
   ```

2. Edit `config.env` with your settings:
   ```bash
   # URL of the ICS file to download and sync
   ICS_URL=https://your-calendar-url.com/calendar.ics
   
   # Name of the Google Calendar to import events to
   CALENDAR_NAME=My Imported Calendar
   
   # Path to Google OAuth credentials file
   CREDENTIALS_FILE=credentials.json
   
   # Sync interval in minutes
   SYNC_INTERVAL=1
   ```

### 4. Environment Variables (Alternative to config.env)

You can also set environment variables directly:

```bash
export ICS_URL="https://your-calendar-url.com/calendar.ics"
export CALENDAR_NAME="My Imported Calendar"
export CREDENTIALS_FILE="credentials.json"
export SYNC_INTERVAL="1"
export DEBUG_MODE="false"
```

## Usage

### Basic Usage

```bash
uv run calendar_sync.py
```

The script will:
1. Authenticate with Google Calendar (first run will open browser for OAuth)
2. Find or create the specified calendar
3. Download the ICS file from the provided URL
4. Parse and import events
5. Continue running, checking for updates every minute

### First Run Authentication

On the first run, the script will:
1. Open your default web browser
2. Ask you to log in to your Google account
3. Request permission to access your Google Calendar
4. Save the authentication token for future runs

### Stopping the Script

To stop the script, press `Ctrl+C`. The script will gracefully shut down and log the stop event.

### Logging

The script creates detailed logs in:
- Console output (standard output)
- `calendar_sync.log` file

Log levels include:
- INFO: General operation information
- ERROR: Error messages
- DEBUG: Detailed debugging information

### Debugging Mode
To see more detailed logs, modify the logging level in the script:

```python
logging.basicConfig(level=logging.DEBUG, ...)
```

### Security Notes
- Keep your `credentials.json` file secure and never commit it to version control
- The `token.json` file contains your authentication token - keep it secure
- Consider running the script in a secure environment if dealing with sensitive calendars

## File Structure
```
google_calendear_sync/
├── calendar_sync.py          # Main script
├── requirements.txt          # Python dependencies
├── config.env.example        # Example configuration
├── README.md                 # This file
├── credentials.json          # Google OAuth credentials (you need to add this)
└── token.json                # OAuth token (created after first run)
```
## Known Issues
- Some recurring events may be mis-detected as being updated, causing some redundant event patching. But the script works correctly.
- Some recurring insteance events may not have a master recurring event. We treat them as individual events and insert them separately. As a result, these events will be deleted and re-inserted in each iteration.

## License
This script is provided as-is for educational and personal use.

## Disclaimer

**⚠️ IMPORTANT: This codebase contains significant AI-generated content. Please exercise caution when using it. Use at your own risk.**