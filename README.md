# Google Calendar ICS Sync

A Python script that automatically downloads ICS (iCalendar) files from a given URL and imports them to a Google Calendar. The script runs continuously, checking for updates every minute.

## Features

- Downloads ICS files from any accessible URL
- Automatically authenticates with Google Calendar API
- Creates or finds the target Google Calendar
- **Advanced ICS import using Google Calendar API's import method**
- **Fallback to standard event creation for compatibility**
- **Preserves original event data and metadata**
- **Automatic event deletion** (events removed from source are deleted from calendar)
- **Configurable deletion behavior** (can be disabled for safety)
- **Delta-based synchronization** (only processes changed events for maximum speed)
- **Smart event comparison** (detects changes in title, description, location, times)
- Prevents duplicate events using iCalUID
- Runs continuously with configurable intervals
- Comprehensive logging and error handling
- **Supports authentication cookies for protected calendars**
- **Full recurrent event support** with RRULE handling
- **Configurable recurring event import modes**

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

#### Step 2: Fix Testing Mode Issue

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

#### Step 3: OAuth Consent Screen Configuration

Make sure your OAuth consent screen has:
- App name: 'Calendar Synchronization' (or any name)
- User support email: your email
- Developer contact: your email
- Scopes: https://www.googleapis.com/auth/calendar

After completing these steps, wait a few minutes before running the sync script.

### 3. Calendar URL Setup

#### For Outlook/Office365 Calendars:

If you're syncing from Outlook/Office365, you need to get the correct ICS URL:

1. **Run the URL helper:**
   ```bash
   python3 outlook_url_helper.py
   ```

2. **Get the correct URL from Outlook:**
   - Open Outlook Web Access in your browser
   - Go to your calendar
   - Click Settings (gear icon) → Calendar
   - Find "Publish a calendar" or "Share calendar"
   - Copy the ICS subscription URL (not the sharing URL)

3. **Alternative method:**
   - Right-click on your calendar in Outlook Web Access
   - Select "Share" → "Publish calendar"
   - Choose "Can view all details"
   - Copy the generated ICS URL

#### For Other Calendar Services:

- **Google Calendar**: Right-click calendar → Settings → Integrate calendar → Secret address in iCal format
- **Apple Calendar**: File → Export → Export your calendar
- **Other services**: Look for "Export" or "Subscribe" options

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
export ENABLE_EVENT_DELETION="true"
export DEBUG_COMPARISON="false"
```

## Import Methods

The script uses multiple methods to import ICS events with maximum compatibility:

### **Method 1: Google Calendar API Import (Preferred)**
- Uses `events.import` method when possible
- Preserves original event data and metadata
- Requires iCalUID (unique event identifier)
- Best fidelity to original ICS file

### **Method 2: Standard Event Creation (Fallback)**
- Uses `events.insert` method
- Recreates events from parsed data
- Works with all event types
- Compatible with all calendars

### **Method 3: CalDAV Import (Advanced)**
- Alternative method using CalDAV protocol
- Better native ICS support
- Requires CalDAV server and credentials

## Recurrent Events Support

The script provides comprehensive support for recurring events (RRULE):

### **Recurrent Event Modes**

**Series Mode (Recommended):**
```bash
RECURRENT_EVENT_MODE=series
```
- Imports recurring events as single event series
- Preserves RRULE (recurrence rules)
- Most efficient and Google Calendar native
- Reduces duplicate updates

**Single Instance Mode:**
```bash
RECURRENT_EVENT_MODE=single_instance
```
- Treats each occurrence as separate events
- Useful for calendars with complex recurrence patterns
- May create many individual events

**Both Mode:**
```bash
RECURRENT_EVENT_MODE=both
```
- Imports both the series and individual instances
- Maximum compatibility but may create duplicates

### **Supported RRULE Types**
- **Daily**: `FREQ=DAILY`
- **Weekly**: `FREQ=WEEKLY;BYDAY=MO,WE,FR`
- **Monthly**: `FREQ=MONTHLY;BYMONTHDAY=15`
- **Yearly**: `FREQ=YEARLY;BYMONTH=12`
- **With intervals**: `FREQ=WEEKLY;INTERVAL=2`
- **With count**: `FREQ=DAILY;COUNT=10`
- **With until**: `FREQ=WEEKLY;UNTIL=20241231T235959Z`

### **Recurrent Event Configuration**
```bash
# Enable/disable recurrent event support
ENABLE_RECURRENT_EVENTS=true

# Set recurrent event handling mode
RECURRENT_EVENT_MODE=series
```

## Event Synchronization

### **Automatic Event Deletion**

By default, the script performs **bidirectional synchronization**:
- ✅ **Adds new events** from the ICS file
- ✅ **Updates existing events** with changes
- ✅ **Deletes events** that are no longer in the source ICS file

This ensures your Google Calendar stays perfectly in sync with the source calendar.

### **Safety Controls**

You can control deletion behavior:

**Enable deletion (default):**
```bash
ENABLE_EVENT_DELETION=true
```

**Disable deletion (add-only mode):**
```bash
ENABLE_EVENT_DELETION=false
```

**⚠️ Warning:** When deletion is enabled, events that are removed from the source ICS file will be permanently deleted from your Google Calendar. Use with caution if you have manually added events to the target calendar.

### **Delta-Based Synchronization**

The script uses intelligent delta synchronization for maximum efficiency:

#### **How It Works:**
1. **Fetches existing events** once per sync cycle
2. **Compares with new events** from the ICS file
3. **Identifies only changed events** (inserts, updates, deletes)
4. **Processes only the delta** instead of all events

#### **Performance Benefits:**
- **Faster sync cycles** - only processes changed events
- **Reduced API calls** - fewer Google Calendar API requests
- **Lower bandwidth usage** - less data transfer
- **Better scalability** - works efficiently with large calendars

#### **Change Detection:**
The script detects changes in:
- ✅ **Event title** (summary)
- ✅ **Event description**
- ✅ **Event location**
- ✅ **Start time** (including timezone changes)
- ✅ **End time** (including timezone changes)

#### **Sync Statistics:**
```
Delta sync completed: 2 inserted, 1 updated, 15 unchanged, 0 deleted, 0 errors
```

## Usage

### Basic Usage

```bash
python calendar_sync.py
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

## File Structure

```
google_calendear_sync/
├── calendar_sync.py          # Main script
├── requirements.txt          # Python dependencies
├── config.env.example       # Example configuration
├── README.md                # This file
├── credentials.json         # Google OAuth credentials (you need to add this)
└── token.json              # OAuth token (created after first run)
```

## Logging

The script creates detailed logs in:
- Console output (standard output)
- `calendar_sync.log` file

Log levels include:
- INFO: General operation information
- ERROR: Error messages
- DEBUG: Detailed debugging information

## Error Handling

The script includes comprehensive error handling for:
- Network connectivity issues
- Invalid ICS file formats
- Google Calendar API errors
- Authentication problems
- File system errors

## Stopping the Script

To stop the script, press `Ctrl+C`. The script will gracefully shut down and log the stop event.

## Troubleshooting

### Common Issues

1. **Authentication Error**: Make sure `credentials.json` is properly downloaded from Google Cloud Console
2. **redirect_uri_mismatch Error**: This happens when OAuth redirect URIs don't match. Follow the detailed OAuth setup instructions above
3. **access_denied / Testing Mode Error**: Your OAuth app is in testing mode. Follow the "Fix Testing Mode Issue" steps above
4. **500 Server Error (Outlook/Office365)**: Your calendar URL is incorrect or expired. Run `python3 outlook_url_helper.py` for help
5. **Network Error**: Check if the ICS URL is accessible and the network connection is stable
6. **Calendar Not Found**: The script will create a new calendar if the specified name doesn't exist
7. **Permission Denied**: Ensure the Google account has calendar access permissions
8. **Many Duplicate Updates**: Events being updated repeatedly. Enable `DEBUG_COMPARISON=true` to troubleshoot
9. **Timezone Comparison Issues**: Events with same time in different timezones being marked as different. Fixed with proper UTC normalization.

### Debug Mode

To see more detailed logs, modify the logging level in the script:

```python
logging.basicConfig(level=logging.DEBUG, ...)
```

## Security Notes

- Keep your `credentials.json` file secure and never commit it to version control
- The `token.json` file contains your authentication token - keep it secure
- Consider running the script in a secure environment if dealing with sensitive calendars

## Customization

The script can be easily customized by modifying:
- Sync interval (default: 1 minute)
- Calendar timezone (default: UTC)
- Event handling logic
- Logging configuration
- Error handling behavior

## License

This script is provided as-is for educational and personal use.
