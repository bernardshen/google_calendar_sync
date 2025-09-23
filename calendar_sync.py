#!/usr/bin/env python3
"""
Google Calendar ICS Sync Script

This script downloads ICS files from a given URL and imports them to a Google Calendar.
It runs continuously, checking for updates every minute.
"""

import os
import sys
import time
import logging
from logging.handlers import RotatingFileHandler
import requests
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import icalendar
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import http.cookiejar
import pytz
import uuid

# Configure logging with rotation
def setup_logging(max_bytes=10*1024*1024, backup_count=5, log_file='calendar_sync.log'):
    """
    Setup logging with file rotation to prevent large log files.
    
    Args:
        max_bytes: Maximum size of each log file in bytes (default: 10MB)
        backup_count: Number of backup files to keep (default: 5)
        log_file: Name of the log file (default: calendar_sync.log)
    """
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Get root logger and clear existing handlers to avoid duplicates
    root_logger = logging.getLogger()
    root_logger.handlers.clear()  # Remove all existing handlers
    
    # Create rotating file handler
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    
    # Add handlers to root logger
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    return logging.getLogger(__name__)

# Setup basic logging first
logger = setup_logging()

# Google Calendar API scopes
SCOPES = ['https://www.googleapis.com/auth/calendar']

def load_config(config_file: str = 'config.env') -> Dict[str, Any]:
    """
    Load configuration from a file.
    
    Args:
        config_file: Path to the configuration file
        
    Returns:
        Dictionary containing configuration values
    """
    config = {}
    
    if os.path.exists(config_file):
        logger.info(f"Loading configuration from {config_file}")
        try:
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse KEY=VALUE format
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        # Remove quotes if present
                        if value.startswith('"') and value.endswith('"'):
                            value = value[1:-1]
                        elif value.startswith("'") and value.endswith("'"):
                            value = value[1:-1]
                        
                        config[key] = value
                        
            logger.info(f"Loaded {len(config)} configuration values from {config_file}")
        except Exception as e:
            logger.warning(f"Error reading config file {config_file}: {e}")
    else:
        logger.info(f"Config file {config_file} not found, using environment variables only")
    
    return config

def load_cookies_from_file(cookie_file: str = 'cookies.txt') -> Optional[http.cookiejar.CookieJar]:
    """Load cookies from a cookies.txt file."""
    if not os.path.exists(cookie_file):
        return None
    
    try:
        cookie_jar = http.cookiejar.MozillaCookieJar()
        cookie_jar.load(cookie_file, ignore_discard=True, ignore_expires=True)
        logger.info(f"Loaded cookies from {cookie_file}")
        return cookie_jar
    except Exception as e:
        logger.warning(f"Could not load cookies from {cookie_file}: {e}")
        return None

class CalendarSync:
    def __init__(self, ics_url: str, calendar_name: str, credentials_file: str = 'credentials.json'):
        """
        Initialize the CalendarSync instance.
        
        Args:
            ics_url: URL to download the ICS file from
            calendar_name: Name of the Google Calendar to import events to
            credentials_file: Path to Google OAuth credentials file
        """
        self.ics_url = ics_url
        self.calendar_name = calendar_name
        self.credentials_file = credentials_file
        self.service = None
        self.calendar_id = None
        
    def authenticate_google_calendar(self):
        """Authenticate with Google Calendar API."""
        creds = None
        token_file = 'token.json'
        
        # Load existing token
        if os.path.exists(token_file):
            creds = Credentials.from_authorized_user_file(token_file, SCOPES)
        
        # If there are no (valid) credentials available, let the user log in
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists(self.credentials_file):
                    raise FileNotFoundError(
                        f"Credentials file '{self.credentials_file}' not found. "
                        "Please download it from Google Cloud Console."
                    )
                
                # Try different authentication methods to avoid redirect_uri_mismatch
                try:
                    # Method 1: Use console-based authentication (most compatible)
                    logger.info("Attempting console-based authentication...")
                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.credentials_file, SCOPES)
                    creds = flow.run_console()
                except Exception as console_error:
                    logger.warning(f"Console authentication failed: {console_error}")
                    if "access_denied" in str(console_error).lower():
                        logger.error("OAuth application is in testing mode. Please see setup instructions.")
                        self._print_oauth_setup_instructions()
                    try:
                        # Method 2: Use local server with explicit redirect URI
                        logger.info("Attempting local server authentication...")
                        flow = InstalledAppFlow.from_client_secrets_file(
                            self.credentials_file, SCOPES)
                        creds = flow.run_local_server(
                            port=8080,
                            redirect_uri_trailing_slash=False,
                            open_browser=True
                        )
                    except Exception as server_error:
                        logger.warning(f"Local server authentication failed: {server_error}")
                        if "access_denied" in str(server_error).lower():
                            logger.error("OAuth application is in testing mode. Please see setup instructions.")
                            self._print_oauth_setup_instructions()
                        # Method 3: Use default local server (original method)
                        logger.info("Attempting default local server authentication...")
                        flow = InstalledAppFlow.from_client_secrets_file(
                            self.credentials_file, SCOPES)
                        creds = flow.run_local_server(port=0)
            
            # Save the credentials for the next run
            with open(token_file, 'w') as token:
                token.write(creds.to_json())
        
        self.service = build('calendar', 'v3', credentials=creds)
        logger.info("Successfully authenticated with Google Calendar API")
    
    def _print_oauth_setup_instructions(self):
        """Print detailed OAuth setup instructions."""
        print("\n" + "="*60)
        print("OAUTH SETUP INSTRUCTIONS")
        print("="*60)
        print("Your Google OAuth application is in 'Testing' mode.")
        print("To fix this, you have two options:")
        print()
        print("OPTION 1: Add your email to test users (Recommended for personal use)")
        print("- Go to Google Cloud Console: https://console.cloud.google.com/")
        print("- Navigate to: APIs & Services > OAuth consent screen")
        print("- Scroll down to 'Test users' section")
        print("- Click 'ADD USERS' and add your Google email address")
        print("- Save the changes")
        print()
        print("OPTION 2: Publish the application (For wider access)")
        print("- Go to Google Cloud Console: https://console.cloud.google.com/")
        print("- Navigate to: APIs & Services > OAuth consent screen")
        print("- Click 'PUBLISH APP' button")
        print("- Confirm the publication")
        print()
        print("After making changes, wait a few minutes and try again.")
        print("="*60)
        print()
        
    def find_or_create_calendar(self):
        """Find existing calendar or create a new one."""
        try:
            # List existing calendars
            calendar_list = self.service.calendarList().list().execute()
            
            for calendar_item in calendar_list.get('items', []):
                if calendar_item['summary'] == self.calendar_name:
                    self.calendar_id = calendar_item['id']
                    logger.info(f"Found existing calendar: {self.calendar_name}")
                    return
            
            # Create new calendar if not found
            calendar = {
                'summary': self.calendar_name,
                'timeZone': 'UTC',
                'description': f'Auto-imported calendar from {self.ics_url}'
            }
            
            created_calendar = self.service.calendars().insert(body=calendar).execute()
            self.calendar_id = created_calendar['id']
            logger.info(f"Created new calendar: {self.calendar_name}")
            
        except HttpError as error:
            logger.error(f"Error managing calendar: {error}")
            raise
    
    def download_ics_file(self) -> Optional[str]:
        """Download ICS file from the given URL."""
        try:
            logger.info(f"Downloading ICS file from: {self.ics_url}")
            
            # Create a session to handle cookies and authentication
            session = requests.Session()
            
            # Try to load cookies from file
            cookie_jar = load_cookies_from_file()
            if cookie_jar:
                session.cookies = cookie_jar
                logger.info("Using cookies from cookies.txt file")
            
            # Add comprehensive headers to mimic a real browser
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/calendar, application/ics, text/html, application/xhtml+xml, application/xml;q=0.9, image/avif, image/webp, image/apng, */*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Cache-Control': 'max-age=0'
            }
            
            session.headers.update(headers)
            
            # First, try to access the main Outlook page to establish session
            if 'outlook.office365.com' in self.ics_url:
                logger.info("Detected Outlook URL - attempting to establish session...")
                try:
                    # Try to access the main Outlook page first
                    outlook_main = 'https://outlook.office365.com/owa/'
                    logger.info(f"Accessing main Outlook page: {outlook_main}")
                    main_response = session.get(outlook_main, timeout=30, allow_redirects=True)
                    logger.info(f"Main page response: {main_response.status_code}")
                    
                    # Wait a moment for any redirects to complete
                    import time
                    time.sleep(2)
                    
                except Exception as e:
                    logger.warning(f"Could not establish Outlook session: {e}")
            
            # Now try to download the actual ICS file
            logger.info("Attempting to download ICS file...")
            response = session.get(self.ics_url, timeout=30, allow_redirects=True)
            
            # Log response details for debugging
            logger.info(f"Response status: {response.status_code}")
            logger.info(f"Response headers: {dict(response.headers)}")
            logger.info(f"Final URL after redirects: {response.url}")
            logger.info(f"Response cookies: {dict(session.cookies)}")
            
            response.raise_for_status()
            
            # Check if the response looks like an ICS file
            content_type = response.headers.get('content-type', '').lower()
            content_preview = response.text[:300] if response.text else "No content"
            
            logger.info(f"Content-Type: {content_type}")
            logger.info(f"Content preview: {content_preview}")
            
            # Check for common error indicators
            if any(indicator in content_preview.lower() for indicator in ['sign in', 'login', 'authentication', 'error', 'unauthorized']):
                logger.error("Response appears to be an authentication or error page")
                logger.error("The URL might require you to be logged into Outlook in your browser")
                logger.error("Try the following solutions:")
                logger.error("1. Log into Outlook Web Access in your browser first")
                logger.error("2. Get a fresh ICS URL from Outlook after logging in")
                logger.error("3. Use a different calendar sharing method")
                return None
            
            if 'calendar' not in content_type and 'BEGIN:VCALENDAR' not in content_preview:
                logger.warning("Response doesn't appear to be an ICS calendar file")
                logger.warning("This might be an authentication page or error page")
                
                # Try to detect if it's HTML content
                if '<html' in content_preview.lower() or '<!doctype' in content_preview.lower():
                    logger.error("Received HTML content instead of ICS file")
                    logger.error("This usually means authentication is required")
                    return None
            
            # Save to temporary file
            temp_file = f"temp_calendar_{int(time.time())}.ics"
            with open(temp_file, 'wb') as f:
                f.write(response.content)
            
            logger.info(f"Successfully downloaded ICS file: {temp_file} ({len(response.content)} bytes)")
            return temp_file
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP Error downloading ICS file: {e}")
            if e.response.status_code == 500:
                logger.error("Server returned 500 Internal Server Error")
                logger.error("This usually means:")
                logger.error("1. The URL is incorrect or expired")
                logger.error("2. The calendar requires authentication")
                logger.error("3. The service is temporarily unavailable")
                logger.error("4. You need to use a different URL format")
            elif e.response.status_code == 401:
                logger.error("Authentication required - the calendar might be private")
                logger.error("Try logging into Outlook Web Access in your browser first")
            elif e.response.status_code == 403:
                logger.error("Access forbidden - check calendar permissions")
            elif e.response.status_code == 404:
                logger.error("Calendar not found - check the URL")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error downloading ICS file: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error downloading ICS file: {e}")
            return None
    
    def _convert_to_utc(self, dt: datetime) -> datetime:
        """Convert a datetime to UTC."""
        if hasattr(dt, 'tzinfo') and dt.tzinfo:
            return dt.astimezone(pytz.utc)
        return dt
    
    def _convert_component_time_to_utc(self, component):
        """Convert a component's time to UTC."""
        if component.get('dtstart') and component.get('dtend'):
            component.get('dtstart').dt = self._convert_to_utc(component.get('dtstart').dt)
            component.get('dtend').dt = self._convert_to_utc(component.get('dtend').dt)
        if component.get('recurrence-id'):
            component.get('recurrence-id').dt = self._convert_to_utc(component.get('recurrence-id').dt)
        return component

    def parse_ics_file(self, ics_file_path: str) -> list:
        """Parse ICS file and extract events."""
        events = []
        recurrence_event_ids = []
        try:
            with open(ics_file_path, 'rb') as f:
                calendar = icalendar.Calendar.from_ical(f.read())
        except Exception as e:
            logger.error(f"Error parsing ICS file: {e}")
            return []
            
        for component in calendar.walk():
            if component.name == "VEVENT":
                # Fix timezone issue - convert to UTC for Google Calendar API compatibility
                component = self._convert_component_time_to_utc(component)

                # Extract basic event data
                event_data = {
                    'summary': str(component.get('summary', '')),
                    'description': str(component.get('description', '')),
                    'start': component.get('dtstart'),
                    'end': component.get('dtend'),
                    'location': str(component.get('location', '')),
                    'uid': str(component.get('uid', '')),
                    'rrule': component.get('rrule'),  # Add recurrence rule support
                    'recurrence_id': component.get('recurrence-id'),  # For exceptions to recurring events
                    'is_recurring': bool(component.get('rrule'))  # Flag for recurring events
                }

                # Determine event type and handle accordingly
                if event_data['is_recurring']:
                    # Master recurring event (has RRULE)
                    event_data['event_type'] = 'master_recurring'
                    recurrence_event_ids.append(event_data['uid'])
                    logger.debug(f"Found master recurring event: '{event_data['summary']}' with UID: {event_data['uid']}")
                # elif event_data['uid'] in recurrence_event_ids:
                elif event_data['recurrence_id']:
                    # Follow-up instance of recurring event (has recurrence-id and without RRULE)
                    event_data['event_type'] = 'recurring_instance'
                    logger.debug(f"Found recurring event instance: '{event_data['summary']}' with UID: {event_data['uid']}")
                else:
                    # Normal event
                    event_data['event_type'] = 'normal'
                    logger.debug(f"Found normal event: '{event_data['summary']}'")
                
                events.append(event_data)
            
        # Log event type breakdown
        master_recurring = sum(1 for event in events if event['event_type'] == 'master_recurring')
        recurring_instances = sum(1 for event in events if event['event_type'] == 'recurring_instance')
        normal_events = sum(1 for event in events if event['event_type'] == 'normal')
            
        logger.info(f"Parsed {len(events)} events:")
        logger.info(f"  - {master_recurring} master recurring events")
        logger.info(f"  - {recurring_instances} recurring event instances")
        logger.info(f"  - {normal_events} normal events")
            
        return events
            
    def _format_rrule_for_google(self, rrule_dict: dict) -> str:
        """Convert RRULE dict to Google Calendar format."""
        try:
            # Google Calendar uses a specific RRULE format
            parts = []
            
            # Frequency
            freq_map = {
                'DAILY': 'DAILY',
                'WEEKLY': 'WEEKLY', 
                'MONTHLY': 'MONTHLY',
                'YEARLY': 'YEARLY'
            }
            
            # Helper function to extract first value from list if needed and clean string
            def extract_and_clean_value(value):
                if isinstance(value, list) and len(value) > 0:
                    value = value[0]
                return str(value).replace("'", "").replace('"', "").replace('[', "").replace(']', "").strip()
            
            if 'FREQ' in rrule_dict:
                freq = extract_and_clean_value(rrule_dict['FREQ'])
                freq = freq.upper()
                parts.append(f"FREQ={freq_map.get(freq, freq)}")
            
            # Interval
            if 'INTERVAL' in rrule_dict:
                interval = extract_and_clean_value(rrule_dict['INTERVAL'])
                parts.append(f"INTERVAL={interval}")
            
            # Count
            if 'COUNT' in rrule_dict:
                count = extract_and_clean_value(rrule_dict['COUNT'])
                parts.append(f"COUNT={count}")
            
            # Until
            if 'UNTIL' in rrule_dict:
                until = rrule_dict['UNTIL']
                # Handle list case (common in iCalendar)
                if isinstance(until, list) and len(until) > 0:
                    until = until[0]
                
                if hasattr(until, 'strftime'):
                    # Convert to UTC if it has timezone info
                    if until.tzinfo:
                        until_utc = until.astimezone(pytz.utc)
                        parts.append(f"UNTIL={until_utc.strftime('%Y%m%dT%H%M%SZ')}")
                    else:
                        parts.append(f"UNTIL={until.strftime('%Y%m%dT%H%M%SZ')}")
                else:
                    # Handle string case
                    until_str = str(until)
                    parts.append(f"UNTIL={until_str}")
            
            # Byday (for weekly/monthly recurrences)
            if 'BYDAY' in rrule_dict:
                byday = rrule_dict['BYDAY']
                if isinstance(byday, list):
                    byday_values = [extract_and_clean_value(day) for day in byday]
                    byday_str = ','.join(byday_values)
                else:
                    byday_str = extract_and_clean_value(byday)
                parts.append(f"BYDAY={byday_str}")
            
            # Bymonth (for yearly recurrences)
            if 'BYMONTH' in rrule_dict:
                bymonth = rrule_dict['BYMONTH']
                if isinstance(bymonth, list):
                    bymonth_values = [extract_and_clean_value(month) for month in bymonth]
                    bymonth_str = ','.join(bymonth_values)
                else:
                    bymonth_str = extract_and_clean_value(bymonth)
                parts.append(f"BYMONTH={bymonth_str}")
            
            # Bymonthday (for monthly recurrences)
            if 'BYMONTHDAY' in rrule_dict:
                bymonthday = rrule_dict['BYMONTHDAY']
                if isinstance(bymonthday, list):
                    bymonthday_values = [extract_and_clean_value(day) for day in bymonthday]
                    bymonthday_str = ','.join(bymonthday_values)
                else:
                    bymonthday_str = extract_and_clean_value(bymonthday)
                parts.append(f"BYMONTHDAY={bymonthday_str}")
            
            # WKST (week start) - Google Calendar supports this
            if 'WKST' in rrule_dict:
                wkst = extract_and_clean_value(rrule_dict['WKST'])
                parts.append(f"WKST={wkst}")
            
            result = ';'.join(parts)
            logger.debug(f"Formatted RRULE: {result}")
            return result
            
        except Exception as e:
            logger.warning(f"Error formatting RRULE for Google Calendar: {e}")
            logger.warning(f"Original rrule_dict: {rrule_dict}")
            # Return a basic RRULE if formatting fails
            if 'FREQ' in rrule_dict:
                freq = extract_and_clean_value(rrule_dict['FREQ'])
                return f"FREQ={freq}"
            return "FREQ=WEEKLY"
    
    def _deal_with_recurring_events(self, events: list, existing_events_map: dict):
        # Deal with recurring events
        # Find master recurring events in existing events for all recurring instances
        # If no existing master recurring event, find a master recurring event in the new events
        # If no master recurring event in the new events, set the event type to dangling_recurring_instance
        for event_data in events:
            if event_data.get('event_type') == 'recurring_instance':
                # Check if the UID exists in existing events before accessing
                if event_data.get('uid') in existing_events_map:
                    for existing_event in existing_events_map[event_data.get('uid')]:
                        if existing_event.get('recurrence'):
                            event_data['master_recurring_event'] = existing_event
                            break
                
                if event_data.get('master_recurring_event') is None:
                    event_data['event_type'] = 'dangling_recurring_instance'
                    for new_event in events:
                        if new_event.get('event_type') == 'master_recurring' and new_event.get('uid') == event_data.get('uid'):
                            event_data['event_type'] = 'recurring_instance'
                            event_data['master_recurring_event'] = new_event
                            break

            if event_data.get('event_type') == 'dangling_recurring_instance':
                event_data['event_type'] = 'normal'
                event_data['uid'] = str(uuid.uuid4())
            
            assert(event_data['event_type'] in ['recurring_instance', 'master_recurring', 'normal'])
            # Only assert master_recurring_event for recurring instances
            if event_data['event_type'] == 'recurring_instance':
                assert(event_data.get('master_recurring_event') is not None)

    def import_events_to_calendar(self, events: list):
        """Import events to Google Calendar using delta-based sync for efficiency."""
        if not events:
            logger.info("No events to import")
            return
        
        imported_count = 0
        updated_count = 0
        skipped_count = 0
        error_count = 0
        deleted_count = 0
        
        # Get all existing events from the calendar for delta comparison
        logger.info("Fetching existing events for delta sync...")
        existing_events = self.get_existing_events()
        existing_events_map = {}
        for event in existing_events:
            if event.get('iCalUID') in existing_events_map:
                existing_events_map[event.get('iCalUID')].append(event)
            else:
                existing_events_map[event.get('iCalUID')] = [event]
        existing_uids = set(existing_events_map.keys())
        
        # Deal with recurring events
        self._deal_with_recurring_events(events, existing_events_map)
        
        # Get UIDs from the new events (filter out empty UIDs)
        new_uids = {event_data.get('uid', '') for event_data in events if event_data.get('uid') and event_data.get('uid').strip()}

        logger.debug(f"Existing UIDs count: {len(existing_uids)}")
        logger.debug(f"New UIDs count: {len(new_uids)}")
        
        # Find events to delete (exist in calendar but not in new ICS file)
        events_to_delete = existing_uids - new_uids
        logger.info(f"Found {len(events_to_delete)} events to delete")
        for uid in events_to_delete:
            if self.delete_event_by_uid(uid, existing_events_map):
                deleted_count += 1
            else:
                logger.warning(f"Failed to delete event with UID: {uid}")
        
        # Process events for delta sync
        logger.info("Processing events for delta sync...")
        events_to_insert = []
        events_to_update = []
        
        for event_data in events:
            if event_data.get('uid') not in existing_events_map or not event_data.get('uid'):
                events_to_insert.append(event_data)
                continue

            if event_data.get('event_type') == 'recurring_instance':
                assert(event_data['master_recurring_event'] is not None)
                if self.recurring_instance_needs_update(event_data, existing_events_map):
                    events_to_update.append((event_data, event_data['master_recurring_event']))
            elif event_data.get('event_type') == 'master_recurring':
                if self.recurring_master_needs_update(event_data, existing_events_map):
                    events_to_update.append((event_data, event_data['existing_master_event']))
            else:
                assert(len(existing_events_map[event_data.get('uid')]) == 1)
                existing_event = existing_events_map[event_data.get('uid')][0]
                if self.normal_event_needs_update(event_data, existing_event):
                    events_to_update.append((event_data, existing_event))
                else:
                    skipped_count += 1
        
        logger.info(f"Delta sync: {len(events_to_insert)} to insert, {len(events_to_update)} to update, {skipped_count} unchanged")
        
        # Process events to insert (new events)
        master_recurring_event_map = {}
        for event_data in events_to_insert:
            try:
                if self.insert_event(event_data, master_recurring_event_map):
                    imported_count += 1
                else:
                    error_count += 1
            except Exception as e:
                logger.error(f"Unexpected error inserting event '{event_data['summary']}': {e}")
                error_count += 1
        
        # Process events to update (changed events)
        for event_data, existing_event in events_to_update:
            try:
                if self.update_event(event_data, existing_event):
                    updated_count += 1
                else:
                    error_count += 1
            except Exception as e:
                logger.error(f"Unexpected error updating event '{event_data['summary']}': {e}")
                error_count += 1
        
        logger.info(f"Delta sync completed: {imported_count} inserted, {updated_count} updated, {skipped_count} unchanged, {deleted_count} deleted, {error_count} errors")
    
    def get_existing_events(self) -> list:
        """Get all existing events from the calendar."""
        try:
            logger.debug("Fetching existing events from calendar...")
            events_result = self.service.events().list(
                calendarId=self.calendar_id,
                maxResults=2500,  # Google Calendar API limit
            ).execute()
            
            events = events_result.get('items', [])
            logger.debug(f"Found {len(events)} existing events in calendar")
            return events
            
        except HttpError as error:
            logger.error(f"Error fetching existing events: {error}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error fetching existing events: {e}")
            return []
    
    def delete_event_by_uid(self, uid: str, existing_events_map: dict = None) -> bool:
        """Delete an event by its iCalUID."""
        try:
            logger.debug(f"Attempting to delete event with UID: {uid}")
            
            event = None
            event_id = None
            
            # First try to find the event in the existing events map (more reliable)
            if existing_events_map and uid in existing_events_map:
                events_list = existing_events_map[uid]
                if events_list:
                    event = events_list[0]  # Get the first event from the list
                    event_id = event['id']
                    logger.debug(f"Found event in existing events map: '{event.get('summary', 'Untitled')}' (ID: {event_id})")
                else:
                    logger.warning(f"Empty events list for UID {uid}")
                    return False
            else:
                # Fallback to API search (less reliable for some UID formats)
                logger.debug(f"Event not in existing map, trying API search...")
                events_result = self.service.events().list(
                    calendarId=self.calendar_id,
                    q=uid,
                    maxResults=1
                ).execute()
                
                events = events_result.get('items', [])
                if not events:
                    logger.warning(f"Event with UID {uid} not found via API search")
                    return False
                
                event = events[0]
                event_id = event['id']
                event_ical_uid = event.get('iCalUID', 'No iCalUID')
                
                # Verify the UID matches (safety check)
                if event_ical_uid != uid:
                    logger.warning(f"UID mismatch: expected {uid}, found {event_ical_uid}")
                    return False
            
            event_summary = event.get('summary', 'Untitled Event')
            logger.debug(f"Found event to delete: '{event_summary}' (ID: {event_id})")
            
            # Delete the event
            self.service.events().delete(
                calendarId=self.calendar_id,
                eventId=event_id
            ).execute()
            
            logger.info(f"Successfully deleted event: {event_summary}")
            return True
            
        except HttpError as error:
            logger.error(f"HTTP error deleting event with UID {uid}: {error}")
            if hasattr(error, 'resp') and hasattr(error.resp, 'status'):
                logger.error(f"HTTP status code: {error.resp.status}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error deleting event with UID {uid}: {e}")
            return False
    
    def recurring_instance_needs_update(self, new_event_data: dict, existing_events_map: dict) -> bool:
        """Check if a recurring event needs updating by comparing key fields."""
        """For all events with the same UID, start, and end, check if the summary, description, location, or recurrence rule. If new_event_data matches any one existing event, return False."""
        logger.info(f"Checking if recurring event {new_event_data.get('summary')} needs updating")
        for existing_event in existing_events_map[new_event_data.get('uid')]:
            if not self.normal_event_needs_update(new_event_data, existing_event):
                logger.info(f"Recurring event instance {new_event_data.get('summary')} does not need updating, matches existing event {existing_event.get('summary')}")
                return False
        logger.info(f"Recurring event instance {new_event_data.get('summary')} needs updating, does not match any existing event")
        return True
    
    def recurring_master_needs_update(self, new_event_data: dict, existing_events_map: dict) -> bool:
        """Check if a recurring master event needs updating by comparing key fields."""
        logger.info(f"Checking if recurring master event {new_event_data.get('summary')} needs updating")
        # Check if the existing event is also a recurring event
        if len(existing_events_map[new_event_data.get('uid')]) == 1 and not existing_events_map[new_event_data.get('uid')][0].get('recurrence'):
            logger.info(f"Existing matching event {new_event_data.get('summary')} is not a recurring event")
            new_event_data['existing_master_event'] = existing_events_map[new_event_data.get('uid')][0]
            return True

        # Check if the existing event has the same rrule
        existing_master_event = None
        for existing_event in existing_events_map[new_event_data.get('uid')]:
            if existing_event.get('recurrence'):
                existing_master_event = existing_event
                break

        new_event_data['existing_master_event'] = existing_master_event
        if existing_master_event.get('rrule') != new_event_data.get('recurrence'):
            logger.info(f"Existing matching event {new_event_data.get('summary')} has a different rrule, {existing_master_event.get('rrule')} -> {new_event_data.get('recurrence')}")
            return True
        
        # Check if the existing event has the same summary, start time, etc.
        if self.normal_event_needs_update(new_event_data, existing_master_event):
            logger.info(f"Recurrent master event needs updating, {new_event_data.get('summary')} -> {existing_master_event.get('summary')}")
            return True
        logger.info(f"Recurrent master event does not need updating, {new_event_data.get('summary')} -> {existing_master_event.get('summary')}")
        return False

    def normal_event_needs_update(self, new_event_data: dict, existing_event: dict) -> bool:
        """Check if an event needs updating by comparing key fields."""
        try:
            # Normalize strings for comparison (strip whitespace, handle None)
            def normalize_str(value):
                if value is None:
                    return ''
                return str(value).strip()
            
            # Compare summary
            new_summary = normalize_str(new_event_data.get('summary'))
            existing_summary = normalize_str(existing_event.get('summary'))
            if new_summary != existing_summary:
                logger.info(f"Summary changed: '{existing_summary}' -> '{new_summary}'")
                return True
            
            # Compare description
            new_description = normalize_str(new_event_data.get('description'))
            existing_description = normalize_str(existing_event.get('description'))
            if new_description != existing_description:
                logger.info(f"Description changed: '{existing_description}' -> '{new_description}'")
                return True
            
            # Compare location
            new_location = normalize_str(new_event_data.get('location'))
            existing_location = normalize_str(existing_event.get('location'))
            if new_location != existing_location:
                logger.info(f"Location changed: '{existing_location}' -> '{new_location}'")
                return True
            
            # Compare start time
            if self._times_different(new_event_data.get('start'), existing_event.get('start')):
                logger.info(f"Start time changed for {new_summary}")
                return True
            
            # Compare end time
            if self._times_different(new_event_data.get('end'), existing_event.get('end')):
                logger.info(f"End time changed for {new_summary}")
                return True
            
            logger.info(f"No changes detected for {new_summary}")
            return False
            
        except Exception as e:
            logger.warning(f"Error comparing events, assuming update needed: {e}")
            return True
    
    def _times_different(self, new_time, existing_time_dict) -> bool:
        """Compare time objects with Google Calendar time format."""
        try:
            if not new_time:
                return existing_time_dict is not None
            
            if not existing_time_dict:
                return new_time is not None
            
            new_dt = new_time.dt
            existing_dt_str = existing_time_dict.get('dateTime') or existing_time_dict.get('date')
            
            if not existing_dt_str:
                return True
            
            # Convert new time to string format for comparison
            if hasattr(new_dt, 'date') and not hasattr(new_dt, 'time'):
                # All-day event
                new_dt_str = new_dt.strftime('%Y-%m-%d')
                # For all-day events, Google Calendar stores just the date
                return new_dt_str != existing_dt_str
            else:
                # Timed event - normalize both to UTC for proper comparison
                if new_dt.tzinfo is None:
                    new_dt = pytz.utc.localize(new_dt)
                
                # Parse the existing time string to a datetime object
                try:
                    from dateutil import parser
                    existing_dt = parser.parse(existing_dt_str)
                    if existing_dt.tzinfo is None:
                        existing_dt = pytz.utc.localize(existing_dt)
                except Exception as parse_error:
                    logger.warning(f"Could not parse existing time '{existing_dt_str}': {parse_error}")
                    # Fall back to string comparison
                    return new_dt.isoformat() != existing_dt_str
                
                # Convert both to UTC for comparison
                new_dt_utc = new_dt.astimezone(pytz.utc)
                existing_dt_utc = existing_dt.astimezone(pytz.utc)
                
                # Compare the actual datetime objects (ignoring microseconds and seconds for recurring events)
                new_dt_utc_normalized = new_dt_utc.replace(microsecond=0, second=0)
                existing_dt_utc_normalized = existing_dt_utc.replace(microsecond=0, second=0)
                
                # For recurring events, be more tolerant - only consider it different if minute-level time changes
                different = new_dt_utc_normalized != existing_dt_utc_normalized
                
                if different:
                    logger.debug(f"Time different (UTC normalized): '{existing_dt_utc_normalized.isoformat()}' vs '{new_dt_utc_normalized.isoformat()}'")
                    logger.debug(f"Original times: '{existing_dt_str}' vs '{new_dt.isoformat()}'")
                
                return different
                
        except Exception as e:
            logger.warning(f"Error comparing times: {e}")
            return True
    
    def insert_event(self, event_data: dict, master_recurring_event_map: dict) -> bool:
        """Insert a new event into the calendar."""
        try:
            event_type = event_data.get('event_type', 'normal')
            
            if event_type == 'master_recurring':
                # Insert master recurring event as recurring series
                return self._insert_master_recurring_event(event_data, master_recurring_event_map)
            elif event_type == 'recurring_instance':
                # Insert recurring instance as individual event (no recurrence)
                return self._insert_recurring_instance(event_data, master_recurring_event_map)
            else:
                # Insert normal event
                return self._insert_normal_event(event_data)
                
        except Exception as e:
            logger.error(f"Unexpected error inserting event '{event_data['summary']}': {e}, event_type: {event_type}")
            return False

    def _insert_master_recurring_event(self, event_data: dict, master_recurring_event_map: dict) -> bool:
        """Insert master recurring event as recurring series."""
        try:
            google_event = self._create_google_event(event_data)
            created_event = self.service.events().insert(
                calendarId=self.calendar_id,
                body=google_event
            ).execute()
            logger.info(f"Inserted master recurring event: {event_data['summary']}")
            master_recurring_event_map[event_data['uid']] = created_event
            return True
        except Exception as e:
            logger.error(f"Error inserting master recurring event '{event_data['summary']}': {e}")
            return False

    def _insert_recurring_instance(self, event_data: dict, master_recurring_event_map: dict) -> bool:
        """Insert recurring instance as individual event (no recurrence)."""
        try:
            # Create event data without recurrence rules
            instance_event_data = event_data.copy()
            instance_event_data['rrule'] = None
            instance_event_data['is_recurring'] = False
            
            google_event = self._create_google_event(instance_event_data)
            created_event = self.service.events().patch(
                calendarId=self.calendar_id,
                eventId=master_recurring_event_map[event_data['uid']]['id'],
                body=google_event
            ).execute()
            logger.info(f"Patched recurring instance: {event_data['summary']}")
            return True
        except Exception as e:
            logger.error(f"Error patching recurring instance '{event_data['summary']}': {e}, {event_data['uid']}, {event_data['recurrence_id']}")
            return False

    def _insert_normal_event(self, event_data: dict) -> bool:
        """Insert normal event."""
        try:
            google_event = self._create_google_event(event_data)
            created_event = self.service.events().insert(
                calendarId=self.calendar_id,
                body=google_event
            ).execute()
            logger.info(f"Inserted normal event: {event_data['summary']}")
            return True
        except Exception as e:
            logger.error(f"Error inserting normal event '{event_data['summary']}': {e}")
            return False

    def _create_google_datetime(self, dt_component) -> dict:
        """Create Google Calendar API datetime format from iCal component."""
        if not dt_component:
            return None
            
        dt = dt_component.dt
        
        # Handle all-day events
        if hasattr(dt, 'date') and not hasattr(dt, 'time'):
            return {'date': dt.strftime('%Y-%m-%d')}
        
        # Handle timed events
        if dt.tzinfo is None:
            dt = pytz.utc.localize(dt)
        
        # Convert to UTC and format
        dt_utc = dt.astimezone(pytz.utc)
        return {
            'dateTime': dt_utc.strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-3] + 'Z',
            'timeZone': str(dt.tzinfo)
        }

    def _patch_recurring_instance(self, event_data: dict, existing_event: dict) -> bool:
        """Update recurring instance using PATCH method."""
        try:
            # Create patch data with updated fields from master recurring event
            patch_data = {}
            
            # Update basic fields from the master event
            if event_data.get('summary') != existing_event.get('summary'):
                patch_data['summary'] = event_data['summary']
            
            if event_data.get('description') != existing_event.get('description'):
                patch_data['description'] = event_data['description']
                
            if event_data.get('location') != existing_event.get('location'):
                patch_data['location'] = event_data['location']
            
            # Update times if they're different
            if event_data.get('start') and existing_event.get('start'):
                new_start = self._create_google_datetime(event_data['start'])
                if new_start != existing_event['start']:
                    patch_data['start'] = new_start
                    
            if event_data.get('end') and existing_event.get('end'):
                new_end = self._create_google_datetime(event_data['end'])
                if new_end != existing_event['end']:
                    patch_data['end'] = new_end
            
            # Only patch if there are changes
            if patch_data:
                existing_event_id = existing_event['id']
                updated_event = self.service.events().patch(
                    calendarId=self.calendar_id,
                    eventId=existing_event_id,
                    body=patch_data
                ).execute()
                logger.info(f"Patched recurring instance: {event_data['summary']} with {len(patch_data)} fields")
                return True
            else:
                logger.debug(f"No changes needed for recurring instance: {event_data['summary']}")
                return True
                
        except Exception as e:
            logger.error(f"Error patching recurring instance '{event_data['summary']}': {e}")
            return False

    def update_event(self, event_data: dict, existing_event: dict) -> bool:
        """Update an existing event in the calendar."""
        try:
            event_type = event_data.get('event_type', 'normal')
            
            if event_type == 'recurring_instance':
                # Update recurring instance using PATCH
                return self._patch_recurring_instance(event_data, existing_event)
            else:
                # Update normal events and master recurring events using update API
                return self._update_event_with_update_api(event_data, existing_event)
                
        except Exception as e:
            logger.error(f"Unexpected error updating event '{event_data['summary']}': {e}, event_type: {event_type}")
            return False

    def _update_event_with_update_api(self, event_data: dict, existing_event: dict) -> bool:
        """Update normal events and master recurring events using update API."""
        try:
            logger.info(f"Updating event with update API: {event_data['summary']}")
            
            event_id = existing_event['id']
            google_event = self._create_google_event(event_data)
            
            # For recurring events, try to handle recurrence rules properly
            if event_data.get('is_recurring') and 'recurrence' in google_event:
                logger.debug(f"Updating recurring event with recurrence rule: {google_event['recurrence']}")
            
            # Update the event
            updated_event = self.service.events().update(
                calendarId=self.calendar_id,
                eventId=event_id,
                body=google_event
            ).execute()
            
            logger.info(f"Updated event: {event_data['summary']}")
            return True
            
        except HttpError as error:
            logger.error(f"Error updating event '{event_data['summary']}': {error}")
            return False

        except Exception as e:
            logger.error(f"Unexpected error updating event '{event_data['summary']}': {e}")
            return False

    def _create_google_event(self, event_data: dict) -> dict:
        """Create a Google Calendar event object from event data."""
        google_event = {
            'summary': event_data['summary'],
            'description': event_data['description'],
            'location': event_data['location'],
        }
        
        # Add iCalUID if available (helps prevent duplicates)
        if event_data.get('uid'):
            google_event['iCalUID'] = event_data['uid']
        
        # Handle date/time with proper timezone handling
        if event_data['start']:
            start_dt = event_data['start'].dt
            logger.debug(f"Processing start time: {start_dt} (type: {type(start_dt)})")
            
            if hasattr(start_dt, 'date') and not hasattr(start_dt, 'time'):
                # All-day event (date only)
                google_event['start'] = {
                    'date': start_dt.strftime('%Y-%m-%d')
                }
                logger.debug(f"All-day event start: {google_event['start']}")
                
                if event_data['end']:
                    end_dt = event_data['end'].dt
                    google_event['end'] = {
                        'date': end_dt.strftime('%Y-%m-%d')
                    }
                    logger.debug(f"All-day event end: {google_event['end']}")
            else:
                # Timed event
                # Handle timezone properly
                if start_dt.tzinfo is None:
                    # No timezone info, assume UTC
                    start_dt = pytz.utc.localize(start_dt)
                    logger.debug("Added UTC timezone to start time")
                
                # Format datetime for Google Calendar API
                try:
                    if start_dt.tzinfo:
                        # Use UTC format for timezone-aware datetimes
                        start_dt_utc = start_dt.astimezone(pytz.utc)
                        google_event['start'] = {
                            'dateTime': start_dt_utc.strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-3] + 'Z',  # Remove last 3 microseconds
                            'timeZone': str(start_dt.tzinfo)
                        }
                    else:
                        # For naive datetimes, assume UTC
                        google_event['start'] = {
                            'dateTime': start_dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-3] + 'Z',
                            'timeZone': 'UTC'
                        }
                    logger.debug(f"Timed event start: {google_event['start']}")
                except Exception as e:
                    logger.error(f"Error formatting start time for event '{event_data['summary']}': {e}")
                    return google_event
                
                if event_data['end']:
                    end_dt = event_data['end'].dt
                    if end_dt.tzinfo is None:
                        # No timezone info, assume UTC
                        end_dt = pytz.utc.localize(end_dt)
                        logger.debug("Added UTC timezone to end time")
                    
                    # Format end datetime for Google Calendar API
                    try:
                        if end_dt.tzinfo:
                            # Use UTC format for timezone-aware datetimes
                            end_dt_utc = end_dt.astimezone(pytz.utc)
                            google_event['end'] = {
                                'dateTime': end_dt_utc.strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-3] + 'Z',  # Remove last 3 microseconds
                                'timeZone': str(end_dt.tzinfo)
                            }
                        else:
                            # For naive datetimes, assume UTC
                            google_event['end'] = {
                                'dateTime': end_dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-3] + 'Z',
                                'timeZone': 'UTC'
                            }
                        logger.debug(f"Timed event end: {google_event['end']}")
                    except Exception as e:
                        logger.error(f"Error formatting end time for event '{event_data['summary']}': {e}")
                        # Continue without end time
        
        # Handle recurrence rules for recurring events
        if event_data.get('is_recurring') and event_data.get('rrule'):
            try:
                # Convert RRULE to Google Calendar format
                rrule_dict = dict(event_data['rrule'])
                formatted_rrule = self._format_rrule_for_google(rrule_dict)
                google_event['recurrence'] = [f"RRULE:{formatted_rrule}"]
                logger.debug(f"Added recurrence rule to google_event: {google_event['recurrence']}")
            except Exception as e:
                logger.warning(f"Error adding recurrence rule to event '{event_data['summary']}': {e}")
        
        return google_event
    
    def sync_calendar(self):
        """Perform one sync cycle."""
        logger.info("Starting calendar sync cycle")
        
        # Download ICS file
        ics_file = self.download_ics_file()
        if not ics_file:
            return
        
        try:
            # Parse events
            events = self.parse_ics_file(ics_file)
            
            # Import events
            self.import_events_to_calendar(events)
            
        finally:
            # Clean up temporary file
            if os.path.exists(ics_file):
                os.remove(ics_file)
                logger.debug(f"Cleaned up temporary file: {ics_file}")
    
    def run_continuous_sync(self, interval_minutes: int = 1):
        """Run continuous sync with specified interval."""
        logger.info(f"Starting continuous sync every {interval_minutes} minute(s)")
        
        try:
            while True:
                self.sync_calendar()
                logger.info(f"Waiting {interval_minutes} minute(s) before next sync...")
                time.sleep(interval_minutes * 60)
                
        except KeyboardInterrupt:
            logger.info("Sync stopped by user")
        except Exception as e:
            logger.error(f"Unexpected error in continuous sync: {e}")
            raise

def main():
    """Main function to run the calendar sync."""
    # Load configuration from file first, then fall back to environment variables
    config = load_config()
    
    # Configuration with fallback: config file -> environment variable -> default
    ICS_URL = config.get('ICS_URL') or os.getenv('ICS_URL', 'https://example.com/calendar.ics')
    CALENDAR_NAME = config.get('CALENDAR_NAME') or os.getenv('CALENDAR_NAME', 'Imported Calendar')
    CREDENTIALS_FILE = config.get('CREDENTIALS_FILE') or os.getenv('CREDENTIALS_FILE', 'credentials.json')
    SYNC_INTERVAL = int(config.get('SYNC_INTERVAL') or os.getenv('SYNC_INTERVAL', '1'))
    DEBUG_MODE = config.get('DEBUG_MODE', '').lower() == 'true' or os.getenv('DEBUG_MODE', '').lower() == 'true'
    
    # Log rotation configuration
    LOG_MAX_BYTES = int(config.get('LOG_MAX_BYTES') or os.getenv('LOG_MAX_BYTES', '10485760'))  # 10MB default
    LOG_BACKUP_COUNT = int(config.get('LOG_BACKUP_COUNT') or os.getenv('LOG_BACKUP_COUNT', '5'))
    LOG_FILE = config.get('LOG_FILE') or os.getenv('LOG_FILE', 'calendar_sync.log')
    
    # Reconfigure logging with rotation settings
    global logger
    logger = setup_logging(max_bytes=LOG_MAX_BYTES, backup_count=LOG_BACKUP_COUNT, log_file=LOG_FILE)
    
    # Set debug logging if enabled
    if DEBUG_MODE:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.info("Debug mode enabled - detailed logging active")
    
    logger.info(f"Log rotation configured: max {LOG_MAX_BYTES} bytes, {LOG_BACKUP_COUNT} backup files")
    
    if ICS_URL == 'https://example.com/calendar.ics':
        logger.error("Please set the ICS_URL in config.env or as an environment variable")
        sys.exit(1)
    
    logger.info(f"Starting calendar sync for: {ICS_URL}")
    logger.info(f"Target calendar: {CALENDAR_NAME}")
    logger.info(f"Sync interval: {SYNC_INTERVAL} minute(s)")
    logger.info(f"Debug mode: {'enabled' if DEBUG_MODE else 'disabled'}")
    
    try:
        sync = CalendarSync(ICS_URL, CALENDAR_NAME, CREDENTIALS_FILE)
        sync.authenticate_google_calendar()
        sync.find_or_create_calendar()
        sync.run_continuous_sync(SYNC_INTERVAL)
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
