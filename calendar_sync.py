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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('calendar_sync.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

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
    def __init__(self, ics_url: str, calendar_name: str, credentials_file: str = 'credentials.json', enable_deletion: bool = True, debug_comparison: bool = False, dry_run: bool = False, enable_recurrent_events: bool = True, recurrent_event_mode: str = 'series'):
        """
        Initialize the CalendarSync instance.
        
        Args:
            ics_url: URL to download the ICS file from
            calendar_name: Name of the Google Calendar to import events to
            credentials_file: Path to Google OAuth credentials file
            enable_deletion: Whether to delete events not in the source ICS file
            debug_comparison: Whether to show detailed comparison logging
            dry_run: Whether to simulate operations without actually performing them
            enable_recurrent_events: Whether to handle recurring events properly
            recurrent_event_mode: How to handle recurring events (single_instance|series|both)
        """
        self.ics_url = ics_url
        self.calendar_name = calendar_name
        self.credentials_file = credentials_file
        self.enable_deletion = enable_deletion
        self.debug_comparison = debug_comparison
        self.dry_run = dry_run
        self.enable_recurrent_events = enable_recurrent_events
        self.recurrent_event_mode = recurrent_event_mode
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
    
    def parse_ics_file(self, ics_file_path: str) -> list:
        """Parse ICS file and extract events."""
        events = []
        recurrence_event_ids = []
        try:
            with open(ics_file_path, 'rb') as f:
                calendar = icalendar.Calendar.from_ical(f.read())
            
            for component in calendar.walk():
                if component.name == "VEVENT":
                    # Fix timezone issue - convert to UTC for Google Calendar API compatibility
                    if component.get('dtstart') and component.get('dtend'):
                        start_dt = component.get('dtstart').dt
                        end_dt = component.get('dtend').dt
                        
                        # Convert to UTC if timezone-aware
                        if hasattr(start_dt, 'tzinfo') and start_dt.tzinfo:
                            start_dt_utc = start_dt.astimezone(pytz.utc)
                            end_dt_utc = end_dt.astimezone(pytz.utc)
                            
                            # Update the component with UTC times
                            from icalendar import vDatetime
                            component['dtstart'] = vDatetime(start_dt_utc)
                            component['dtend'] = vDatetime(end_dt_utc)
                            logger.debug(f"Converted times to UTC: {start_dt} -> {start_dt_utc}, {end_dt} -> {end_dt_utc}")
                    
                    # Also convert recurrence-id to UTC if present
                    if component.get('recurrence-id'):
                        recurrence_dt = component.get('recurrence-id').dt
                        
                        # Convert to UTC if timezone-aware
                        if hasattr(recurrence_dt, 'tzinfo') and recurrence_dt.tzinfo:
                            recurrence_dt_utc = recurrence_dt.astimezone(pytz.utc)
                            
                            # Update the component with UTC time
                            from icalendar import vDatetime
                            component['recurrence-id'] = vDatetime(recurrence_dt_utc)
                            logger.debug(f"Converted recurrence-id to UTC: {recurrence_dt} -> {recurrence_dt_utc}")

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
                    elif event_data['uid'] in recurrence_event_ids:
                        # Follow-up instance of recurring event (no RRULE but UID matches a master)
                        event_data['event_type'] = 'recurring_instance'
                        logger.debug(f"Found recurring event instance: '{event_data['summary']}' with UID: {event_data['uid']}")
                    else:
                        # Normal event
                        event_data['event_type'] = 'normal'
                        logger.debug(f"Found normal event: '{event_data['summary']}'")
                    
                    if event_data['recurrence_id'] and event_data['event_type'] == 'normal':
                        event_data['uid'] = str(uuid.uuid4())
                    
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
            
        except Exception as e:
            logger.error(f"Error parsing ICS file: {e}")
            return []
    
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
        existing_events_map = {event.get('iCalUID', ''): event for event in existing_events if event.get('iCalUID')}
        existing_uids = set(existing_events_map.keys())
        
        # Get UIDs from the new events (filter out empty UIDs)
        new_uids = {event_data.get('uid', '') for event_data in events if event_data.get('uid') and event_data.get('uid').strip()}
        
        logger.debug(f"Existing UIDs count: {len(existing_uids)}")
        logger.debug(f"New UIDs count: {len(new_uids)}")
        
        # Debug: Show sample UIDs to identify potential issues
        if self.debug_comparison and existing_uids:
            sample_uids = list(existing_uids)[:3]
            logger.debug(f"Sample existing UIDs: {sample_uids}")
        
        # Handle event deletion if enabled
        if self.enable_deletion:
            # Find events to delete (exist in calendar but not in new ICS file)
            events_to_delete = existing_uids - new_uids
            
            logger.debug(f"Events to delete: {len(events_to_delete)}")
            if events_to_delete and self.debug_comparison:
                logger.info(f"Events to delete (UIDs): {list(events_to_delete)[:5]}...")  # Show first 5 for debugging
            
            if events_to_delete:
                if self.dry_run:
                    logger.info(f"[DRY RUN] Found {len(events_to_delete)} events that would be deleted")
                    if self.debug_comparison:
                        logger.info(f"[DRY RUN] Events to delete: {list(events_to_delete)}")
                    deleted_count = len(events_to_delete)  # Count as if deleted for dry run
                else:
                    logger.info(f"Found {len(events_to_delete)} events to delete")
                    for uid in events_to_delete:
                        if self.delete_event_by_uid(uid, existing_events_map):
                            deleted_count += 1
                        else:
                            logger.warning(f"Failed to delete event with UID: {uid}")
            else:
                logger.info("No events to delete")
        else:
            logger.info("Event deletion is disabled - only adding/updating events")
        
        # Process events for delta sync
        logger.info("Processing events for delta sync...")
        events_to_insert = []
        events_to_update = []
        
        for event_data in events:
            uid = event_data.get('uid', '')
            if not uid:
                # Events without UID always get inserted
                events_to_insert.append(event_data)
                continue
            
            if uid in existing_events_map:
                # Event exists - check if it needs updating
                existing_event = existing_events_map[uid]
                if self.event_needs_update(event_data, existing_event):
                    events_to_update.append((event_data, existing_event))
                else:
                    skipped_count += 1
            else:
                # New event - needs to be inserted
                events_to_insert.append(event_data)
        
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
                if self.update_event(event_data):
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
                singleEvents=True,
                orderBy='startTime'
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
                event = existing_events_map[uid]
                event_id = event['id']
                logger.debug(f"Found event in existing events map: '{event.get('summary', 'Untitled')}' (ID: {event_id})")
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
    
    def event_needs_update(self, new_event_data: dict, existing_event: dict) -> bool:
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
                if self.debug_comparison:
                    logger.info(f"Summary changed: '{existing_summary}' -> '{new_summary}'")
                else:
                    logger.debug(f"Summary changed: '{existing_summary}' -> '{new_summary}'")
                return True
            
            # Compare description
            new_description = normalize_str(new_event_data.get('description'))
            existing_description = normalize_str(existing_event.get('description'))
            if new_description != existing_description:
                logger.debug(f"Description changed: '{existing_description}' -> '{new_description}'")
                return True
            
            # Compare location
            new_location = normalize_str(new_event_data.get('location'))
            existing_location = normalize_str(existing_event.get('location'))
            if new_location != existing_location:
                logger.debug(f"Location changed: '{existing_location}' -> '{new_location}'")
                return True
            
            # Special handling for recurring events
            new_is_recurring = new_event_data.get('is_recurring', False)
            existing_recurrence = existing_event.get('recurrence', [])
            existing_is_recurring = len(existing_recurrence) > 0
            
            # Check if recurrence status changed
            if new_is_recurring != existing_is_recurring:
                if self.debug_comparison:
                    logger.info(f"Recurrence status changed for {new_summary}: {existing_is_recurring} -> {new_is_recurring}")
                return True
            
            # For recurring events, we need to determine if we're comparing the master event or an occurrence
            if new_is_recurring and existing_is_recurring:
                # Check if this is the master recurring event (has RRULE) or an individual occurrence
                new_has_rrule = new_event_data.get('rrule') is not None
                existing_has_rrule = len(existing_recurrence) > 0
                
                if new_has_rrule and existing_has_rrule:
                    # Both are master recurring events - compare recurrence rules
                    new_rrule = new_event_data.get('rrule')
                    if new_rrule:
                        new_rrule_str = self._format_rrule_for_google(dict(new_rrule))
                        existing_rrule_str = existing_recurrence[0].replace('RRULE:', '') if existing_recurrence else ''
                        
                        if new_rrule_str != existing_rrule_str:
                            if self.debug_comparison:
                                logger.info(f"Recurrence rule changed for {new_summary}: '{existing_rrule_str}' -> '{new_rrule_str}'")
                            return True
                    
                    # For master recurring events, also compare the base event properties (summary, description, location)
                    # but skip time comparison as individual occurrences may have different times
                    logger.debug(f"Master recurring event comparison completed for: {new_summary}")
                    return False
                    
                elif not new_has_rrule and not existing_has_rrule:
                    # Both are individual occurrences of recurring events - compare normally
                    # This will fall through to the time comparison below
                    logger.debug(f"Comparing individual occurrence of recurring event: {new_summary}")
                else:
                    # One is master, one is occurrence - they're different
                    if self.debug_comparison:
                        logger.info(f"Recurring event type mismatch for {new_summary}: master vs occurrence")
                    return True
            
            # Compare start time
            if self._times_different(new_event_data.get('start'), existing_event.get('start')):
                logger.debug(f"Start time changed for {new_summary}")
                return True
            
            # Compare end time
            if self._times_different(new_event_data.get('end'), existing_event.get('end')):
                logger.debug(f"End time changed for {new_summary}")
                return True
            
            logger.debug(f"No changes detected for {new_summary}")
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
                # Use PATCH for recurring instances
                return self._patch_recurring_instance(event_data, existing_event)
            elif event_data.get('is_recurring'):
                try:
                    logger.info(f"Updating recurring event with delete+insert method: {event_data['summary']}")
                    
                    # Delete the existing recurring event first
                    existing_event_id = existing_event['id']
                    try:
                        self.service.events().delete(
                            calendarId=self.calendar_id,
                            eventId=existing_event_id
                        ).execute()
                        logger.debug(f"Deleted existing recurring event: {existing_event_id}")
                        
                        # Add a small delay to ensure deletion is processed
                        import time
                        time.sleep(0.5)
                        
                    except HttpError as delete_error:
                        logger.warning(f"Failed to delete existing event {existing_event_id}: {delete_error}")
                        # Continue with insert anyway - it might work if the event is already gone
                    
                    # Try to use raw_data first, then fall back to _create_google_event
                    if event_data.get('raw_data'):
                        try:
                            # Use raw_data for import method
                            import_data = event_data.get('raw_data')
                            created_event = self.service.events().import_(
                                calendarId=self.calendar_id,
                                body=import_data
                            ).execute()
                            logger.info(f"Updated recurring event (via delete+import): {event_data['summary']}")
                            return True
                        except HttpError as import_error:
                            if "duplicate" in str(import_error).lower() or "already exists" in str(import_error).lower():
                                logger.info(f"Event already exists, skipping insert: {event_data['summary']}")
                                return True  # Consider it successful since the event exists
                            else:
                                logger.warning(f"Import with raw iCal data failed, falling back to insert: {import_error}")
                                # Fallback: Use insert method with created google_event
                                google_event = self._create_google_event(event_data)
                                
                                # If insert fails due to invalid start time, try without recurrence rules
                                try:
                                    created_event = self.service.events().insert(
                                        calendarId=self.calendar_id,
                                        body=google_event
                                    ).execute()
                                    logger.info(f"Updated recurring event (via delete+insert): {event_data['summary']}")
                                    return True
                                except HttpError as insert_error:
                                    if "duplicate" in str(insert_error).lower() or "already exists" in str(insert_error).lower():
                                        logger.info(f"Event already exists, skipping insert: {event_data['summary']}")
                                        return True  # Consider it successful since the event exists
                                    if "Invalid start time" in str(insert_error):
                                        logger.warning(f"Insert failed due to invalid start time, retrying without recurrence rules: {event_data['summary']}")
                                        # Remove recurrence rules and try again
                                        google_event_no_recurrence = google_event.copy()
                                        if 'recurrence' in google_event_no_recurrence:
                                            del google_event_no_recurrence['recurrence']
                                        
                                        created_event = self.service.events().insert(
                                            calendarId=self.calendar_id,
                                            body=google_event_no_recurrence
                                        ).execute()
                                        logger.info(f"Updated recurring event without recurrence rules (via delete+insert): {event_data['summary']}")
                                        return True
                                    else:
                                        raise insert_error
                    
                    # If no raw_data available, use insert method directly
                    google_event = self._create_google_event(event_data)
                    
                    # If insert fails due to invalid start time, try without recurrence rules
                    try:
                        created_event = self.service.events().insert(
                            calendarId=self.calendar_id,
                            body=google_event
                        ).execute()
                        logger.info(f"Updated recurring event (via delete+insert): {event_data['summary']}")
                        return True
                    except HttpError as insert_error:
                        if "duplicate" in str(insert_error).lower() or "already exists" in str(insert_error).lower():
                            logger.info(f"Event already exists, skipping insert: {event_data['summary']}")
                            return True  # Consider it successful since the event exists
                        if "Invalid start time" in str(insert_error):
                            logger.warning(f"Insert failed due to invalid start time, retrying without recurrence rules: {event_data['summary']}")
                            # Remove recurrence rules and try again
                            google_event_no_recurrence = google_event.copy()
                            if 'recurrence' in google_event_no_recurrence:
                                del google_event_no_recurrence['recurrence']
                            
                            created_event = self.service.events().insert(
                                calendarId=self.calendar_id,
                                body=google_event_no_recurrence
                            ).execute()
                            logger.info(f"Updated recurring event without recurrence rules (via delete+insert): {event_data['summary']}")
                            return True
                        else:
                            raise insert_error
                    
                except HttpError as delete_insert_error:
                    logger.warning(f"Delete+insert method failed for recurring event '{event_data['summary']}', falling back to update: {delete_insert_error}")
                    # Fall back to regular update method
                except Exception as delete_insert_error:
                    logger.warning(f"Unexpected error in delete+insert method for recurring event '{event_data['summary']}', falling back to update: {delete_insert_error}")
                    # Fall back to regular update method
            
            # Regular update method for non-recurring events or fallback
            event_id = existing_event['id']
            
            # Create the updated event data
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
            
            # If it's an invalid start time error for recurring events, try without recurrence
            if ("Invalid start time" in str(error) and 
                event_data.get('is_recurring') and 
                'recurrence' in google_event):
                logger.info(f"Retrying update without recurrence rules for: {event_data['summary']}")
                try:
                    # Remove recurrence rules and try again
                    google_event_without_recurrence = google_event.copy()
                    del google_event_without_recurrence['recurrence']
                    
                    updated_event = self.service.events().update(
                        calendarId=self.calendar_id,
                        eventId=event_id,
                        body=google_event_without_recurrence
                    ).execute()
                    
                    logger.info(f"Updated event without recurrence rules: {event_data['summary']}")
                    return True
                except Exception as retry_error:
                    logger.error(f"Retry without recurrence also failed for '{event_data['summary']}': {retry_error}")
            
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
        if (self.enable_recurrent_events and 
            event_data.get('is_recurring') and 
            event_data.get('rrule')):
            try:
                # Convert RRULE to Google Calendar format
                rrule_dict = dict(event_data['rrule'])
                formatted_rrule = self._format_rrule_for_google(rrule_dict)
                google_event['recurrence'] = [f"RRULE:{formatted_rrule}"]
                logger.debug(f"Added recurrence rule to google_event: {google_event['recurrence']}")
            except Exception as e:
                logger.warning(f"Error adding recurrence rule to event '{event_data['summary']}': {e}")
        elif event_data.get('is_recurring') and not self.enable_recurrent_events:
            logger.info(f"Recurrence disabled - treating '{event_data['summary']}' as single event")
        
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
    ENABLE_EVENT_DELETION = config.get('ENABLE_EVENT_DELETION', '').lower() != 'false'  # Default to true
    DEBUG_COMPARISON = config.get('DEBUG_COMPARISON', '').lower() == 'true' or os.getenv('DEBUG_COMPARISON', '').lower() == 'true'
    DRY_RUN = config.get('DRY_RUN', '').lower() == 'true' or os.getenv('DRY_RUN', '').lower() == 'true'
    ENABLE_RECURRENT_EVENTS = config.get('ENABLE_RECURRENT_EVENTS', '').lower() != 'false'  # Default to true
    RECURRENT_EVENT_MODE = config.get('RECURRENT_EVENT_MODE') or os.getenv('RECURRENT_EVENT_MODE', 'series')
    
    # Set debug logging if enabled
    if DEBUG_MODE:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.info("Debug mode enabled - detailed logging active")
    
    if ICS_URL == 'https://example.com/calendar.ics':
        logger.error("Please set the ICS_URL in config.env or as an environment variable")
        sys.exit(1)
    
    logger.info(f"Starting calendar sync for: {ICS_URL}")
    logger.info(f"Target calendar: {CALENDAR_NAME}")
    logger.info(f"Sync interval: {SYNC_INTERVAL} minute(s)")
    logger.info(f"Debug mode: {'enabled' if DEBUG_MODE else 'disabled'}")
    logger.info(f"Event deletion: {'enabled' if ENABLE_EVENT_DELETION else 'disabled'}")
    logger.info(f"Dry run mode: {'enabled' if DRY_RUN else 'disabled'}")
    logger.info(f"Recurrent events: {'enabled' if ENABLE_RECURRENT_EVENTS else 'disabled'}")
    logger.info(f"Recurrent event mode: {RECURRENT_EVENT_MODE}")
    
    try:
        sync = CalendarSync(ICS_URL, CALENDAR_NAME, CREDENTIALS_FILE, ENABLE_EVENT_DELETION, DEBUG_COMPARISON, DRY_RUN, ENABLE_RECURRENT_EVENTS, RECURRENT_EVENT_MODE)
        sync.authenticate_google_calendar()
        sync.find_or_create_calendar()
        sync.run_continuous_sync(SYNC_INTERVAL)
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
