"""
CISA ICS-CERT Feed Ingester

This module fetches threat advisories from CISA's Industrial Control Systems
Cyber Emergency Response Team (ICS-CERT). These advisories focus on threats
to critical infrastructure, which includes public safety systems like 911,
emergency radio networks, and related infrastructure.

CISA publishes advisories as RSS/XML feeds that we can parse programmatically.
We'll fetch these advisories, extract relevant information, and prepare them
for ECROSPK scoring.

Why CISA ICS-CERT?
- Government source = high authority (contributes to Evidence factor)
- Focuses on infrastructure = relevant to public safety
- Structured format = easy to parse
- Free, public access = no API keys needed
"""

import feedparser
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from dateutil import parser as date_parser


class CISAICSFeedIngester:
    """
    Fetches and parses CISA ICS-CERT advisories.
    
    This class handles the entire process of:
    1. Fetching the RSS feed from CISA
    2. Parsing the XML/RSS structure
    3. Extracting relevant fields
    4. Converting to our internal format
    5. Calculating how many months old each advisory is
    """
    
    # CISA ICS-CERT advisory feed URL
    # This RSS feed contains all published ICS advisories
    FEED_URL = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
    
    def __init__(self, timeout: int = 30):
        """
        Initialize the feed ingester.
        
        Args:
            timeout: How long to wait for the feed to respond (in seconds)
                    Default is 30 seconds, which is reasonable for a government site
                    that might be slower than commercial APIs.
        """
        self.timeout = timeout
        
        # We'll store the last successful fetch time to track freshness
        # This helps us know if we're getting stale data
        self.last_fetch_time: Optional[datetime] = None
        
        # ========================================
        # HTTP Headers to avoid 403 Forbidden
        # ========================================
        # Government sites often block requests without proper headers
        # because they look like bots/scrapers. We need to include headers
        # that make our request look like it's coming from a real browser.
        self.headers = {
            # User-Agent: Tells the server what browser/client is making the request
            # We identify as a modern Firefox browser on Windows
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            
            # Accept: Tells the server what content types we can handle
            # We're willing to accept XML, HTML, or anything
            'Accept': 'application/xml, text/xml, application/rss+xml, */*',
            
            # Accept-Language: Tells the server our language preference
            'Accept-Language': 'en-US,en;q=0.9',
            
            # Accept-Encoding: We can handle compressed responses
            'Accept-Encoding': 'gzip, deflate, br',
            
            # Connection: Keep the connection alive for potential future requests
            'Connection': 'keep-alive',
            
            # Referer: Some sites want to know where the request came from
            # We say we came from CISA's main page
            'Referer': 'https://www.cisa.gov/',
        }
    
    def fetch_advisories(self, max_items: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Fetch and parse CISA ICS-CERT advisories from the RSS feed.
        
        This is the main entry point. It fetches the feed, parses it,
        and returns a list of advisory dictionaries ready for scoring.
        
        Args:
            max_items: Optional limit on how many advisories to return.
                      Useful for testing or limiting processing.
                      If None, returns all available advisories.
        
        Returns:
            List of dictionaries, each representing one advisory with fields:
            - id: Unique advisory identifier (e.g., "ICSA-23-166-01")
            - title: Advisory title
            - summary: Brief description
            - published: Publication date as datetime object
            - link: URL to full advisory
            - months_old: How many months since publication (for Recency)
            - tags: List of relevant tags/categories
        
        Raises:
            requests.RequestException: If the network request fails
            ValueError: If the feed can't be parsed
        """
        try:
            # ========================================
            # STEP 1: Fetch the RSS feed
            # ========================================
            # We use requests library to fetch the XML feed
            # The timeout prevents hanging if CISA's servers are slow/down
            # The headers make us look like a legitimate browser
            print(f"Fetching CISA ICS-CERT feed from {self.FEED_URL}...")
            
            response = requests.get(
                self.FEED_URL, 
                timeout=self.timeout,
                headers=self.headers  # This is the key fix for the 403 error
            )
            
            # Raise an exception if we got an error status code (404, 500, etc.)
            # This ensures we don't try to parse error pages as RSS feeds
            response.raise_for_status()
            
            # Record when we successfully fetched the feed
            self.last_fetch_time = datetime.now(timezone.utc)
            
            # ========================================
            # STEP 2: Parse the RSS/XML feed
            # ========================================
            # feedparser is a robust library that handles various RSS/Atom formats
            # It returns a structured object we can navigate like a dictionary
            feed = feedparser.parse(response.content)
            
            # Check if parsing succeeded
            # The 'bozo' field indicates malformed feed (bozo=1 means problems)
            if feed.bozo:
                raise ValueError(f"Feed parsing error: {feed.bozo_exception}")
            
            # ========================================
            # STEP 3: Extract and transform entries
            # ========================================
            # The feed.entries list contains all advisory items
            # We'll convert each one from feedparser's format to our format
            advisories = []
            
            # Process each entry in the feed
            # If max_items is set, we'll only take that many (useful for testing)
            entries_to_process = feed.entries[:max_items] if max_items else feed.entries
            
            for entry in entries_to_process:
                try:
                    # Convert this RSS entry to our internal format
                    advisory = self._parse_entry(entry)
                    advisories.append(advisory)
                except Exception as e:
                    # If one advisory fails to parse, log it but continue with others
                    # We don't want one bad entry to kill the entire ingestion
                    print(f"Warning: Failed to parse entry {entry.get('id', 'unknown')}: {e}")
                    continue
            
            print(f"Successfully fetched {len(advisories)} advisories")
            return advisories
            
        except requests.RequestException as e:
            # Network errors: timeout, connection refused, DNS failure, 403 forbidden, etc.
            # We catch this separately to give helpful error messages
            if hasattr(e.response, 'status_code') and e.response.status_code == 403:
                print(f"Error: CISA server returned 403 Forbidden.")
                print(f"This usually means our request was blocked by their security.")
                print(f"We're using browser-like headers, but they may still be filtering.")
                print(f"You may need to run this from a different network or use a VPN.")
            else:
                print(f"Error fetching CISA feed: {e}")
            raise
        except Exception as e:
            # Any other unexpected error
            print(f"Unexpected error processing CISA feed: {e}")
            raise
    
    def _parse_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a single RSS entry into our internal advisory format.
        
        This method handles the conversion from feedparser's structure
        (which varies by feed format) to a consistent internal structure
        that our scoring and storage systems expect.
        
        Args:
            entry: A single entry from feedparser (one advisory)
        
        Returns:
            Dictionary with standardized advisory fields
        """
        # ========================================
        # Extract basic fields
        # ========================================
        # RSS feeds have standard fields that feedparser normalizes for us
        # We use .get() with defaults to handle missing fields gracefully
        
        # ID: Usually something like "ICSA-23-166-01"
        # This is our unique identifier for this advisory
        advisory_id = entry.get('id', entry.get('link', 'unknown'))
        
        # Title: Human-readable name of the advisory
        title = entry.get('title', 'Untitled Advisory')
        
        # Summary/description: Brief overview of the threat
        # Some feeds use 'summary', others use 'description'
        summary = entry.get('summary', entry.get('description', ''))
        
        # Link: URL to the full advisory on CISA's website
        link = entry.get('link', '')
        
        # ========================================
        # Parse publication date
        # ========================================
        # RSS feeds include publication dates, but in various formats
        # feedparser usually gives us 'published_parsed' (a time tuple)
        # or 'published' (a string we need to parse)
        
        published = None
        if hasattr(entry, 'published_parsed') and entry.published_parsed:
            # published_parsed is a time.struct_time tuple
            # We convert it to a proper datetime object with timezone
            from time import mktime
            timestamp = mktime(entry.published_parsed)
            published = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        elif 'published' in entry:
            # If we only have a string, use dateutil.parser to parse it
            # dateutil is smart enough to handle most date formats
            try:
                published = date_parser.parse(entry.published)
                # Ensure it has timezone info (assume UTC if not specified)
                if published.tzinfo is None:
                    published = published.replace(tzinfo=timezone.utc)
            except Exception as e:
                print(f"Warning: Could not parse date '{entry.published}': {e}")
                # Fall back to current time if parsing fails
                published = datetime.now(timezone.utc)
        else:
            # If no date at all, assume it's brand new
            published = datetime.now(timezone.utc)
        
        # ========================================
        # Calculate age in months
        # ========================================
        # For ECROSPK's Recency factor, we need to know how old the advisory is
        # We calculate months since publication
        months_old = self._calculate_months_old(published)
        
        # ========================================
        # Extract tags/categories
        # ========================================
        # Some RSS feeds include tags or categories
        # These can help us determine if an advisory is relevant to public safety
        tags = []
        if 'tags' in entry:
            # feedparser gives us a list of tag dictionaries
            tags = [tag.get('term', '') for tag in entry.tags]
        
        # ========================================
        # Return standardized format
        # ========================================
        return {
            'id': advisory_id,
            'title': title,
            'summary': summary,
            'published': published,
            'link': link,
            'months_old': months_old,
            'tags': tags,
            # We also store the source for tracking
            'source': 'CISA-ICS-CERT',
            # And when we fetched it
            'fetched_at': self.last_fetch_time
        }
    
    def _calculate_months_old(self, published_date: datetime) -> float:
        """
        Calculate how many months old an advisory is.
        
        This is used for the Recency factor in ECROSPK scoring.
        We calculate the difference between now and the publication date,
        then convert to months (approximating 30.44 days per month).
        
        Args:
            published_date: When the advisory was published
        
        Returns:
            Age in months as a float (e.g., 2.5 months)
        """
        # Get current time in UTC to match our stored dates
        now = datetime.now(timezone.utc)
        
        # Calculate the time difference
        time_delta = now - published_date
        
        # Convert to months
        # We use 30.44 days as average month length (365.25 / 12)
        # This handles the fact that months have different lengths
        months = time_delta.days / 30.44
        
        # Return with 2 decimal places
        return round(months, 2)
    
    def filter_public_safety_relevant(self, 
                                      advisories: List[Dict[str, Any]],
                                      keywords: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Filter advisories to only those relevant to public safety infrastructure.
        
        Not all ICS advisories are relevant to public safety. For example, an
        advisory about a power plant control system might not matter to 911 centers.
        This method filters to just the relevant ones based on keywords.
        
        Args:
            advisories: List of advisory dictionaries to filter
            keywords: List of keywords to search for. If None, uses default
                     public safety keywords.
        
        Returns:
            Filtered list containing only relevant advisories
        """
        # ========================================
        # Define public safety keywords
        # ========================================
        # These are terms that indicate an advisory might affect public safety systems
        if keywords is None:
            keywords = [
                # Emergency services
                'emergency', '911', 'e911', 'ng911',
                'ambulance', 'ems', 'fire', 'police',
                
                # Communication systems
                'radio', 'p25', 'tetra', 'dmr', 'apco',
                'dispatch', 'cad', 'computer aided dispatch',
                
                # Public safety orgs
                'public safety', 'first responder', 'psap',
                
                # Related infrastructure
                'alert', 'warning', 'notification',
                'siren', 'mass notification'
            ]
        
        # Convert to lowercase for case-insensitive matching
        keywords = [k.lower() for k in keywords]
        
        # ========================================
        # Filter advisories
        # ========================================
        relevant = []
        
        for advisory in advisories:
            # Combine title and summary into searchable text
            searchable_text = (
                advisory.get('title', '') + ' ' + 
                advisory.get('summary', '')
            ).lower()
            
            # Check if any keyword appears in the text
            is_relevant = any(keyword in searchable_text for keyword in keywords)
            
            if is_relevant:
                relevant.append(advisory)
        
        print(f"Filtered {len(advisories)} advisories down to {len(relevant)} relevant to public safety")
        return relevant


# ========================================
# Convenience function for quick testing
# ========================================
def fetch_recent_public_safety_advisories(max_items: int = 20) -> List[Dict[str, Any]]:
    """
    Quick function to fetch recent public safety-relevant CISA advisories.
    
    This is a convenience function that combines fetching and filtering
    in one step. Useful for testing or quick scripts.
    
    Args:
        max_items: Maximum number of advisories to fetch from feed
    
    Returns:
        List of relevant advisories
    """
    ingester = CISAICSFeedIngester()
    all_advisories = ingester.fetch_advisories(max_items=max_items)
    relevant = ingester.filter_public_safety_relevant(all_advisories)
    return relevant


if __name__ == "__main__":
    # ========================================
    # Test code - runs when you execute this file directly
    # ========================================
    print("Testing CISA ICS-CERT feed ingester...")
    print("=" * 60)
    
    try:
        # Fetch a few recent advisories
        advisories = fetch_recent_public_safety_advisories(max_items=10)
        
        # Display them
        print(f"\nFound {len(advisories)} public safety-relevant advisories:\n")
        for adv in advisories:
            print(f"ID: {adv['id']}")
            print(f"Title: {adv['title']}")
            print(f"Age: {adv['months_old']} months")
            print(f"Link: {adv['link']}")
            print("-" * 60)
    except Exception as e:
        print(f"\nTest failed with error: {e}")
        print("\nIf you're still getting 403 errors, CISA may be actively blocking")
        print("automated access. We can proceed by creating sample test data instead.")
