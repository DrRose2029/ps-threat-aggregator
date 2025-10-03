"""
NVD (National Vulnerability Database) API Ingester

This module fetches vulnerability data from NIST's National Vulnerability Database.
The NVD contains every published CVE (Common Vulnerabilities and Exposures) with
detailed metadata including affected products, severity scores, and descriptions.

Why NVD?
- NIST/government source = high authority (same as CISA for Evidence factor)
- Designed for automated access = won't block us like CISA did
- Rich metadata = better ECROSPK scoring inputs
- Free API with no authentication required (but rate-limited)
- JSON format = easier to parse than RSS/XML

The NVD API is rate-limited to 5 requests per 30 seconds without an API key.
You can get a free API key from https://nvd.nist.gov/developers/request-an-api-key
to increase this to 50 requests per 30 seconds, but we'll start without one.

API Documentation: https://nvd.nist.gov/developers/vulnerabilities
"""

import requests
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from dateutil import parser as date_parser


class NVDAPIIngester:
    """
    Fetches and parses CVE data from the National Vulnerability Database API.
    
    This class handles:
    1. Querying the NVD API with filters
    2. Parsing JSON responses
    3. Extracting relevant vulnerability information
    4. Rate limiting to stay within API constraints
    5. Converting to our internal format for ECROSPK scoring
    """
    
    # NVD API v2.0 base URL
    # This is the current version of the API as of 2025
    API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None, rate_limit_delay: float = 6.0):
        """
        Initialize the NVD API ingester.
        
        Args:
            api_key: Optional NVD API key for higher rate limits.
                    Without a key: 5 requests per 30 seconds
                    With a key: 50 requests per 30 seconds
                    Get one free at: https://nvd.nist.gov/developers/request-an-api-key
            
            rate_limit_delay: Seconds to wait between requests (default 6.0).
                             This ensures we stay under the 5 requests/30 seconds limit.
                             6 seconds * 5 requests = 30 seconds, so we're safe.
                             If you have an API key, you could reduce this to 0.6 seconds.
        """
        self.api_key = api_key
        self.rate_limit_delay = rate_limit_delay
        
        # Track when we last made a request to enforce rate limiting
        # This prevents us from getting temporarily banned by NVD
        self.last_request_time: Optional[float] = None
        
        # We'll store the last successful fetch time to track freshness
        self.last_fetch_time: Optional[datetime] = None
        
        # ========================================
        # HTTP Headers for the NVD API
        # ========================================
        # The NVD API is designed for automation, so we don't need to
        # pretend to be a browser like we did with CISA. But we still
        # include a descriptive User-Agent so NVD knows who's using their API.
        self.headers = {
            # User-Agent: Identify our tool
            'User-Agent': 'PS-Threat-Aggregator/1.0 (Public Safety Threat Intelligence Tool)',
            
            # Accept: We want JSON responses
            'Accept': 'application/json',
        }
        
        # If we have an API key, add it to the headers
        # The NVD uses an "apiKey" parameter in the URL, not a header,
        # so we'll store it separately and add it to requests later
        if self.api_key:
            print("Using NVD API key for higher rate limits (50 req/30sec)")
        else:
            print("No API key provided. Using public rate limit (5 req/30sec)")
            print("Consider getting a free key at: https://nvd.nist.gov/developers/request-an-api-key")
    
    def _enforce_rate_limit(self):
        """
        Enforce rate limiting by waiting between requests if needed.
        
        The NVD API has strict rate limits:
        - Without API key: 5 requests per 30 seconds
        - With API key: 50 requests per 30 seconds
        
        If we exceed these limits, NVD will return a 403 Forbidden error
        and may temporarily ban our IP. This method ensures we stay compliant
        by tracking the time since our last request and sleeping if needed.
        """
        if self.last_request_time is not None:
            # Calculate how long it's been since our last request
            elapsed = time.time() - self.last_request_time
            
            # If we haven't waited long enough, sleep for the remaining time
            if elapsed < self.rate_limit_delay:
                sleep_time = self.rate_limit_delay - elapsed
                print(f"Rate limiting: waiting {sleep_time:.1f} seconds...")
                time.sleep(sleep_time)
        
        # Record this request time for next call
        self.last_request_time = time.time()
    
    def fetch_recent_cves(self, 
                         days_back: int = 30,
                         keywords: Optional[List[str]] = None,
                         max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch recent CVEs from the NVD, optionally filtered by keywords.
        
        This is the main entry point for fetching vulnerabilities. It queries
        the NVD API for CVEs published in the last N days, then filters them
        for relevance to public safety if keywords are provided.
        
        Args:
            days_back: How many days back to search (default 30).
                      The NVD publishes hundreds of CVEs per month, so 30 days
                      gives us a good sample without overwhelming the system.
            
            keywords: Optional list of keywords to filter CVEs.
                     If provided, only CVEs mentioning these keywords in their
                     description will be returned. If None, returns all CVEs
                     from the time period.
            
            max_results: Maximum number of CVEs to return (default 100).
                        The NVD API returns results in pages of up to 2000 items,
                        but we usually don't need that many for testing/demo purposes.
        
        Returns:
            List of vulnerability dictionaries with fields:
            - id: CVE ID (e.g., "CVE-2024-1234")
            - title: Short description
            - description: Full description of the vulnerability
            - published: Publication date as datetime object
            - severity: CVSS severity (Critical/High/Medium/Low)
            - score: CVSS base score (0.0-10.0)
            - affected_products: List of affected products/vendors
            - link: URL to full CVE details on NVD
            - months_old: How many months since publication
            - cwe_ids: List of CWE (Common Weakness Enumeration) IDs
        
        Raises:
            requests.RequestException: If the API request fails
            ValueError: If the API response can't be parsed
        """
        # ========================================
        # STEP 1: Calculate date range
        # ========================================
        # The NVD API uses ISO 8601 datetime format for date filtering
        # We need to specify a start and end date for our query
        
        # End date is now (we want CVEs up to this moment)
        end_date = datetime.now(timezone.utc)
        
        # Start date is N days ago
        start_date = end_date - timedelta(days=days_back)
        
        # Format dates as ISO 8601 strings (required by NVD API)
        # Example: "2024-01-15T00:00:00.000"
        start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        print(f"Fetching CVEs published between {start_str} and {end_str}")
        
        # ========================================
        # STEP 2: Build API request parameters
        # ========================================
        # The NVD API uses query parameters to filter results
        params = {
            # pubStartDate/pubEndDate: Filter by publication date range
            'pubStartDate': start_str,
            'pubEndDate': end_str,
            
            # resultsPerPage: How many results per page (max 2000)
            # We'll request 100 at a time to avoid overwhelming the API
            'resultsPerPage': min(max_results, 2000),
            
            # startIndex: Pagination offset (0-based)
            # For now we just get the first page, but we could add pagination later
            'startIndex': 0,
        }
        
        # If we have an API key, add it to parameters
        # The NVD API expects the key as a URL parameter, not a header
        if self.api_key:
            params['apiKey'] = self.api_key
        
        # ========================================
        # STEP 3: Make the API request
        # ========================================
        try:
            # Enforce rate limiting before making the request
            self._enforce_rate_limit()
            
            print(f"Querying NVD API...")
            response = requests.get(
                self.API_BASE_URL,
                params=params,
                headers=self.headers,
                timeout=30  # 30 second timeout
            )
            
            # Check for errors
            # The NVD API returns specific status codes:
            # 200 = Success
            # 403 = Rate limit exceeded or API key invalid
            # 404 = Invalid endpoint
            # 503 = Service temporarily unavailable
            response.raise_for_status()
            
            # Record when we successfully fetched
            self.last_fetch_time = datetime.now(timezone.utc)
            
            # ========================================
            # STEP 4: Parse the JSON response
            # ========================================
            # The NVD API returns JSON with this structure:
            # {
            #   "resultsPerPage": 100,
            #   "startIndex": 0,
            #   "totalResults": 523,
            #   "format": "NVD_CVE",
            #   "version": "2.0",
            #   "timestamp": "2024-01-15T10:30:00.000",
            #   "vulnerabilities": [
            #     { "cve": { ... actual CVE data ... } },
            #     { "cve": { ... } },
            #     ...
            #   ]
            # }
            
            data = response.json()
            
            # Extract the vulnerabilities array
            # Each item has a "cve" object containing the actual vulnerability data
            vulnerabilities = data.get('vulnerabilities', [])
            
            print(f"Retrieved {len(vulnerabilities)} CVEs from NVD")
            
            # ========================================
            # STEP 5: Parse and convert each CVE
            # ========================================
            cves = []
            for vuln_wrapper in vulnerabilities:
                try:
                    # Each vulnerability is wrapped in a { "cve": {...} } structure
                    # We extract the actual CVE data
                    cve_data = vuln_wrapper.get('cve', {})
                    
                    # Parse this CVE into our internal format
                    cve = self._parse_cve(cve_data)
                    cves.append(cve)
                    
                except Exception as e:
                    # If one CVE fails to parse, log it but continue with others
                    cve_id = vuln_wrapper.get('cve', {}).get('id', 'unknown')
                    print(f"Warning: Failed to parse CVE {cve_id}: {e}")
                    continue
            
            # ========================================
            # STEP 6: Filter by keywords if provided
            # ========================================
            if keywords:
                print(f"Filtering for keywords: {keywords}")
                cves = self._filter_by_keywords(cves, keywords)
                print(f"After filtering: {len(cves)} CVEs relevant to public safety")
            
            return cves
            
        except requests.RequestException as e:
            # Network or API errors
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 403:
                    print("Error: NVD API returned 403 Forbidden.")
                    print("This usually means you've exceeded the rate limit.")
                    print("Wait 30 seconds and try again, or get an API key for higher limits.")
                else:
                    print(f"Error: NVD API returned status {e.response.status_code}")
            else:
                print(f"Error connecting to NVD API: {e}")
            raise
        except Exception as e:
            print(f"Unexpected error querying NVD: {e}")
            raise
    
    def _parse_cve(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a single CVE from NVD format to our internal format.
        
        The NVD's JSON structure is complex and deeply nested. This method
        navigates that structure and extracts the fields we care about for
        threat intelligence and ECROSPK scoring.
        
        Args:
            cve_data: The "cve" object from NVD API response
        
        Returns:
            Dictionary with standardized vulnerability fields
        """
        # ========================================
        # Extract basic identification
        # ========================================
        # CVE ID: The unique identifier like "CVE-2024-1234"
        cve_id = cve_data.get('id', 'unknown')
        
        # ========================================
        # Extract descriptions
        # ========================================
        # CVEs have descriptions in multiple languages
        # We look for English descriptions first, fall back to first available
        descriptions = cve_data.get('descriptions', [])
        description = ''
        
        for desc in descriptions:
            # Each description has a language code and text
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        # If no English description found, use the first available
        if not description and descriptions:
            description = descriptions[0].get('value', '')
        
        # Use first sentence as title (or first 100 chars if no period)
        title = description.split('.')[0] if '.' in description else description[:100]
        
        # ========================================
        # Extract publication date
        # ========================================
        # CVEs have both 'published' and 'lastModified' dates
        # We use 'published' for our Recency factor
        published_str = cve_data.get('published', '')
        published = None
        
        if published_str:
            try:
                # NVD uses ISO 8601 format: "2024-01-15T10:30:00.000"
                published = date_parser.parse(published_str)
                # Ensure timezone info
                if published.tzinfo is None:
                    published = published.replace(tzinfo=timezone.utc)
            except Exception as e:
                print(f"Warning: Could not parse date '{published_str}': {e}")
                published = datetime.now(timezone.utc)
        else:
            # If no date, assume it's brand new
            published = datetime.now(timezone.utc)
        
        # Calculate age in months for ECROSPK Recency factor
        months_old = self._calculate_months_old(published)
        
        # ========================================
        # Extract CVSS severity and score
        # ========================================
        # CVEs can have multiple CVSS scores (v2.0, v3.0, v3.1)
        # We prefer CVSS v3.x as it's more current and accurate
        severity = 'Unknown'
        score = 0.0
        
        # The metrics object contains CVSS data
        metrics = cve_data.get('metrics', {})
        
        # Try CVSS v3.1 first (most current)
        if 'cvssMetricV31' in metrics:
            cvss_data = metrics['cvssMetricV31']
            if cvss_data:
                # cvssData contains the actual score and severity
                cvss = cvss_data[0].get('cvssData', {})
                severity = cvss.get('baseSeverity', 'Unknown')
                score = float(cvss.get('baseScore', 0.0))
        
        # Fall back to CVSS v3.0 if v3.1 not available
        elif 'cvssMetricV30' in metrics:
            cvss_data = metrics['cvssMetricV30']
            if cvss_data:
                cvss = cvss_data[0].get('cvssData', {})
                severity = cvss.get('baseSeverity', 'Unknown')
                score = float(cvss.get('baseScore', 0.0))
        
        # Last resort: CVSS v2.0 (older scoring system)
        elif 'cvssMetricV2' in metrics:
            cvss_data = metrics['cvssMetricV2']
            if cvss_data:
                cvss = cvss_data[0].get('cvssData', {})
                score = float(cvss.get('baseScore', 0.0))
                # CVSS v2 doesn't have severity labels, so we calculate it
                if score >= 7.0:
                    severity = 'HIGH'
                elif score >= 4.0:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
        
        # ========================================
        # Extract affected products
        # ========================================
        # The configurations tell us what products/versions are affected
        # This is deeply nested and complex, so we simplify it
        affected_products = []
        configurations = cve_data.get('configurations', [])
        
        for config in configurations:
            # Each configuration has nodes with CPE (Common Platform Enumeration) data
            nodes = config.get('nodes', [])
            for node in nodes:
                # CPE match criteria specify affected products
                cpe_matches = node.get('cpeMatch', [])
                for match in cpe_matches:
                    if match.get('vulnerable', True):
                        # Extract vendor and product from CPE URI
                        # CPE format: cpe:2.3:a:vendor:product:version:...
                        cpe = match.get('criteria', '')
                        if cpe:
                            parts = cpe.split(':')
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                affected_products.append(f"{vendor} {product}")
        
        # Remove duplicates and limit to first 10 for brevity
        affected_products = list(set(affected_products))[:10]
        
        # ========================================
        # Extract CWE IDs (weakness types)
        # ========================================
        # CWEs categorize the type of vulnerability (e.g., CWE-79 = XSS)
        cwe_ids = []
        weaknesses = cve_data.get('weaknesses', [])
        for weakness in weaknesses:
            descriptions = weakness.get('description', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    cwe_id = desc.get('value', '')
                    if cwe_id:
                        cwe_ids.append(cwe_id)
        
        # ========================================
        # Build NVD URL
        # ========================================
        # Each CVE has a detail page on the NVD website
        link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        
        # ========================================
        # Return standardized format
        # ========================================
        return {
            'id': cve_id,
            'title': title,
            'description': description,
            'published': published,
            'severity': severity,
            'score': score,
            'affected_products': affected_products,
            'link': link,
            'months_old': months_old,
            'cwe_ids': cwe_ids,
            # Store source for tracking
            'source': 'NVD',
            'fetched_at': self.last_fetch_time
        }
    
    def _calculate_months_old(self, published_date: datetime) -> float:
        """
        Calculate how many months old a CVE is.
        
        Same logic as the CISA ingester - used for ECROSPK Recency factor.
        
        Args:
            published_date: When the CVE was published
        
        Returns:
            Age in months as a float
        """
        now = datetime.now(timezone.utc)
        time_delta = now - published_date
        months = time_delta.days / 30.44  # Average month length
        return round(months, 2)
    
    def _filter_by_keywords(self, 
                           cves: List[Dict[str, Any]], 
                           keywords: List[str]) -> List[Dict[str, Any]]:
        """
        Filter CVEs to only those mentioning specified keywords.
        
        This is similar to the public safety filter in the CISA ingester,
        but works with CVE descriptions instead of advisory summaries.
        
        Args:
            cves: List of CVE dictionaries to filter
            keywords: List of keywords to search for (case-insensitive)
        
        Returns:
            Filtered list containing only relevant CVEs
        """
        # Convert keywords to lowercase for case-insensitive matching
        keywords = [k.lower() for k in keywords]
        
        relevant = []
        for cve in cves:
            # Combine description and affected products into searchable text
            searchable_text = (
                cve.get('description', '') + ' ' +
                ' '.join(cve.get('affected_products', []))
            ).lower()
            
            # Check if any keyword appears in the text
            if any(keyword in searchable_text for keyword in keywords):
                relevant.append(cve)
        
        return relevant


# ========================================
# Convenience function for quick testing
# ========================================
def fetch_public_safety_cves(days_back: int = 30, max_results: int = 100) -> List[Dict[str, Any]]:
    """
    Quick function to fetch recent CVEs relevant to public safety.
    
    This combines fetching and filtering in one step, using the same
    public safety keywords we used for CISA advisories.
    
    Args:
        days_back: How many days back to search
        max_results: Maximum CVEs to return
    
    Returns:
        List of relevant CVEs
    """
    # Define public safety keywords
    keywords = [
        # Emergency services
        'emergency', '911', 'e911', 'ng911',
        'ambulance', 'ems', 'fire', 'police',
        # Communication systems
        'radio', 'p25', 'tetra', 'dmr', 'apco',
        'dispatch', 'cad', 'motorola',
        # Public safety infrastructure
        'public safety', 'first responder', 'psap',
        'alert', 'warning', 'notification', 'siren'
    ]
    
    ingester = NVDAPIIngester()
    cves = ingester.fetch_recent_cves(
        days_back=days_back,
        keywords=keywords,
        max_results=max_results
    )
    
    return cves


if __name__ == "__main__":
    # ========================================
    # Test code - runs when you execute this file directly
    # ========================================
    print("Testing NVD API ingester...")
    print("=" * 60)
    
    try:
        # Fetch CVEs from last 60 days (gives us more results)
        # Filter for public safety relevance
        print("Fetching public safety-relevant CVEs from last 60 days...\n")
        cves = fetch_public_safety_cves(days_back=60, max_results=50)
        
        # Display results
        print(f"\nFound {len(cves)} public safety-relevant CVEs:\n")
        print("=" * 60)
        
        for cve in cves[:10]:  # Show first 10 for readability
            print(f"\nID: {cve['id']}")
            print(f"Severity: {cve['severity']} (Score: {cve['score']})")
            print(f"Age: {cve['months_old']} months")
            print(f"Description: {cve['description'][:150]}...")
            if cve['affected_products']:
                print(f"Affects: {', '.join(cve['affected_products'][:3])}")
            print(f"Link: {cve['link']}")
            print("-" * 60)
        
        if len(cves) > 10:
            print(f"\n... and {len(cves) - 10} more CVEs")
        
    except Exception as e:
        print(f"\nTest failed with error: {e}")
        import traceback
        traceback.print_exc()
