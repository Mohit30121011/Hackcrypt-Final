import asyncio
from urllib.parse import urlparse, urljoin
from typing import Set, List
from playwright.async_api import async_playwright

class Spider:
    def __init__(self, start_url: str, max_pages: int = 10):
        self.start_url = start_url
        self.visited_urls: Set[str] = set()
        self.found_links: Set[str] = set()
        self.found_links.add(start_url)
        self.max_pages = max_pages
        self.domain = urlparse(start_url).netloc
        
    def _is_internal(self, url: str) -> bool:
        netloc = urlparse(url).netloc
        # Handle localhost/127.0.0.1 mismatch
        if "localhost" in self.domain and "127.0.0.1" in netloc: return True
        if "127.0.0.1" in self.domain and "localhost" in netloc: return True
        return netloc == self.domain

    async def crawl(self, session_ignored=None) -> List[str]:
        """
        Dynamic Crawling using Playwright (Headless Chromium).
        Executes JavaScript to find links in SPAs (React/Vue/Angular).
        """
        print(f"[*] Starting Dynamic Crawl (Playwright) on {self.start_url}")
        
        async with async_playwright() as p:
            # Launch browser (Headless)
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Scancrypt/2.0 (Dynamic)"
            )
            
            # If session is provided and has cookies, we could technically sync them here.
            # For now, we proceed as a fresh browser session.
            
            page = await context.new_page()
            queue = [self.start_url]
            
            while queue and len(self.visited_urls) < self.max_pages:
                url = queue.pop(0)
                if url in self.visited_urls:
                    continue
                
                print(f"[*] Visiting (Dynamic): {url}")
                try:
                    # Navigate and Wait for Network Idle (critical for SPAs)
                    # 'domcontentloaded' is faster, 'networkidle' is safer for heavy SPAs
                    await page.goto(url, timeout=15000, wait_until="networkidle")
                    self.visited_urls.add(url)
    async def crawl(self, session_ignored=None):
        """
        Main crawl method.
        Tries Dynamic (Playwright) first.
        If it fails (e.g., browsers not installed on Render), falls back to Static (BS4).
        """
        print(f"[*] Starting Crawl on {self.base_url}")
        
        # Try Dynamic Crawl
        try:
            print("[*] Attempting Dynamic Crawl (Playwright)...")
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Scancrypt/2.0 (Dynamic)"
                )
                page = await context.new_page()
                
                # ... (Existing Playwright Logic adapted) ...
                queue = [self.base_url]
                
                while queue and len(self.visited_urls) < self.max_pages:
                    url = queue.pop(0)
                    if url in self.visited_urls:
                        continue
                    
                    print(f"[*] Visiting (Dynamic): {url}")
                    try:
                        await page.goto(url, timeout=15000, wait_until="networkidle")
                        self.visited_urls.add(url)
                        
                        # Extract Links from DOM using JS evaluation
                        # This finds <a href="..."> tags created by JS
                        links = await page.evaluate("""
                            () => Array.from(document.querySelectorAll('a')).map(a => a.href)
                        """)
                        print(f"[*] Extracted {len(links)} raw links from {url}")
                        
                        for full_url in links:
                            # Normalize
                            parsed = urlparse(full_url)
                            if not parsed.scheme or not parsed.netloc: continue
                            
                            clean_url = parsed.scheme + "://" + parsed.netloc + parsed.path
                            if parsed.query: clean_url += "?" + parsed.query
                            
                            if self._is_internal(clean_url):
                                 if clean_url not in self.visited_urls and clean_url not in queue:
                                     queue.append(clean_url)
                            else:
                                 pass # print(f"Skipping external: {clean_url}")
                                     
                    except Exception as e:
                        print(f"[!] Error crawling {url}: {e}")
                
                # Check for login form (example, can be integrated into loop or after initial load)
                if await page.query_selector("input[type='password']"):
                    print("[!] Login form detected!")
                
                await browser.close()
                print(f"[*] Dynamic Crawl Success. Found {len(self.visited_urls)} URLs.")
                return list(self.visited_urls)

        except Exception as e:
            print(f"[!] Dynamic Crawl Failed: {e}")
            print("[*] Falling back to Static Crawl (BeautifulSoup)...")
            return await self.crawl_static()

    async def crawl_static(self):
        """Fallback static crawler using aiohttp + BeautifulSoup"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.base_url, timeout=10, ssl=False) as response:
                    if response.status == 200:
                        html = await response.text()
                        await self._extract_links(html)
                        print(f"[*] Static Crawl Success. Found {len(self.visited_urls)} URLs.")
                    else:
                        print(f"[!] Static Crawl Failed: HTTP {response.status}")
        except Exception as e:
            print(f"[!] Static Crawl Error: {e}")
        
        return list(self.visited_urls)

    async def _extract_links(self, html_content):
        """Helper to extract links from HTML string"""
        soup = BeautifulSoup(html_content, "html.parser")
        
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            full_url = urljoin(self.base_url, href)
            
            parsed_base = urlparse(self.base_url)
            parsed_url = urlparse(full_url)
            
            if parsed_url.netloc == parsed_base.netloc:
                self.visited_urls.add(full_url)

```
