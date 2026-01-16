import asyncio
from urllib.parse import urlparse, urljoin
from typing import Set, List
import aiohttp
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

class Spider:
    def __init__(self, start_url: str, max_pages: int = 10):
        self.start_url = start_url
        self.base_url = start_url
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
                # Create context with custom UA
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Scancrypt/2.0 (Dynamic)"
                )
                page = await context.new_page()
                
                queue = [self.base_url]
                self.visited_urls.add(self.base_url) # Start with base
                
                while queue and len(self.visited_urls) < self.max_pages:
                    url = queue.pop(0)
                    
                    print(f"[*] Visiting (Dynamic): {url}")
                    try:
                        await page.goto(url, timeout=15000, wait_until="networkidle")
                        
                        # Extract Links
                        links = await page.evaluate("""
                            () => Array.from(document.querySelectorAll('a')).map(a => a.href)
                        """)
                        
                        for full_url in links:
                            parsed = urlparse(full_url)
                            if not parsed.scheme or not parsed.netloc: continue
                            
                            clean_url = parsed.scheme + "://" + parsed.netloc + parsed.path
                            if parsed.query: clean_url += "?" + parsed.query
                            
                            if self._is_internal(clean_url):
                                 if clean_url not in self.visited_urls and clean_url not in queue:
                                     self.visited_urls.add(clean_url)
                                     queue.append(clean_url)
                                     
                    except Exception as e:
                        print(f"[!] Error crawling {url}: {e}")
                
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
                        soup = BeautifulSoup(html, "html.parser")
                        self.visited_urls.add(self.base_url)
                        
                        for a_tag in soup.find_all("a", href=True):
                            href = a_tag["href"]
                            full_url = urljoin(self.base_url, href)
                            
                            if self._is_internal(full_url):
                                self.visited_urls.add(full_url)
                                
                        print(f"[*] Static Crawl Success. Found {len(self.visited_urls)} URLs.")
                    else:
                        print(f"[!] Static Crawl Failed: HTTP {response.status}")
        except Exception as e:
            import traceback
            print(f"[!] Static Crawl Error: {e}\n{traceback.format_exc()}")
        
        return list(self.visited_urls)
