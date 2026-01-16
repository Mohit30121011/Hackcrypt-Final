import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Set, List

class Spider:
    def __init__(self, start_url: str, max_pages: int = 10):
        self.start_url = start_url
        self.visited_urls: Set[str] = set()
        self.found_links: Set[str] = set()
        # Initialize found links with start URL to ensure it's in the list
        self.found_links.add(start_url)
        self.max_pages = max_pages
        self.domain = urlparse(start_url).netloc
        
    def _is_internal(self, url: str) -> bool:
        return urlparse(url).netloc == self.domain

    async def crawl(self, session: aiohttp.ClientSession) -> List[str]:
        print(f"[*] Starting crawl on {self.start_url}")
        queue = [self.start_url]
        
        while queue and len(self.visited_urls) < self.max_pages:
            url = queue.pop(0)
            if url in self.visited_urls:
                continue
            
            print(f"[*] Visiting: {url}")
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Scancrypt/1.0'}
                
                # Use shared session
                async with session.get(url, headers=headers, timeout=10) as response:
                    self.visited_urls.add(url)
                    
                    if response.status == 200:
                        text = await response.text()
                        soup = BeautifulSoup(text, 'html.parser')
                        for a_tag in soup.find_all('a', href=True):
                            href = a_tag['href']
                            full_url = urljoin(url, href)
                            parsed = urlparse(full_url)
                            
                            # Clean fragments
                            # Reconstruct URL without fragment
                            clean_url = parsed.scheme + "://" + parsed.netloc + parsed.path
                            if parsed.query:
                                clean_url += "?" + parsed.query
                                
                            if self._is_internal(clean_url):
                                if clean_url not in self.visited_urls and clean_url not in queue:
                                    queue.append(clean_url)
                                self.found_links.add(clean_url)
            except Exception as e:
                print(f"[!] Error crawling {url}: {e}")
                
        print(f"[*] Crawl finished. Found {len(self.found_links)} internal URLs.")
        return list(self.found_links)

