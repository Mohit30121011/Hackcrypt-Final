import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class Authenticator:
    def __init__(self):
        pass

    async def login(self, login_url: str, username: str, password: str) -> aiohttp.ClientSession:
        """
        Attempts to log in to the application and returns an authenticated aiohttp session.
        """
        print(f"[*] Attempting login at {login_url} as {username}")
        
        # Create a session that will hold the cookies
        session = aiohttp.ClientSession()
        
        try:
            # 1. GET the login page to get CSRF tokens and cookies
            async with session.get(login_url) as resp:
                text = await resp.text()
                soup = BeautifulSoup(text, 'html.parser')

                # 2. Find the login form
                # Heuristic: Find first form with a password field
                password_input = soup.find('input', {'type': 'password'})
                if not password_input:
                    print("[!] No password field found on login page.")
                    return session

                form = password_input.find_parent('form')
                if not form:
                    print("[!] Password field is not inside a form.")
                    return session

                # 3. Extract Form Destination (Action)
                action = form.get('action')
                post_url = urljoin(login_url, action) if action else login_url

                # 4. Extract All Inputs (including hidden CSRF tokens)
                data = {}
                for input_tag in form.find_all('input'):
                    name = input_tag.get('name')
                    value = input_tag.get('value', '')
                    if not name: continue
                    
                    if input_tag.get('type') == 'password':
                        data[name] = password
                    elif name.lower() in ['user', 'username', 'email', 'login']:
                        data[name] = username
                    else:
                        # Keep existing values (e.g. CSRF token)
                        data[name] = value
                
                print(f"[*] Found login form. Posting to {post_url} with data keys: {list(data.keys())}")

            # 5. POST the credentials
            async with session.post(post_url, data=data) as post_resp:
                print(f"[*] Login POST status: {post_resp.status}")
                # We assume success if we get a redirect (3xx) or a 200 OK.
                # Ideally, we should check for "logout" in the response, but for now we rely on cookies being set.
                if post_resp.cookies:
                    print(f"[*] Session cookies captured: {len(post_resp.cookies)}")
                else:
                    print("[!] Warning: No cookies received after login.")
                    
        except Exception as e:
            print(f"[!] Login failed: {e}")
            # Don't close session here, we might want to return it even if failed (partial state)
            # But usually we should handle it.
        
        return session
