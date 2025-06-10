import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""
        self.features = []

        # Initialize URL parsing, WHOIS, and HTTP response
        self._initialize()

        # Extract features
        self._extract_features()

    def _initialize(self):
        """Initialize URL parsing, WHOIS, and HTTP response."""
        try:
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc
        except Exception as e:
            print(f"Error parsing URL: {e}")

        try:
            self.response = requests.get(self.url, timeout=10)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except Exception as e:
            print(f"Error fetching URL content: {e}")

        try:
            self.whois_response = whois.whois(self.domain)
        except Exception as e:
            print(f"Error fetching WHOIS data: {e}")

    def _extract_features(self):
        """Extract all features and store them in the features list."""
        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # Feature Extraction Methods (as shown above)



    # Feature Extraction Methods
    def UsingIp(self):
        """Check if the URL uses an IP address."""
        try:
            ipaddress.ip_address(self.url)
            return -1
        except ValueError:
            return 1

    def longUrl(self):
        """Check if the URL is long."""
        url_length = len(self.url)
        if url_length < 54:
            return 1
        elif 54 <= url_length <= 75:
            return 0
        return -1

    def shortUrl(self):
        """Check if the URL is a shortened URL."""
        shorteners = [
            r'bit\.ly', r'goo\.gl', r'short\.st', r'go2l\.ink', r'x\.co', r'ow\.ly', r't\.co', r'tinyurl',
            r'tr\.im', r'is\.gd', r'cli\.gs', r'yfrog\.com', r'migre\.me', r'ff\.im', r'tiny\.cc', r'url4\.eu',
            r'twit\.ac', r'su\.pr', r'twurl\.nl', r'snipurl\.com', r'short\.to', r'BudURL\.com', r'ping\.fm',
            r'post\.ly', r'Just\.as', r'bkite\.com', r'snipr\.com', r'fic\.kr', r'loopt\.us', r'doiop\.com',
            r'short\.ie', r'kl\.am', r'wp\.me', r'rubyurl\.com', r'om\.ly', r'to\.ly', r'bit\.do', r't\.co',
            r'lnkd\.in', r'db\.tt', r'qr\.ae', r'adf\.ly', r'goo\.gl', r'bitly\.com', r'cur\.lv', r'tinyurl\.com',
            r'ow\.ly', r'bit\.ly', r'ity\.im', r'q\.gs', r'is\.gd', r'po\.st', r'bc\.vc', r'twitthis\.com',
            r'u\.to', r'j\.mp', r'buzurl\.com', r'cutt\.us', r'u\.bb', r'yourls\.org', r'x\.co', r'prettylinkpro\.com',
            r'scrnch\.me', r'filoops\.info', r'vzturl\.com', r'qr\.net', r'1url\.com', r'tweez\.me', r'v\.gd', r'tr\.im',
            r'link\.zip\.net']
        if re.search('|'.join(shorteners), self.url):
            return -1
        return 1

    def symbol(self):
        """Check for '@' symbol in the URL."""
        if re.findall("@", self.url):
            return -1
        return 1

    def redirecting(self):
        """Check for redirects in the URL."""
        if self.url.rfind('//') > 6:
            return -1
        return 1

    def prefixSuffix(self):
        """Check for hyphens in the domain."""
        try:
            if re.findall(r'\-', self.domain):
                return -1
            return 1
        except:
            return -1

    def SubDomains(self):
        """Count the number of subdomains."""
        dot_count = len(re.findall(r"\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    def Hppts(self):
        """Check if the URL uses HTTPS."""
        try:
            if self.urlparse.scheme == 'https':
                return 1
            return -1
        except:
            return 1

    def DomainRegLen(self):
        """Check the domain registration length."""
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            if age >= 12:
                return 1
            return -1
        except:
            return -1

    def Favicon(self):
        """Check if the favicon is from the same domain."""
        try:
            for head in self.soup.find_all('head'):
                for link in head.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer(r'\.', link['href'])]
                    if self.url in link['href'] or len(dots) == 1 or self.domain in link['href']:
                        return 1
            return -1
        except:
            return -1

    def NonStdPort(self):
        """Check if the URL uses a non-standard port."""
        try:
            port = self.domain.split(":")
            if len(port) > 1:
                return -1
            return 1
        except:
            return -1

    def HTTPSDomainURL(self):
        """Check if the domain contains 'https'."""
        try:
            if 'https' in self.domain:
                return -1
            return 1
        except:
            return -1

    def RequestURL(self):
        """Check the percentage of external resources."""
        try:
            total, success = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for element in self.soup.find_all(tag, src=True):
                    dots = [x.start(0) for x in re.finditer(r'\.', element['src'])]
                    if self.url in element['src'] or self.domain in element['src'] or len(dots) == 1:
                        success += 1
                    total += 1

            if total == 0:
                return 1
            percentage = (success / total) * 100
            if percentage < 22.0:
                return 1
            elif 22.0 <= percentage < 61.0:
                return 0
            return -1
        except:
            return -1

    def AnchorURL(self):
        """Check the percentage of unsafe anchor URLs."""
        try:
            total, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe += 1
                total += 1

            if total == 0:
                return 1
            percentage = (unsafe / total) * 100
            if percentage < 31.0:
                return 1
            elif 31.0 <= percentage < 67.0:
                return 0
            return -1
        except:
            return -1

    def LinksInScriptTags(self):
        """Check the percentage of external links in script tags."""
        try:
            total, success = 0, 0
            for tag in ['link', 'script']:
                for element in self.soup.find_all(tag, src=True):
                    dots = [x.start(0) for x in re.finditer(r'\.', element['src'])]
                    if self.url in element['src'] or self.domain in element['src'] or len(dots) == 1:
                        success += 1
                    total += 1

            if total == 0:
                return 1
            percentage = (success / total) * 100
            if percentage < 17.0:
                return 1
            elif 17.0 <= percentage < 81.0:
                return 0
            return -1
        except:
            return -1

    def ServerFormHandler(self):
        """Check if the form action is suspicious."""
        try:
            forms = self.soup.find_all('form', action=True)
            if not forms:
                return 1
            for form in forms:
                if not form['action'] or form['action'] == "about:blank":
                    return -1
                elif self.url not in form['action'] and self.domain not in form['action']:
                    return 0
            return 1
        except:
            return -1

    def InfoEmail(self):
        """Check if the page contains email addresses."""
        try:
            if re.findall(r"[mail\(\)|mailto:?]", self.soup.text):
                return -1
            return 1
        except:
            return -1

    def AbnormalURL(self):
        """Check if the URL content matches the WHOIS info."""
        try:
            if self.response.text == self.whois_response.text:
                return 1
            return -1
        except:
            return -1

    def WebsiteForwarding(self):
        """Check the number of redirects."""
        try:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            return -1
        except:
            return -1

    def StatusBarCust(self):
        """Check for custom status bar scripts."""
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return 1
            return -1
        except:
            return -1

    def DisableRightClick(self):
        """Check if right-click is disabled."""
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return 1
            return -1
        except:
            return -1

    def UsingPopupWindow(self):
        """Check for popup windows."""
        try:
            if re.findall(r"alert\(", self.response.text):
                return 1
            return -1
        except:
            return -1

    def IframeRedirection(self):
        """Check for iframe redirections."""
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                return 1
            return -1
        except:
            return -1

    def _get_domain_age(self):
        """Helper method to calculate domain age."""
        try:
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            return age
        except:
            return None

    def AgeofDomain(self):
        """Check the age of the domain."""
        age = self._get_domain_age()
        if age is not None and age >= 6:
            return 1
        return -1

    def DNSRecording(self):
        """Check the DNS record age."""
        age = self._get_domain_age()
        if age is not None and age >= 6:
            return 1
        return -1

    import requests
    from bs4 import BeautifulSoup

    def WebsiteTraffic(url):
        """Check the website's traffic rank using SimilarWeb's free data."""
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            response = requests.get(f"https://www.similarweb.com/website/{url}", headers=headers)
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Extract global rank (example selector, may need to update)
            rank_element = soup.find("div", {"class": "wa-rank-list__value"})
            if rank_element:
                rank = int(rank_element.text.strip().replace(",", ""))
                if rank < 100000:
                    return 1
                return 0
            return -1
        except Exception as e:
            print(f"Error: {e}")
            return -1


    def PageRank(self):
        """Check the website's PageRank."""
        try:
            prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
            global_rank = int(re.findall(r"Global Rank: ([0-9]+)", prank_checker_response.text)[0])
            if 0 < global_rank < 100000:
                return 1
            return -1
        except:
            return -1

    def GoogleIndex(self):
        """Check if the site is indexed by Google."""
        try:
            site = search(self.url, num=5, stop=5, pause=2)
            if site:
                return 1
            return -1
        except:
            return 1

    def LinksPointingToPage(self):
        """Check the number of links pointing to the page."""
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            return -1
        except:
            return -1

    def StatsReport(self):
        """Check for suspicious IP addresses or domains."""
        try:
            suspicious_domains = [
                r'at\.ua', r'usa\.cc', r'baltazarpresentes\.com\.br', r'pe\.hu', r'esy\.es', r'hol\.es', r'sweddy\.com',
                r'myjino\.ru', r'96\.lt', r'ow\.ly'
            ]
            suspicious_ips = [
                r'146\.112\.61\.108', r'213\.174\.157\.151', r'121\.50\.168\.88', r'192\.185\.217\.116', r'78\.46\.211\.158',
                r'181\.174\.165\.13', r'46\.242\.145\.103', r'121\.50\.168\.40', r'83\.125\.22\.219', r'46\.242\.145\.98',
                r'107\.151\.148\.44', r'107\.151\.148\.107', r'64\.70\.19\.203', r'199\.184\.144\.27', r'107\.151\.148\.108',
                r'107\.151\.148\.109', r'119\.28\.52\.61', r'54\.83\.43\.69', r'52\.69\.166\.231', r'216\.58\.192\.225',
                r'118\.184\.25\.86', r'67\.208\.74\.71', r'23\.253\.126\.58', r'104\.239\.157\.210', r'175\.126\.123\.219',
                r'141\.8\.224\.221', r'10\.10\.10\.10', r'43\.229\.108\.32', r'103\.232\.215\.140', r'69\.172\.201\.153',
                r'216\.218\.185\.162', r'54\.225\.104\.146', r'103\.243\.24\.98', r'199\.59\.243\.120', r'31\.170\.160\.61',
                r'213\.19\.128\.77', r'62\.113\.226\.131', r'208\.100\.26\.234', r'195\.16\.127\.102', r'195\.16\.127\.157',
                r'34\.196\.13\.28', r'103\.224\.212\.222', r'172\.217\.4\.225', r'54\.72\.9\.51', r'192\.64\.147\.141',
                r'198\.200\.56\.183', r'23\.253\.164\.103', r'52\.48\.191\.26', r'52\.214\.197\.72', r'87\.98\.255\.18',
                r'209\.99\.17\.27', r'216\.38\.62\.18', r'104\.130\.124\.96', r'47\.89\.58\.141', r'78\.46\.211\.158',
                r'54\.86\.225\.156', r'54\.82\.156\.19', r'37\.157\.192\.102', r'204\.11\.56\.48', r'110\.34\.231\.42'
            ]

            # Check for suspicious domains
            if re.search('|'.join(suspicious_domains), self.domain):
                return -1

            # Check for suspicious IP addresses
            ip_address = socket.gethostbyname(self.domain)
            if re.search('|'.join(suspicious_ips), ip_address):
                return -1

            return 1
        except:
            return 1
    
    def getFeaturesList(self):
        """Return the list of extracted features."""
        return self.features
