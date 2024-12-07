import os
import subprocess
import requests
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor
import time

# Version of the script
__version__ = "1.1.0"

# Constants for retry logic
MAX_RETRIES = 3
BACKOFF_FACTOR = 2
HTTPX_PATH = os.path.expanduser("~/go/bin/httpx")


class Dominator:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.live_domains = set()

    def run_command(self, command):
        """Run a system command safely without shell=True."""
        try:
            logging.info(f"Running command: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True)
            result.check_returncode()
            return result.stdout.strip().split("\n")
        except subprocess.CalledProcessError as e:
            logging.error(f"Command '{' '.join(command)}' failed with error: {e}")
            return []

    def run_tool_with_retries(self, command, tool_name):
        """Run a command with retries and exponential backoff."""
        for attempt in range(MAX_RETRIES):
            logging.info(f"Attempting to run {tool_name} (Attempt {attempt + 1}/{MAX_RETRIES})")
            result = self.run_command(command)
            if result:  # If subdomains are returned
                return result
            wait_time = BACKOFF_FACTOR ** attempt
            logging.warning(f"{tool_name} failed. Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
        logging.error(f"{tool_name} failed after {MAX_RETRIES} retries.")
        return []

    def find_subdomains(self):
        """Discover subdomains using Subfinder, Assetfinder, and Findomain."""
        tools = [
            ("subfinder", ["subfinder", "-d", self.domain, "-silent"]),
            ("assetfinder", ["assetfinder", "--subs-only", self.domain]),
            ("findomain", ["findomain", "-t", self.domain, "-q"])
        ]

        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda x: self.run_tool_with_retries(x[1], x[0]), tools)
            for result in results:
                self.subdomains.update(result)

        logging.info(f"Total subdomains discovered: {len(self.subdomains)}")
        return self.subdomains

    def query_crtsh(self):
        """Query crt.sh for subdomains."""
        logging.info(f"Querying crt.sh for {self.domain}...")
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        retries = MAX_RETRIES

        for attempt in range(retries):
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = response.json()
                for entry in data:
                    subdomain = entry['name_value']
                    self.subdomains.update(subdomain.split('\n'))
                logging.info(f"crt.sh returned {len(self.subdomains)} subdomains.")
                return self.subdomains
            except requests.RequestException as e:
                if attempt < retries - 1:
                    wait_time = BACKOFF_FACTOR ** attempt
                    logging.warning(f"Request to crt.sh failed: {e}. Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    logging.error(f"Failed to query crt.sh after {retries} attempts: {e}")
        return set()

    def check_live_domains(self):
        """Check which subdomains are live using httpx."""
        logging.info(f"Running httpx to check live subdomains...")

        subdomain_input = "\n".join(self.subdomains)
        try:
            result = subprocess.run(
                [HTTPX_PATH, "-silent"],
                input=subdomain_input,
                capture_output=True,
                text=True
            )
            result.check_returncode()
            self.live_domains.update(result.stdout.splitlines())
        except subprocess.CalledProcessError as e:
            logging.error(f"httpx failed with error: {e}")
        
        logging.info(f"Total live domains found: {len(self.live_domains)}")
        return self.live_domains

    def save_live_domains(self):
        """Save the live domains to a text file."""
        output_file = f"{self.domain}_live_domains.txt"
        with open(output_file, "w") as f:
            for live_domain in sorted(self.live_domains):
                f.write(live_domain + "\n")
        logging.info(f"Live domains saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Dominator: A Bug Bounty Content Discovery Tool")
    parser.add_argument("-d", "--domain", required=True, help="The target domain")
    parser.add_argument("--version", action='version', version=f"Dominator v{__version__}")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    domain = args.domain
    dominator = Dominator(domain)

    dominator.find_subdomains()
    dominator.query_crtsh()
    dominator.check_live_domains()
    dominator.save_live_domains()


if __name__ == "__main__":
    main()
