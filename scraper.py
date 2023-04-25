"""Extract scam URLs found at https://www.globalantiscam.org/scam-websites
and write them to a .txt blocklist
"""
import ipaddress
import itertools
import json
import logging
import re
import socket
from datetime import datetime

import requests
import tldextract
from selenium.common.exceptions import TimeoutException
from selenium.webdriver import Chrome
from selenium.webdriver.chrome.options import Options

logger = logging.getLogger()
logging.basicConfig(level=logging.INFO, format="%(message)s")


def current_datetime_str() -> str:
    """Current time's datetime string in UTC

    Returns:
        str: Timestamp in strftime format "%d_%b_%Y_%H_%M_%S-UTC".
    """
    return datetime.utcnow().strftime("%d_%b_%Y_%H_%M_%S-UTC")


def clean_url(url: str) -> str:
    """Remove zero width spaces, leading/trailing whitespaces, trailing slashes,
    and URL prefixes from a URL

    Args:
        url (str): URL.

    Returns:
        str: URL without zero width spaces, leading/trailing whitespaces, trailing slashes,
    and URL prefixes.
    """
    removed_zero_width_spaces = re.sub(r"[\u200B-\u200D\uFEFF]", "", url)
    removed_leading_and_trailing_whitespaces = removed_zero_width_spaces.strip()
    removed_trailing_slashes = removed_leading_and_trailing_whitespaces.rstrip("/")
    removed_https = re.sub(r"^[Hh][Tt][Tt][Pp][Ss]:\/\/", "", removed_trailing_slashes)
    removed_http = re.sub(r"^[Hh][Tt][Tt][Pp]:\/\/", "", removed_https)

    return removed_http


def get_sv_session() -> str | None:
    """Retrieve `svSession` session token from globalantiscam.org

    Returns:
        str | None: `svSession` session token if it exists, otherwise None.
    """
    options = Options()
    options.add_argument("--headless")
    browser = Chrome(options=options)

    try:
        browser.get("https://www.globalantiscam.org/scam-websites")
    except TimeoutException:
        return None

    cookie = browser.get_cookie("svSession")
    if cookie:
        return str(cookie["value"])
    return None


def get_page(svSession: str, offset: int = 0) -> requests.Response:
    """Retrieve data from globalantiscam.org Scam URL API
    from a given datapoint index `offset`

    Args:
        svSession (str): To authenticate the API call.
        offset (int, optional): Datapoint index to start from. This is necessary
        because of a server-side enforced maximum page size limit. Defaults to 0.

    Returns:
        requests.Response: API response data
    """
    endpoint = (
        "https://www.globalantiscam.org/_api/cloud-data/v1/wix-data/collections/query"
    )
    data = {
        "collectionName": "scamcompanies",
        "dataQuery": {
            "sort": [{"fieldName": "url", "order": "ASC"}],
            "paging": {"offset": offset, "limit": 1000},
        }
    }
    cookies = {"svSession": svSession}
    return requests.post(
        endpoint, json.dumps(data), cookies=cookies, timeout=30
    )


def retrieve_dataset(
    svSession: str, first_page_response: requests.Response
) -> list[dict]:
    """Retrieve all data from globalantiscam.org Scam URL API

    Args:
        svSession (str): To authenticate the API call.
        first_page_response (requests.Response): API data response from first page.

    Returns:
        list[dict]: List of all API responses as JSON.
    """
    first_page_body = first_page_response.json()

    # From the first page body, determine number of pages to fetch
    # (Each page has a maximum size of `page_limit`)
    page_limit = 1000  # limit enforced by server-side
    if "totalResults" in first_page_body:
        total_results = first_page_body["totalResults"]
        num_offsets = total_results // page_limit

    bodies: list[dict] = [first_page_body]
    for offset in range(1, num_offsets + 1):
        response = get_page(svSession, offset=offset * page_limit)
        if response.status_code == 200:
            body = response.json()
        bodies.append(body)
    return bodies


def extract_scam_urls() -> set[str]:
    """Extract scam URLs found at www.globalantiscam.org

    Returns:
        set[str]: Unique scam URLs.
    """
    try:
        svSession = get_sv_session()
        if not svSession:
            raise OSError("svSession token not available")

        first_page_response = get_page(svSession, offset=0)
        if first_page_response.status_code != 200:
            logger.error("Page status code: %d", first_page_response.status_code)
            raise OSError("Unable to retrieve first page")

        bodies = retrieve_dataset(svSession, first_page_response)

        # Manual cleaning
        all_items = list(
            itertools.chain.from_iterable(
                body["items"] for body in bodies if "items" in body
            )
        )
        raw_urls = [x["url"].strip(" \t\v\n\r\f.") for x in all_items if "url" in x]
        lines = (re.sub("\\s+", " ", line) for line in raw_urls)
        urls = set(
            y
            for x in itertools.chain.from_iterable(line.split(" ") for line in lines)
            if (y := clean_url(x.strip(" \t\v\n\r\f."))) and y != "www"
        )

        return urls
    except Exception as error:
        logger.error(error)
        return set()


if __name__ == "__main__":
    urls: set[str] = extract_scam_urls()
    ips: set[str] = set()
    non_ips: set[str] = set()
    fqdns: set[str] = set()
    if urls:
        for url in urls:
            res = tldextract.extract(url)
            domain, fqdn = res.domain, res.fqdn
            if domain and not fqdn:
                # Possible IPv4 Address
                try:
                    socket.inet_aton(domain)
                    ips.add(domain)
                except socket.error:
                    # Is invalid URL and invalid IP -> skip
                    pass
            elif fqdn:
                non_ips.add(url)
                fqdns.add(fqdn)

    if not non_ips and not ips:
        logger.error("No content available for blocklists.")
    else:
        non_ips_timestamp: str = current_datetime_str()
        non_ips_filename = "global-anti-scam-org-scam-urls.txt"
        with open(non_ips_filename, "w") as f:
            f.writelines("\n".join(sorted(non_ips)))
            logger.info(
                "%d non-IPs written to %s at %s",
                len(non_ips),
                non_ips_filename,
                non_ips_timestamp,
            )

        ips_timestamp: str = current_datetime_str()
        ips_filename = "global-anti-scam-org-scam-ips.txt"
        with open(ips_filename, "w") as f:
            f.writelines("\n".join(sorted(ips, key=ipaddress.IPv4Address)))
            logger.info(
                "%d IPs written to %s at %s", len(ips), ips_filename, ips_timestamp
            )

        fqdns_timestamp: str = current_datetime_str()
        fqdns_filename = "global-anti-scam-org-scam-urls-pihole.txt"
        with open(fqdns_filename, "w") as f:
            f.writelines("\n".join(sorted(fqdns)))
            logger.info(
                "%d FQDNs written to %s at %s",
                len(fqdns),
                fqdns_filename,
                fqdns_timestamp,
            )
