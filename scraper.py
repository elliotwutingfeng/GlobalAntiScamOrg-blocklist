"""Extracts scam URLs found at https://www.globalantiscam.org/list-of-scam-websites-and-links
and writes them to a .txt blocklist
"""
import asyncio
import json
import logging
import re
import socket
from datetime import datetime

import aiohttp
import cchardet  # type: ignore
from bs4 import BeautifulSoup, SoupStrainer
from more_itertools import flatten
from urlextract import URLExtract

logger = logging.getLogger()
logging.basicConfig(level=logging.INFO, format="%(message)s")

extractor = URLExtract()


default_headers: dict = {
    "Content-Type": "application/json",
    "Connection": "keep-alive",
    "Cache-Control": "no-cache",
    "Accept": "*/*",
}


class KeepAliveClientRequest(aiohttp.client_reqrep.ClientRequest):
    """Attempt to prevent `Response payload is not completed` error

    https://github.com/aio-libs/aiohttp/issues/3904#issuecomment-759205696


    """

    async def send(self, conn):
        """Send keep-alive TCP probes"""
        sock = conn.protocol.transport.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)

        return await super().send(conn)


async def backoff_delay_async(backoff_factor: float, number_of_retries_made: int) -> None:
    """Asynchronous time delay that exponentially increases with `number_of_retries_made`

    Args:
        backoff_factor (float): Backoff delay multiplier
        number_of_retries_made (int): More retries made -> Longer backoff delay
    """
    await asyncio.sleep(backoff_factor * (2 ** (number_of_retries_made - 1)))


async def get_async(
    endpoints: list[str], max_concurrent_requests: int = 5, headers: dict = None
) -> dict[str, bytes]:
    """Given a list of HTTP endpoints, make HTTP GET requests asynchronously

    Args:
        endpoints (list[str]): List of HTTP GET request endpoints
        max_concurrent_requests (int, optional): Maximum number of concurrent async HTTP requests.
        Defaults to 5.
        headers (dict, optional): HTTP Headers to send with every request. Defaults to None.

    Returns:
        dict[str,bytes]: Mapping of HTTP GET request endpoint to its HTTP response content. If
        the GET request failed, its HTTP response content will be `b"{}"`
    """
    if headers is None:
        headers = default_headers

    async def gather_with_concurrency(max_concurrent_requests: int, *tasks) -> dict[str, bytes]:
        semaphore = asyncio.Semaphore(max_concurrent_requests)

        async def sem_task(task):
            async with semaphore:
                await asyncio.sleep(0.5)
                return await task

        tasklist = [sem_task(task) for task in tasks]
        return dict([await f for f in asyncio.as_completed(tasklist)])

    async def get(url, session):
        max_retries: int = 5
        errors: list[str] = []
        for number_of_retries_made in range(max_retries):
            try:
                async with session.get(url, headers=headers) as response:
                    return (url, await response.read())
            except Exception as error:
                errors.append(repr(error))
                logger.warning("%s | Attempt %d failed", error, number_of_retries_made + 1)
                if number_of_retries_made != max_retries - 1:  # No delay if final attempt fails
                    await backoff_delay_async(1, number_of_retries_made)
        logger.error("URL: %s GET request failed! Errors: %s", url, errors)
        return (url, b"{}")  # Allow json.loads to parse body if request fails

    # GET request timeout of 5 minutes (300 seconds)
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=0, ttl_dns_cache=300),
        raise_for_status=True,
        timeout=aiohttp.ClientTimeout(total=300),
        request_class=KeepAliveClientRequest,
    ) as session:
        # Only one instance of any duplicate endpoint will be used
        return await gather_with_concurrency(
            max_concurrent_requests, *[get(url, session) for url in set(endpoints)]
        )


def get_recursively(search_dict: dict, field: str) -> list:
    """Take a dict with nested lists and dicts,
    and searche all dicts for a key of the field
    provided.

    https://stackoverflow.com/a/20254842

    Args:
        search_dict (dict): Dictionary to search
        field (str): Field to search for

    Returns:
        list: List of values of field
    """
    fields_found = []

    for key, value in search_dict.items():

        if key == field:
            fields_found.append(value)

        elif isinstance(value, dict):
            results = get_recursively(value, field)
            for result in results:
                fields_found.append(result)

        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    more_results = get_recursively(item, field)
                    for another_result in more_results:
                        fields_found.append(another_result)

    return fields_found


def current_datetime_str() -> str:
    """Current time's datetime string in UTC.

    Returns:
        str: Timestamp in strftime format "%d_%b_%Y_%H_%M_%S-UTC"
    """
    return datetime.utcnow().strftime("%d_%b_%Y_%H_%M_%S-UTC")


def clean_url(url: str) -> str:
    """Remove zero width spaces, leading/trailing whitespaces, trailing slashes,
    and URL prefixes from a URL

    Args:
        url (str): URL

    Returns:
        str: URL without zero width spaces, leading/trailing whitespaces, trailing slashes,
    and URL prefixes
    """
    removed_zero_width_spaces = re.sub(r"[\u200B-\u200D\uFEFF]", "", url)
    removed_leading_and_trailing_whitespaces = removed_zero_width_spaces.strip()
    removed_trailing_slashes = removed_leading_and_trailing_whitespaces.rstrip("/")
    removed_https = re.sub(r"^[Hh][Tt][Tt][Pp][Ss]:\/\/", "", removed_trailing_slashes)
    removed_http = re.sub(r"^[Hh][Tt][Tt][Pp]:\/\/", "", removed_https)

    return removed_http


async def extract_scam_urls() -> set[str]:
    """Extract scam URLs found at www.globalantiscam.org

    Returns:
        set[str]: Unique scam URLs
    """
    try:
        # main scam list page
        endpoint: str = "https://www.globalantiscam.org/list-of-scam-websites-and-links"
        main_page = (await get_async([endpoint]))[endpoint]

        # Feed URLs are found in this <script> tag with id="wix-warmup-data"
        script_wix_warmup_data_strainer = SoupStrainer("script", id="wix-warmup-data")

        soup = BeautifulSoup(main_page, "lxml", parse_only=script_wix_warmup_data_strainer)

        if script_tags := soup.find_all(lambda tag: tag.string is not None):
            # Extract all feed URLs
            script_content = json.loads(script_tags[0].get_text())
            feed_urls = [x.get("href", "") for x in get_recursively(script_content, "link")]

            # Download content of all feed URLs
            feed_contents = await get_async(feed_urls)

            # Extract scam URLs
            urls = []
            a_data_auto_recognition_strainer = SoupStrainer("a", {"data-auto-recognition": "true"})
            for feed_content in feed_contents.values():
                soup = BeautifulSoup(
                    feed_content, "lxml", parse_only=a_data_auto_recognition_strainer
                )
                urls += [
                    extractor.find_urls(a.get_text(strip=True))
                    for a in soup.find_all(lambda tag: tag.string is not None)
                ]
            # Some lines may have multiple URLs or no valid URLs
            return set(clean_url(url) for url in flatten(urls))
        else:
            logger.error("'wix-warmup-data' not found!")
            return set()
    except Exception as error:
        logger.error(error)
        return set()


if __name__ == "__main__":
    urls: set[str] = asyncio.get_event_loop().run_until_complete(extract_scam_urls())
    if urls:
        timestamp: str = current_datetime_str()
        filename = "global-anti-scam-org-scam-urls.txt"
        with open(filename, "w") as f:
            f.writelines("\n".join(sorted(urls)))
            logger.info("%d URLs written to %s at %s", len(urls), filename, timestamp)
    else:
        raise ValueError("Failed to scrape URLs")
