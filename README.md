# Global Anti Scam Organization blocklist

![Python](https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)

[![GitHub license](https://img.shields.io/badge/LICENSE-BSD--3--CLAUSE-GREEN?style=for-the-badge)](LICENSE)
[![scraper](https://img.shields.io/github/actions/workflow/status/elliotwutingfeng/GlobalAntiScamOrg-blocklist/scraper.yml?branch=main&label=SCRAPER&style=for-the-badge)](https://github.com/elliotwutingfeng/GlobalAntiScamOrg-blocklist/actions/workflows/scraper.yml)
<img src="https://tokei-rs.onrender.com/b1/github/elliotwutingfeng/GlobalAntiScamOrg-blocklist?label=Total%20Blocklist%20URLS&style=for-the-badge" alt="Total Blocklist URLs"/>

Machine-readable `.txt` blocklist of scam URLs and IP Addresses from the [Global Anti Scam Organization](https://www.globalantiscam.org) website, updated once a day.

The URLs and IP Addresses in this blocklist are compiled by the **Global Anti Scam Organization**.

**Disclaimer:** _This project is not sponsored, endorsed, or otherwise affiliated with the Global Anti Scam Organization._

## Blocklist download

| File | Download |
|:-:|:-:|
| global-anti-scam-org-scam-urls.txt | [:floppy_disk:](global-anti-scam-org-scam-urls.txt?raw=true) |
| global-anti-scam-org-scam-urls-ABP.txt | [:floppy_disk:](global-anti-scam-org-scam-urls-ABP.txt?raw=true) |
| global-anti-scam-org-scam-urls-UBO.txt | [:floppy_disk:](global-anti-scam-org-scam-urls-UBO.txt?raw=true) |
| global-anti-scam-org-scam-urls-pihole.txt | [:floppy_disk:](global-anti-scam-org-scam-urls-pihole.txt?raw=true) |
| global-anti-scam-org-scam-ips.txt | [:floppy_disk:](global-anti-scam-org-scam-ips.txt?raw=true) |

## Requirements

- Python >= 3.11

## Setup instructions

`git clone` and `cd` into the project directory, then run the following

```bash
pip3 install -r requirements.txt
```

## Usage

```bash
python3 scraper.py
```

## Libraries/Frameworks used

- [Selenium](https://selenium.dev)
- [tldextract](https://github.com/john-kurkowski/tldextract)

&nbsp;

<sup>These files are provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, arising from, out of or in connection with the files or the use of the files.</sup>

<sub>Any and all trademarks are the property of their respective owners.</sub>
