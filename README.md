# Appendix-automated-detection-of-passkey-support
This repository contains the source code and datasets from a bachelor's thesis focused on the automated detection of Passkey support on websites. The included tasks (static, dynamic, and network-based scrapers) are provided to allow for full reproducibility of the research methods.

# Automated Detection of Passkey Support on Websites

This repository contains the core software and datasets developed as part of a bachelor's thesis on the automated detection of Passkey implementations. The project addresses the lack of reliable, up-to-date methods for identifying websites that support the WebAuthn standard for passwordless authentication.

The goal of this repository is to provide the three core analytical tasks for direct reproducibility of the research methods. For a detailed discussion of the methodology, results, and architecture, please refer to the complete thesis document.

### Methodology

The project is based on three distinct detection methods:

1.  **Static Code Scraper (`term_scraper.py`):** Analyzes a website's source code for specific keywords and code patterns (e.g., `navigator.credentials.create`) that indicate potential WebAuthn support.
2.  **Dynamic API Scraper (`api_scraper.py`):** Utilizes browser automation and a Monkey Patching technique to directly monitor and log calls to the `navigator.credentials` API, providing a reliable way to verify a functional Passkey implementation.
3.  **Network Traffic Scraper (`network_scraper.py`):** Observes network requests and responses for characteristic patterns related to WebAuthn, such as challenges, `rpId`s, and specific API endpoints.

### Repository Contents

* `code/`:
    * `term_scraper.py`: The Python script for the static code analysis.
    * `api_scraper.py`: The Python script for the dynamic API analysis.
    * `network_scraper.py`: The Python script for the network traffic analysis.
* `data/`:
    * `ground_truth.csv`: The primary dataset of manually verified websites used for evaluation.
    * `Lastpass_auth.txt`: A list of the URLs that were scraped.
    * `navigator_methods.txt`: The list with Terms for the static code analysis.
* `results/`:
    * `api_scraper`: The folder with the exported results for the dynamic API analysis.
    * `elements_found`: The folder with the exported results formatted as HTML list for all three analysis.
    * `network_scraper`: The folder with the exported results for the network traffic analysis.
    * `scraper_comparison`: The folder with the exported results for comparison of all three analysis.
    * `term_scraper`: The folder with the exported results for the static code analysis.

### License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).
