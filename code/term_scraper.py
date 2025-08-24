from typing import Iterable, List, Dict, Any
from playwright.sync_api import (
    sync_playwright,
    Page,
    ElementHandle,
    Error as PlaywrightError,
)
from configs import term_scraper
import os
import re
from urllib.parse import urlparse, urlunparse
from datetime import datetime
from functools import partial
import time

script_counter = {"count": 0}
scripts_found = []
debug_folder = None
logs_folder = None
default_timeout = 1000

# --------------------------- --------------------- ---------------------------#
# --------------------------- Taskly specific method ---------------------------#
# --------------------------- ---------------------- ---------------------------#


def schedule(
    scan_config: term_scraper.ScanConfig, task_config: term_scraper.TaskConfig
) -> Iterable[term_scraper.AnalysisConfig]:
    """
    Schedules analysis configurations based on the provided scan and task configurations.

    Args:
        scan_config (term_scraper.ScanConfig): Configuration for the scan, including URL and term files.
        task_config (term_scraper.TaskConfig): Configuration for the specific task.
    """
    terms_file_path = (
        scan_config.search_terms_file.value
        if isinstance(scan_config.search_terms_file, term_scraper.TermLists)
        else ""
    )
    urls = []
    url_source = scan_config.url_file
    if isinstance(url_source, str) and url_source.startswith("/"):
        try:
            with open(url_source, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: URL file not found at {url_source}")
    elif isinstance(url_source, term_scraper.UrlLists):
        try:
            with open(url_source.value, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: Predefined URL file not found at {url_source.value}")
    else:
        print("Invalid URL configuration.")

    for url in urls:
        yield term_scraper.AnalysisConfig(
            url=url, search_terms_file_path=terms_file_path
        )


# --------------------------- ------------ --------------------------- #
# --------------------------- Same Methods --------------------------- #
# --------------------------- ------------ --------------------------- #


def get_main_domain_from_url(url: str) -> str:
    """
    Extracts the registrable domain from a URL, handling common two-part TLDs
    and removing common subdomains like 'www.', 'sso.', 'idp.', 'login.'.

    Args:
        url (str): The URL from which to extract the main domain.
    """
    try:
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc

        subdomains_to_remove = ["sso.", "idp.", "login.", "www."]
        for subdomain in subdomains_to_remove:
            if netloc.startswith(subdomain):
                netloc = netloc[len(subdomain) :]

        parts = netloc.split(".")

        # A list of common two-part TLDs that need to be handled specifically.
        two_part_tlds = {
            "co.uk",
            "gov.uk",
            "ac.uk",
            "org.uk",
            "me.uk",
            "co.jp",
            "com.au",
            "com.br",
            "co.nz",
            "com.sg",
        }

        if len(parts) > 2:
            # Check if the last two parts form a known two-part TLD
            last_two = ".".join(parts[-2:])
            if last_two in two_part_tlds:
                netloc = ".".join(parts[-3:])
            else:
                netloc = ".".join(parts[-2:])

        return urlunparse((parsed_url.scheme, netloc, "", "", "", ""))
    except Exception:
        return url


def create_folders(
    analysis_config: term_scraper.AnalysisConfig,
    task_config: term_scraper.TaskConfig,
):
    """
    Creates necessary folders for debug and log files.

    Args:
        analysis_config (term_scraper.AnalysisConfig): Configuration for the current analysis.
        task_config (term_scraper.TaskConfig): Configuration for the specific task.
    """
    global debug_folder, logs_folder
    base_path = (
        "/app/tasks/debug/term_scraper/"
        if task_config.debug_mode
        else "/app/tasks/logs/term_scraper/"
    )

    sanitized_name = get_main_domain_from_url(analysis_config.url)

    target_folder = os.path.join(base_path, sanitized_name)
    os.makedirs(target_folder, exist_ok=True)

    if task_config.debug_mode:
        debug_folder = target_folder
    logs_folder = target_folder


def write_failed_url(task_name: str, url: str):
    """
    Writes a failed URL to a designated file.

    Args:
        task_name (str): The name of the task.
        url (str): The URL that failed.
    """
    try:
        failed_dir = "/app/tasks/urls/failed/term_scraper"
        os.makedirs(failed_dir, exist_ok=True)
        file_path = os.path.join(failed_dir, f"{task_name}.txt")
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(url + "\n")
    except Exception as error_writing_failed_list:
        print(
            f"CRITICAL: Could not write failed URL to list. Error: {error_writing_failed_list}"
        )


def log_message(result: Dict[str, Any], message: str, level: str = "INFO"):
    """
    Logs a message to the console and to a log file.

    Args:
        result (Dict[str, Any]): The result dictionary to append log messages to.
        message (str): The message to log.
        level (str, optional): The log level (e.g., "INFO", "WARNING", "ERROR"). Defaults to "INFO".
    """
    base_url_str = ""
    if "url" in result and result["url"]:
        try:
            url_parts = urlparse(result["url"])
            base_url_str = f"[{url_parts.scheme}://{url_parts.netloc}]"
        except Exception:
            base_url_str = "[invalid_url]"

    task_name = result.get("task_name", "task")
    log_entry = f"[{datetime.now().isoformat()}] [{task_name}] [{level}] {base_url_str} {message}"
    print(log_entry)
    if "log_messages" not in result:
        result["log_messages"] = []
    result["log_messages"].append(log_entry)

    if logs_folder:
        safe_task_name = re.sub(r'[^a-zA-Z0-9._-]', '_', result.get('task_name', 'unknown_task'))
        safe_url = re.sub(r'[^a-zA-Z0-9._-]', '_', result.get('url', 'unknown_url'))[:50]
        log_filename = f"{safe_task_name}_{safe_url}.log"
        log_file_path = os.path.join(logs_folder, log_filename)
        with open(log_file_path, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")


def log_error(result: Dict[str, Any], error_message: str):
    """
    Logs an error message and updates the result dictionary.

    Args:
        result (Dict[str, Any]): The result dictionary to update.
        error_message (str): The error message to log.
    """
    log_message(result, "❌ " + error_message, level="ERROR")
    result["error"] = True
    if "workflow_errors" not in result:
        result["workflow_errors"] = []
    result["workflow_errors"].append(error_message)


def get_element_summary(element: ElementHandle, element_type: str) -> Dict[str, Any]:
    """
    Retrieves a summary of an element's properties, creating a truncated
    HTML snippet based on the specified element type.

    Args:
        element (ElementHandle): The Playwright ElementHandle to be summarized.
        element_type (str): The type of the element ('passkey', 'login',
                            'continue', 'webauthn', 'input') to guide keyword search.

    Returns:
        Dict[str, Any]: A dictionary containing the element's summary.
    """
    try:
        get_summary = """
        (el, args) => {
            const elementType = args.elementType;

            const summary = {
                tag: el.tagName.toLowerCase(),
                text: el.innerText ? el.innerText.trim().substring(0, 500) : '',
                element_html: el.outerHTML,
                element_html_truncated: el.outerHTML,
                autocomplete: el.getAttribute('autocomplete'),
                data_testid: el.getAttribute('data-testid'),
                data_test: el.getAttribute('data-test'),
                name: el.getAttribute('name')
            };

            const keywordMap = {
                'passkey': [
                    "passkey", "security key", "fido", "u2f", "hardware token",
                    "biometrics", "face id", "sign in with.*key", "sign in with.*passkey",
                    "continue with.*passkey", "login with.*passkey"
                ],
                'login': [
                    "sign in", "log in", "login", "anmelden", "einloggen",
                    "auth", "account", "admin"
                ],
                'continue': ["continue", "next", "weiter"],
                'webauthn': ['webauthn', 'passkey', 'fido'],
                'input': ['email', 'username', 'user', 'autocomplete', 'mail']
            };

            const keywords = keywordMap[elementType] || keywordMap['login'];
            const html = summary.element_html;
            const htmlLower = html.toLowerCase();
            
            let bestKeywordIndex = -1;
            let bestKeyword = '';

            for (const kw of keywords) {
                const regex = new RegExp(kw, 'i');
                const match = htmlLower.match(regex);
                if (match) {
                    bestKeywordIndex = match.index;
                    bestKeyword = match[0];
                    break;
                }
            }

            const RADIUS_TRUNCATED = 150;
            const RADIUS_HTML = 300;

            if (bestKeywordIndex !== -1) {
                const startTrunc = Math.max(0, bestKeywordIndex - RADIUS_TRUNCATED);
                const endTrunc = Math.min(html.length, bestKeywordIndex + bestKeyword.length + RADIUS_TRUNCATED);
                let snippetTrunc = html.substring(startTrunc, endTrunc);
                if (startTrunc > 0) snippetTrunc = '...' + snippetTrunc;
                if (endTrunc < html.length) snippetTrunc = snippetTrunc + '...';
                summary.element_html_truncated = snippetTrunc;

                const startHtml = Math.max(0, bestKeywordIndex - RADIUS_HTML);
                const endHtml = Math.min(html.length, bestKeywordIndex + bestKeyword.length + RADIUS_HTML);
                let snippetHtml = html.substring(startHtml, endHtml);
                if (startHtml > 0) snippetHtml = '...' + snippetHtml;
                if (endHtml < html.length) snippetHtml = snippetHtml + '...';
                summary.element_html = snippetHtml;

            } else {
                if (html.length > RADIUS_TRUNCATED * 2) {
                    summary.element_html_truncated = html.substring(0, RADIUS_TRUNCATED * 2) + '...';
                }
                if (html.length > RADIUS_HTML * 2) {
                    summary.element_html = html.substring(0, RADIUS_HTML * 2) + '...';
                }
            }
            
            return summary;
        }
        """
        summary = element.evaluate(get_summary, {"elementType": element_type})

        return summary
    except PlaywrightError:
        return {"error": "Element could not be evaluated."}


def remove_overlays(page: Page, result: Dict[str, Any]):
    """
    Attempts to remove common overlays like cookie banners and modals.

    Args:
        page (Page): The Playwright page object.
        result (Dict[str, Any]): The result dictionary to update.
    """
    log_message(
        result, "Attempting to remove overlays (cookie banners, modals, etc.)..."
    )
    try:
        page.evaluate(
            """() => {
            const selectors = [
                '[id*="cookie"]', '[class*="cookie"]', '[id*="banner"]', '[class*="banner"]',
                '[id*="consent"]', '[class*="consent"]', '[id*="modal"]', '[class*="modal"]',
                '[id*="dialog"]', '[class*="dialog"]', '[role="dialog"]', '.overlay', '#sp_message_container_1109411'
            ];
            document.querySelectorAll(selectors.join(', ')).forEach(el => {
                if (el.style) {
                    el.style.display = 'none';
                    el.style.visibility = 'hidden';
                }
            });
            if (document.body.style) {
                document.body.style.overflow = 'auto';
            }
        }"""
        )
        log_message(result, "✅ Overlays hidden via script.")
    except Exception as e:
        log_error(result, f"Error while trying to remove overlays: {e}")


def find_passkey_button_by_text(
    page: Page, pattern: re.Pattern
) -> ElementHandle | None:
    """
    Searches for a visible and enabled Passkey button based on text patterns.
    Uses Playwright's Locator API for better performance.

    Args:
        page (Page): The Playwright page object.
        pattern (re.Pattern): The regex pattern to match against element text.
    """
    # HTML Elements -> from the manual examination of the ground truth
    selectors = [
        "button",
        'input[type="submit"]',
        'input[type="button"]',
        "a",
        "div",
        "span",
    ]
    for tag in selectors:
        try:
            locator = page.locator(tag).filter(has_text=pattern).first
            if locator.count() > 0:
                element_handle = locator.element_handle()
                if (
                    element_handle
                    and element_handle.is_visible()
                    and element_handle.is_enabled()
                ):
                    return element_handle
        except PlaywrightError:
            continue
    return None


def get_init_script() -> str:
    """
    Returns a JavaScript snippet that simulates the availability of a platform authenticator.

    Returns:
        str: JavaScript code to fake platform authenticator availability.
    """
    return """
    (() => {
        if (window.PublicKeyCredential) {
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
            console.log('Platform authenticator has been faked.');
        }
    })();
    """


def generate_passkey_patterns() -> Dict[str, re.Pattern]:
    """
    Generates regex patterns for passkey and sign-in related keywords.

    Returns:
        Dict[str, re.Pattern]: A dictionary containing compiled regex patterns for passkey and signin buttons.
    """
    # keyword pattern -> from the manual examination of the ground truth
    passkey_button_keywords = [
        "passkey",
        "security key",
        "fido",
        "u2f",
        "hardware token",
        "biometrics",
        "face id",
        "sign in with.*key",
        "sign in with.*passkey",
        "continue with.*passkey",
        "login with.*passkey",
    ]
    # keyword pattern -> from the manual examination of the ground truth
    signin_keywords = [
        "sign in",
        "log in",
        "login",
        "anmelden",
        "einloggen",
        "auth",
        "account",
        "admin",
        "continue",
        "next",
        "weiter",
    ]
    passkey_button_pattern = re.compile(
        "|".join(passkey_button_keywords), re.IGNORECASE
    )
    signin_button_pattern = re.compile(
        r"\b(" + "|".join(signin_keywords) + r")\b", re.IGNORECASE
    )
    return {
        "passkey_button": passkey_button_pattern,
        "signin_button": signin_button_pattern,
    }


# --------------------------- --------------------- --------------------------- #
# --------------------------- Term Scraper specific --------------------------- #
# --------------------------- --------------------- --------------------------- #


# adapted from api_scraper passkey workflow
def search_for_passkey_related_elements(page: Page, result: Dict[str, Any]):
    """
    Searches for Passkey buttons and WebAuthn input fields using the logic
    from api_scraper.py but without creating new result fields.

    Args:
        page (Page): The Playwright page object.
        result (Dict[str, Any]): The result dictionary to update.
    """
    log_message(result, "Searching for Passkey related elements (api_scraper style).")
    patterns = generate_passkey_patterns()
    result.update({"passkey_button_found": False, "passkey_button_element": None})

    passkey_action_successful = False

    # Priority 1: Attribute selectors -> from the manual examination of the ground truth
    passkey_button_selectors = [
        '[data-testid*="passkey"]',
        '[data-testid*="webauthn"]',
        '[data-test*="passkey"]',
        '[data-test*="webauthn"]',
        '[name*="passkey"]',
        '[name*="webauthn"]',
        'button[autocomplete*="webauthn"]',
        'a[autocomplete*="webauthn"]',
        'div[autocomplete*="webauthn"]',
        'span[autocomplete*="webauthn"]',
        '[aria-label*="passkey" i]',
        '[aria-label*="security key" i]',
        '[role="button"][title*="passkey" i]',
    ]
    for selector in passkey_button_selectors:
        try:
            elements = page.locator(selector + ":visible:enabled").all()
            if elements:
                element_handle = elements[0].element_handle()
                log_message(
                    result,
                    f"✅ SUCCESS: Found Passkey element via attribute selector '{selector}'.",
                )
                result["passkey_button_found"] = True
                result["passkey_button_element"] = get_element_summary(
                    element_handle, "passkey"
                )
                log_message(result, f"✅ Passkey found")
                passkey_action_successful = True
                break
        except PlaywrightError as e:
            log_message(
                result,
                f"❗ Could not check selector '{selector}': {e}",
                level="WARNING",
            )

    # Priority 2: Text patterns
    if not passkey_action_successful:
        candidate_selectors = ["button", "a", "div", "span"]
        for selector in candidate_selectors:
            try:
                locator = page.locator(selector).filter(
                    has_text=patterns["passkey_button"]
                )
                for i in range(locator.count()):
                    element_handle = locator.nth(i).element_handle()
                    if (
                        element_handle
                        and element_handle.is_visible()
                        and element_handle.is_enabled()
                    ):
                        matched_text = element_handle.inner_text().strip()
                        log_message(
                            result,
                            f"✅ SUCCESS: Found clickable Passkey button via text: '{matched_text}'.",
                        )
                        result["passkey_button_found"] = True
                        result["passkey_button_element"] = get_element_summary(
                            element_handle, "passkey"
                        )
                        log_message(result, f"✅ Passkey found")
                        passkey_action_successful = True
                        break
                if passkey_action_successful:
                    break
            except PlaywrightError as e:
                log_message(
                    result,
                    f"⚠️ Could not check for text pattern on selector '{selector}': {e}",
                    level="WARNING",
                )

    if not passkey_action_successful:
        log_message(result, "❗ No clickable Passkey button found.", level="INFO")

    # WebAuthn input fields
    log_message(result, "Searching for WebAuthn input fields.")
    webauthn_inputs = []
    try:
        webauthn_locators = page.locator('input[autocomplete*="webauthn"]').all()
        for locator in webauthn_locators:
            try:
                webauthn_inputs.append(locator.evaluate("el => el.outerHTML"))
            except PlaywrightError as e:
                log_message(
                    result,
                    f"⚠️ Could not evaluate a webauthn input field: {e}",
                    level="WARNING",
                )
    except PlaywrightError as e:
        log_message(
            result,
            f"⚠️ Could not search for webauthn input fields: {e}",
            level="WARNING",
        )

    if webauthn_inputs:
        result["webauthn_input_found"] = True
        result["webauthn_input_element"] = webauthn_inputs
        log_message(result, f"✅ Found {len(webauthn_inputs)} webauthn input field(s).")
    else:
        result["webauthn_input_found"] = False
        log_message(result, "❗ No webauthn input field found.", level="INFO")


def get_char_context(text: str, start: int, end: int, window: int) -> str:
    """
    Extracts a context snippet around a found term.

    Args:
        text (str): The source text.
        start (int): The starting index of the term.
        end (int): The ending index of the term.
        window (int): The number of characters to include before and after the term.
    """
    begin = max(0, start - window)
    finish = min(len(text), end + window)
    return text[begin:finish]


def handle_scripts(response: Any, result: Dict[str, Any]):
    """
    Processes JavaScript files from network responses.

    Args:
        response (Any): The Playwright Response object.
        result (Dict[str, Any]): The result dictionary to update.
    """
    global script_counter, scripts_found
    try:
        if response.request.resource_type == "script":
            content = response.text()
            scripts_found.append(
                {
                    "name": os.path.basename(urlparse(response.url).path),
                    "content": content,
                }
            )
            script_counter["count"] += 1
    except Exception as e:
        log_message(
            result, f"⚠️ Could not handle script {response.url}: {e}", level="WARNING"
        )


def search_terms(
    terms: List[str], char_window: int, content: str, result: Dict[str, Any]
):
    """
    Searches content and scripts for specific terms.

    Args:
        terms (List[str]): A list of terms to search for.
        char_window (int): The context window size for hit snippets.
        content (str): The HTML content of the page to search in.
        result (Dict[str, Any]): The result dictionary to update.
    """
    log_message(result, f"Searching for {len(terms)} terms.")
    any_term_found = False
    for term in terms:
        term_hits = []
        pattern = (
            re.compile(rf"(\b{re.escape(term)}\b)", re.IGNORECASE)
            if " " not in term
            else re.compile(
                rf"(\b{re.escape(term.split(' ')[0])}\b(?:.|\n){{0,{char_window}}}?\b{re.escape(term.split(' ')[1])}\b)",
                re.IGNORECASE,
            )
        )
        sanitized = (
            term.replace(" ", "_")
            .translate(str.maketrans({".": "_", "$": "_", "/": "_", ":": "_"}))
            .lower()
        )

        for script in scripts_found:
            for m in pattern.finditer(script.get("content", "")):
                term_hits.append(
                    {
                        "source": "script",
                        "script_name": script.get("name"),
                        "context": get_char_context(
                            script.get("content", ""), m.start(), m.end(), char_window
                        ),
                    }
                )

        for m in pattern.finditer(content):
            term_hits.append(
                {
                    "source": "html",
                    "position": m.start(),
                    "context": get_char_context(
                        content, m.start(), m.end(), char_window
                    ),
                }
            )

        result[sanitized] = bool(term_hits)
        if term_hits:
            result[f"{sanitized}_hits"] = term_hits
            any_term_found = True

    result["any_term_found"] = any_term_found


# --------------------------- ---- ---------------------------#
# --------------------------- MAIN ---------------------------#
# --------------------------- ---- ---------------------------#


def start(
    task_config: term_scraper.TaskConfig,
    analysis_config: term_scraper.AnalysisConfig,
) -> dict:
    """
    Starts the Playwright browser and executes the static crawling and analysis task.

    Args:
        task_config (term_scraper.TaskConfig): Configuration for the specific task.
        analysis_config (term_scraper.AnalysisConfig): Configuration for the current analysis.
    """
    global scripts_found, script_counter, debug_folder, logs_folder, default_timeout
    scripts_found, script_counter, debug_folder, logs_folder = (
        [],
        {"count": 0},
        None,
        None,
    )
    start_time = datetime.now()
    start_time_mono = time.monotonic()
    url_id = get_main_domain_from_url(analysis_config.url)

    result = {
        "task_name": task_config.task_name,
        "url_id": url_id,
        "url": analysis_config.url,
        "known_passkey": task_config.passkey_known,
        "timeout": task_config.timeout,
        "locale": task_config.locale.value,
        "debug_mode": task_config.debug_mode,
        "start_time": start_time.isoformat(),
        "error": False,
        "log_messages": [],
        "error_messages": [],
    }

    if task_config.search_passkey:
        result.update(
            {
                "passkey_button_found": False,
                "passkey_button_element": None,
                "webauthn_input_found": False,
            }
        )

    create_folders(analysis_config, task_config)
    log_message(result, f"Starting static analysis for URL: {analysis_config.url}")

    default_timeout = task_config.timeout * 1000
    terms = []
    try:
        with open(analysis_config.search_terms_file_path, "r", encoding="utf-8") as f:
            terms = [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("##")
            ]
        log_message(result, f"Loaded {len(terms)} search terms.")
    except FileNotFoundError:
        log_error(
            result,
            f"Search terms file not found: {analysis_config.search_terms_file_path}",
        )
        return result

    timezone_id = {
        "en-US": "America/New_York",
        "en-GB": "Europe/London",
        "de-DE": "Europe/Berlin",
    }.get(task_config.locale.value, "UTC")

    with sync_playwright() as p:
        browser, context = None, None
        try:
            browser = p.chromium.launch(headless=False)
            context = browser.new_context(
                locale=task_config.locale.value,
                timezone_id=timezone_id,
                record_video_dir=debug_folder if task_config.debug_mode else None,
            )
            if task_config.debug_mode:
                context.tracing.start(screenshots=True, snapshots=True, sources=True)

            context.set_default_timeout(default_timeout)
            page = context.new_page()

            if task_config.search_passkey:
                log_message(
                    result, "Passkey search enabled: Faking platform authenticator."
                )
                page.add_init_script(get_init_script())

            page.on(
                "response",
                partial(handle_scripts, result=result),
            )

            log_message(result, f"🧭 Navigating to {analysis_config.url}")
            page.goto(analysis_config.url, wait_until="load")
            log_message(result, "Page loaded. Starting analysis...")

            log_message(result, "Waiting for 4 seconds before searching for elements.")
            page.wait_for_timeout(4000)

            if task_config.search_passkey:
                search_for_passkey_related_elements(page, result)

            time_before_search = time.monotonic()
            elapsed_so_far = time_before_search - start_time_mono
            wait_duration_seconds = task_config.timeout - elapsed_so_far - 2

            if wait_duration_seconds > 0:
                log_message(
                    result,
                    f"⏱️ Waiting for {wait_duration_seconds:.2f} seconds before final term search.",
                )
                page.wait_for_timeout(wait_duration_seconds * 1000)

            log_message(result, "Executing final term search.")
            content = page.content()
            result["search_url"] = page.url
            if terms:
                search_terms(terms, task_config.context_window, content, result)

            elapsed_after_search = time.monotonic() - start_time_mono
            remaining_wait = task_config.timeout - elapsed_after_search
            if remaining_wait > 0:
                log_message(
                    result,
                    f"Task almost finished. Waiting for remaining {remaining_wait:.2f} seconds.",
                )
                page.wait_for_timeout(remaining_wait * 1000)

        except Exception as e:
            log_error(result, f"A critical error occurred: {repr(e)}")

        finally:
            if task_config.search_passkey:
                results_to_check = [
                    "any_term_found",
                    "webauthn_input_found",
                    "passkey_button_found",
                ]
            else:
                results_to_check = ["any_term_found"]

            if not any(result.get(key) for key in results_to_check):
                log_message(
                    result,
                    f"⚠️ URL failed (no terms found). Adding to failed list: {analysis_config.url}",
                    level="WARNING",
                )
                write_failed_url(task_config.task_name, analysis_config.url)

            result["end_time"] = datetime.now().isoformat()
            result["duration_seconds"] = (datetime.now() - start_time).total_seconds()
            log_message(
                result, f"🏁 Task finished in {result['duration_seconds']:.2f} seconds."
            )
            if context and task_config.debug_mode and debug_folder:
                trace_filename = f"{task_config.task_name}_trace.zip"
                context.tracing.stop(path=os.path.join(debug_folder, trace_filename))
            if browser:
                browser.close()

    return result
