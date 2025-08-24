from typing import Iterable, Dict, Any
from playwright.sync_api import (
    sync_playwright,
    Page,
    ElementHandle,
    Error as PlaywrightError,
    ConsoleMessage,
    TimeoutError,
    Response,
    Locator,
)
from configs import api_scraper
import os
import re
import json
from urllib.parse import urlparse, urlunparse
from datetime import datetime
import time

debug_folder = None
logs_folder = None

# --------------------------- ---------------------- --------------------------- #
# --------------------------- Taskly specific method --------------------------- #
# --------------------------- ---------------------- --------------------------- #


def schedule(
    scan_config: api_scraper.ScanConfig,
    task_config: api_scraper.TaskConfig,
) -> Iterable[api_scraper.AnalysisConfig]:
    """
    Schedules analysis configurations based on the provided scan and task configurations.

    Args:
        scan_config (api_scraper.ScanConfig): Configuration for the scan, including URL file.
        task_config (api_scraper.TaskConfig): Configuration for the specific task.
    """
    urls = []
    url_file_path = None
    if isinstance(scan_config.url_file, str) and scan_config.url_file.startswith("/"):
        url_file_path = scan_config.url_file
    elif hasattr(scan_config.url_file, "value"):
        url_file_path = scan_config.url_file.value

    if url_file_path:
        try:
            with open(url_file_path, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"ERROR: URL file not found at {url_file_path}")
    else:
        print("ERROR: Invalid URL configuration in ScanConfig.url_file")

    for url in urls:
        yield api_scraper.AnalysisConfig(url=url)


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
    analysis_config: api_scraper.AnalysisConfig,
    task_config: api_scraper.TaskConfig,
):
    """
    Creates necessary folders for debug and log files.

    Args:
        analysis_config (api_scraper.AnalysisConfig): Configuration for the current analysis.
        task_config (api_scraper.TaskConfig): Configuration for the specific task.
    """
    global debug_folder, logs_folder
    base_path = (
        "/app/tasks/debug/api_scraper/"
        if task_config.debug_mode
        else "/app/tasks/logs/api_scraper/"
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
        failed_dir = "/app/tasks/urls/failed/api_scraper"
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
            base_url_str = "[invalid_urlF]"

    task_name = result.get("task_name", "task")
    log_entry = f"[{datetime.now().isoformat()}] [{task_name}] [{level}] {base_url_str} {message}"
    print(log_entry)
    if "log_messages" not in result:
        result["log_messages"] = []
    result["log_messages"].append(log_entry)

    if logs_folder:
        safe_task_name = re.sub(
            r"[^a-zA-Z0-9._-]", "_", result.get("task_name", "unknown_task")
        )
        safe_url = re.sub(r"[^a-zA-Z0-9._-]", "_", result.get("url", "unknown_url"))[
            :50
        ]
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


def search_login(page: Page, result: Dict[str, Any]) -> Locator | None:
    """Searches for and interacts with login buttons on a page.

    This function uses a hybrid approach to robustly identify and click a
    primary, internal-only login button. It pre-filters for elements
    containing any login-related keyword. It then explicitly categorizes
    each button as 'third-party' or 'primary'. A button is only considered
    primary if it contains a primary keyword (e.g., "sign in") but does NOT
    contain a third-party provider name (e.g., "google"), thus avoiding
    buttons like "Sign in with Google".

    Args:
        page (Page): The Playwright Page object to interact with.
        result (Dict[str, Any]): A dictionary to store findings, such as
            identified third-party login buttons and logs.

    Returns:
        Locator | None: The Playwright Locator of the clicked primary login
        button, or None if no suitable button was found or clicked.
    """
    log_message(result, "🔍 Starting robust login search with anti-pattern...")

    THIRD_PARTY_PROVIDERS = [
        r"\bgoogle\b",
        r"\bmicrosoft\b",
        r"\bgithub\b",
        r"\bapple\b",
        r"\b(sign\s+in\s+with\s+)?x\b",
        r"\bdiscord\b",
    ]
    PRIMARY_LOGIN_KEYWORDS = ["sign in", "login", "log in"]
    CLICKABLE_SELECTORS = ["button", "a", 'div[role="button"]', 'span[role="button"]']

    all_keywords = PRIMARY_LOGIN_KEYWORDS + THIRD_PARTY_PROVIDERS
    login_regex = re.compile("|".join(all_keywords), re.IGNORECASE)

    result.setdefault("third_party_logins", [])
    found_primary_button = None

    try:
        potential_buttons = page.locator(",".join(CLICKABLE_SELECTORS)).filter(
            has_text=login_regex
        )
        log_message(
            result,
            f"✅ Found {potential_buttons.count()} potential login buttons. Analyzing them...",
        )

        for i in range(potential_buttons.count()):
            button = potential_buttons.nth(i)
            try:
                if not button.is_visible():
                    continue

                button_text_raw = button.inner_text()
                if not button_text_raw.strip():
                    continue

                button_text_lower = button_text_raw.lower()

                contains_provider = any(
                    provider in button_text_lower for provider in THIRD_PARTY_PROVIDERS
                )
                contains_primary_keyword = any(
                    keyword in button_text_lower for keyword in PRIMARY_LOGIN_KEYWORDS
                )

                is_third_party = (
                    contains_provider or "continue with" in button_text_lower
                )

                is_primary = contains_primary_keyword and not contains_provider

                if is_third_party:
                    log_message(result, f"✅  [Third-Party] Found: '{button_text_raw}'")
                    if button_text_raw not in result["third_party_logins"]:
                        result["third_party_logins"].append(button_text_raw)

                elif is_primary and not found_primary_button:
                    log_message(
                        result,
                        f"✅  [Primary] Found: '{button_text_raw}' - this is the target.",
                    )
                    found_primary_button = button

            except Exception as e:
                log_message(
                    result,
                    f"⚠️ Could not analyze a potential button: {e}",
                    level="WARNING",
                )

        if result["third_party_logins"]:
            log_message(
                result, f"Collected third-party logins: {result['third_party_logins']}"
            )

        if found_primary_button:
            log_message(
                result,
                f"✅ Clicking primary login button: '{found_primary_button.inner_text()}'",
            )
            try:
                found_primary_button.click(timeout=5000)
                page.wait_for_load_state("domcontentloaded", timeout=5000)
                return found_primary_button
            except TimeoutError:
                log_message(
                    result, "⚠️ Timeout after clicking login button.", level="WARNING"
                )
            except Exception as e:
                log_message(result, f"Error clicking login button: {e}", level="ERROR")
        else:
            log_message(result, "❗ No suitable primary login button found to click.")

    except Exception as e:
        log_error(result, f"An error occurred during login search: {e}")

    return None


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
            # HTML banners etc. -> from the manual examination of the ground truth
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


def click_and_visualize(page: Page, element: ElementHandle, result: Dict[str, Any]):
    """
    Clicks an element and optionally visualizes the click location for debugging.

    Args:
        page (Page): The Playwright page object.
        element (ElementHandle): The element to click.
        result (Dict[str, Any]): The result dictionary, used to check debug mode.
    """
    if not result.get("debug_mode", False):
        element.click(timeout=2000)
        return

    box = element.bounding_box()
    if not box:
        element.click(timeout=2000)
        return

    click_x = box["x"] + box["width"] / 2
    click_y = box["y"] + box["height"] / 2

    script = """
    (async ({x, y}) => {
        const a = document.createElement('div');
        a.style.position = 'absolute'; a.style.left = x + 'px'; a.style.top = y + 'px';
        a.style.border = '3px solid red'; a.style.borderRadius = '50%';
        a.style.width = '40px'; a.style.height = '40px';
        a.style.transform = 'translate(-50%, -50%)'; a.style.pointerEvents = 'none';
        a.style.zIndex = '2147483647'; a.style.transition = 'opacity 0.8s';
        document.body.appendChild(a);
        await new Promise(r => setTimeout(r, 100));
        a.style.opacity = '0';
        await new Promise(r => setTimeout(r, 800));
        a.remove();
    })
    """
    page.evaluate(script, {"x": click_x, "y": click_y})
    element.click(timeout=2000)


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


def generate_passkey_patterns() -> Dict[str, re.Pattern]:
    """
    Generates more specific regex patterns for passkey and sign-in related keywords.
    """
    # keyword pattern -> from the manual examination of the ground truth
    passkey_button_keywords = [
        r"\b(passkey|security key)\b",
        r"\b(sign in with( a)? passkey)\b",
        r"\b(continue with( a)? passkey)\b",
        r"\b(login with( a)? passkey)\b",
        r"\b(face id|biometrics)\b",
        r"\b(fido|u2f)\b",
    ]

    # keyword pattern -> from the manual examination of the ground truth
    signin_keywords = [
        r"\b(sign in|log in|login)\b",
        r"\b(continue|next|weiter)\b",
        r"\b(anmelden|einloggen)\b",
    ]

    passkey_button_pattern = re.compile(
        "|".join(passkey_button_keywords), re.IGNORECASE
    )
    signin_button_pattern = re.compile("|".join(signin_keywords), re.IGNORECASE)

    return {
        "passkey_button": passkey_button_pattern,
        "signin_button": signin_button_pattern,
    }


# Workflow:
# [route 1]
# 1. loads site and waits 5s
# 2. removes overlays waits 1s
# 3. searches for input field and for autocomplete = webauthn input fields
# 4. [if] searches for passkey buttons by attributes
# 5. [else] searches for passkey buttons by text
# 6. [if] (input field found) [then] fill with mail
# 7. [if] (Passkey Button found) [then] click it and wait 2s
# 8. [if] (no passkey_action_successful) and not is_retry [then]go back to main url and restart workflow
#
# [route 2]
# 1. loads site and waits 5s
# 2. removes overlays waits 1s
# 3. searches for input field and for autocomplete = webauthn input fields
# 4. [if] searches for passkey buttons by attributes
# 5. [else] searches for passkey buttons by text
# 6. [if](input field found) [then] fill with mail
# 7. [if](no passkey button found) [then] searching continue button and click it wait 4s
# 8. [if](continue button clicked) [then] search for passkey button by text an click it wait 2s
# 9. [if] (no passkey_action_successful and not is_retry) [then]go back to main url and restart workflow
def execute_passkey_workflow(
    page: Page,
    result: Dict[str, Any],
    initial_url: str,
    task_config,
    is_retry: bool = False,
):
    """
    Executes the Passkey workflow.
    This workflow first discovers all relevant elements (input fields, passkey buttons),
    then acts upon them by filling the email and clicking the appropriate button.
    As a last resort, it falls back to the main domain and retries.

    Args:
        page (Page): The Playwright page object.
        result (Dict[str, Any]): The result dictionary to update.
        initial_url (str): The initial URL the workflow started with.
        is_retry (bool, optional): Indicates if this is a retry after a main domain redirection. Defaults to False.
    """
    patterns = generate_passkey_patterns()

    passkey_action_successful = False

    if not is_retry:
        result.update(
            {
                "input_element_found": False,
                "webauthn_input_found": False,
                "input_element": None,
                "passkey_button_found": False,
                "passkey_button_element": None,
                "passkey_workflow_retried": False,
                "continue_button_found": False,
                "continue_button_element": None,
            }
        )

    try:
        log_message(result, "Workflow: Initial 5-second wait and overlay removal.")
        page.wait_for_timeout(5000)
        remove_overlays(page, result)
        page.wait_for_timeout(1000)

        if task_config.search_initial_login and not is_retry:
            log_message(
                result,
                "Initial login search is enabled, searching for login button first.",
            )
            search_login(page, result)

        log_message(result, "Discovery Phase: Searching for all relevant elements.")

        email_field_locator = None
        webauthn_input_locator = page.locator(
            'input[autocomplete*="webauthn"]:visible'
        ).first

        if webauthn_input_locator.count() > 0:
            log_message(result, "✅ Found an input field with autocomplete 'webauthn'.")
            result["webauthn_input_found"] = True
            result["input_element_found"] = True
            result["webauthn_input_element"] = get_element_summary(
                webauthn_input_locator.element_handle(), "webauthn"
            )
            log_message(result, f"✅ Webauthn input field found")
            email_field_locator = webauthn_input_locator
        else:
            log_message(
                result,
                "❗ No 'webauthn' input field found. Searching for generic email/username field.",
            )
            generic_email_locator = page.locator(
                'input[type="email"]:visible, input[name*="email"]:visible, input[autocomplete*="username"]:visible, input[type="text"][name*="user"]:visible, input[aria-label*="mail"]:visible'
            ).first
            if generic_email_locator.count() > 0:
                log_message(result, "✅ Found a generic email/username input field.")
                result["input_element_found"] = True
                result["input_element"] = get_element_summary(
                    generic_email_locator.element_handle(), "input"
                )
                email_field_locator = generic_email_locator

        passkey_button_handle = None
        # attributes pattern -> from the manual examination of the ground truth
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
                locator = page.locator(selector + ":visible:enabled").first
                if locator.count() > 0:
                    passkey_button_handle = locator.element_handle()
                    log_message(
                        result,
                        f"✅ Found Passkey button/element via attribute selector '{selector}'.",
                    )
                    result["passkey_button_found"] = True
                    result["passkey_button_element"] = get_element_summary(
                        passkey_button_handle, "passkey"
                    )
                    result["passkey_button_matched_text"] = (
                        f"attribute_match:{selector}"
                    )
                    log_message(result, f"✅ Passkey found with text {selector}")
                    break
            except PlaywrightError:
                continue

        if not passkey_button_handle:
            log_message(result, "❗ No Passkey button by attribute. Searching by text.")
            button_by_text = find_passkey_button_by_text(
                page, patterns["passkey_button"]
            )
            if button_by_text:
                passkey_button_handle = button_by_text
                matched_text = button_by_text.inner_text().strip()
                log_message(
                    result, f"✅ Found Passkey button via text: '{matched_text}'."
                )
                result["passkey_button_found"] = True
                result["passkey_button_element"] = get_element_summary(
                    passkey_button_handle, "passkey"
                )
                result["passkey_button_matched_text"] = matched_text
                log_message(result, f"✅ Passkey found with text {matched_text}")

        log_message(
            result, "Action Phase: Deciding actions based on discovered elements."
        )

        if email_field_locator:
            log_message(
                result, "Filling input field with 'maxmusterscraper@gmail.com'."
            )
            try:
                email_field_locator.type("maxmusterscraper@gmail.com", delay=50)
                result["email_filled"] = True
                page.wait_for_timeout(1000)
            except PlaywrightError as e:
                log_error(result, f"Could not fill input field: {e}")
        else:
            log_message(result, "❗ No email input field found to fill.")

        if passkey_button_handle:
            log_message(result, "✅ A dedicated Passkey button was found. Clicking it.")
            click_and_visualize(page, passkey_button_handle, result)
            result["passkey_button_clicked"] = True
            page.wait_for_timeout(2000)
            passkey_action_successful = True

        elif email_field_locator:
            log_message(
                result,
                "❗ Email was filled, but no direct Passkey button found. Looking for a 'Continue' button.",
            )

            # HTML pattern -> from the manual examination of the ground truth
            continue_button_selectors = [
                'button[data-testid*="continue"]',
                'button[data-test*="continue"]',
                'button[data-testid*="next"]',
                'button[data-test*="next"]',
                'button[data-testid*="sign-in"]',
                'button[data-test*="sign-in"]',
                "button",
                'input[type="submit"]',
                'input[type="button"]',
                "a",
                "div",
                "span",
            ]
            continue_button_locator = (
                page.locator(", ".join(continue_button_selectors))
                .filter(has_text=patterns["signin_button"])
                .first
            )

            if continue_button_locator.count() > 0:
                button = continue_button_locator.element_handle()
                if button and button.is_visible() and button.is_enabled():
                    log_message(
                        result, "✅ Found and clicking 'Continue'/'Sign In' button."
                    )
                    result["continue_button_found"] = True
                    result["continue_button_element"] = get_element_summary(
                        button, "continue"
                    )
                    click_and_visualize(page, button, result)
                    page.wait_for_load_state("domcontentloaded")
                    page.wait_for_timeout(4000)

                    log_message(
                        result,
                        "❗ After 'Continue' click: Searching for Passkey button again.",
                    )
                    final_passkey_button = find_passkey_button_by_text(
                        page, patterns["passkey_button"]
                    )
                    if not final_passkey_button:
                        for selector in passkey_button_selectors:
                            try:
                                locator = page.locator(
                                    selector + ":visible:enabled"
                                ).first
                                if locator.count() > 0:
                                    final_passkey_button = locator.element_handle()
                                    break
                            except PlaywrightError:
                                continue

                    if (
                        final_passkey_button
                        and final_passkey_button.is_visible()
                        and final_passkey_button.is_enabled()
                    ):
                        log_message(
                            result,
                            "✅ Passkey button found after 'Continue' click. Clicking it.",
                        )
                        result["passkey_button_found"] = True
                        result["passkey_button_element"] = get_element_summary(
                            final_passkey_button, "passkey"
                        )
                        result["passkey_button_matched_text"] = "found_after_continue"
                        click_and_visualize(page, final_passkey_button, result)
                        page.wait_for_timeout(2000)
                        passkey_action_successful = True
            else:
                log_message(
                    result, "❗ Email was filled, but no 'Continue' button found."
                )
        else:
            log_message(
                result, "❗ No email field and no passkey button found on the page."
            )

        if not passkey_action_successful and not is_retry:
            log_message(
                result,
                "❗❗ No Passkey action taken. Navigating to main domain to find login.",
            )
            result["passkey_workflow_retried"] = True
            main_domain_url = get_main_domain_from_url(initial_url)
            log_message(result, f"↪️ Redirecting to: {main_domain_url}")
            page.goto(main_domain_url, wait_until="domcontentloaded")
            page.wait_for_timeout(4000)
            search_login(page, result)
            log_message(result, "❗ Restarting Passkey workflow after redirection.")
            execute_passkey_workflow(
                page,
                result,
                initial_url,
                task_config,
                is_retry=True,
            )
            return

    except Exception as e:
        log_error(
            result, f"An unexpected error occurred in the Passkey workflow: {repr(e)}"
        )


# --------------------------- -------------------- ---------------------------#
# --------------------------- API Scraper specific ---------------------------#
# --------------------------- -------------------- ---------------------------#


def handle_playwright_log(msg: ConsoleMessage, result: Dict[str, Any]):
    """
    Handles Playwright console messages, specifically looking for custom logs
    related to WebAuthn API calls.

    Args:
        msg (ConsoleMessage): The Playwright ConsoleMessage object.
        result (Dict[str, Any]): The result dictionary to update.
    """
    try:
        text = msg.text
        if text.startswith("PLAYWRIGHT_LOG:"):
            log_data_str = text[len("PLAYWRIGHT_LOG:") :]
            log_data = json.loads(log_data_str)
            log_type = log_data.get("type")
            options = log_data.get("data", {}).get("options")

            api_call_info = {
                "type": log_type,
                "timestamp": datetime.now().isoformat(),
                "options": options,
            }

            phase = result.get("current_phase", "unknown")
            category_key = f"api_calls_{phase}"
            if category_key not in result:
                result[category_key] = []

            result[category_key].append(api_call_info)
            log_message(
                result, f"✅ API call '{log_type}' detected during phase '{phase}'."
            )
            result["api_call_detected"] = True

            if isinstance(options, dict):
                if "publicKey" in options:
                    result["api_calls_public_key"].append(api_call_info)
                    log_message(
                        result, "✅ Detected API call with 'publicKey' options."
                    )
                    try:
                        if isinstance(options.get("publicKey"), dict):
                            rp_id = options["publicKey"].get("rpId")
                            if rp_id:
                                log_message(
                                    result, f"✅ API call contains rpId: '{rp_id}'."
                                )
                                rpid_info = {
                                    "rpId": rp_id,
                                    "type": log_type,
                                    "timestamp": api_call_info["timestamp"],
                                }
                                result["api_calls_with_rpid"].append(rpid_info)
                    except (TypeError, KeyError):
                        pass

                if "federated" in options:
                    result["api_calls_federated"].append(api_call_info)
                    log_message(
                        result, "✅ Detected API call with 'federated' options."
                    )

                if "identity" in options:
                    result["api_calls_identity"].append(api_call_info)
                    log_message(result, "✅ Detected API call with 'identity' options.")
            else:
                if "api_calls_empty" not in result:
                    result["api_calls_empty"] = []
                result["api_calls_empty"].append(api_call_info)
                log_message(result, "✅ Detected API call with empty or null options.")

            if logs_folder:
                try:
                    safe_task_name = re.sub(
                        r"[^a-zA-Z0-9._-]", "_", result.get("task_name", "unknown_task")
                    )
                    safe_url = re.sub(
                        r"[^a-zA-Z0-9._-]", "_", result.get("url", "unknown_url")
                    )[:50]
                    api_log_filename = f"{safe_task_name}_{safe_url}.log"
                    api_log_path = os.path.join(logs_folder, api_log_filename)
                    with open(api_log_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(api_call_info) + "\n")
                except Exception as e:
                    log_error(result, f"Failed to write to api_calls.log: {e}")

    except Exception as e:
        log_error(result, f"Error processing console message: {repr(e)}")


def get_monkey_patch_script() -> str:
    """
    Returns a JavaScript string to monkey-patch navigator.credentials.get and .create
    to log WebAuthn API calls to the console.
    """
    return """
    (() => {
        function sendToPython(type, data) {
            console.log('PLAYWRIGHT_LOG:' + JSON.stringify({type, data}));
        }
        if (!navigator.credentials) { navigator.credentials = {}; }
        const origGet = navigator.credentials.get;
        navigator.credentials.get = function(options) {
            sendToPython('credentials_get', {options: options ? JSON.parse(JSON.stringify(options)) : null});
            if (typeof origGet === 'function') { return origGet.apply(this, arguments); }
            return Promise.reject(new TypeError("navigator.credentials.get is not a function."));
        };
        const origCreate = navigator.credentials.create;
        navigator.credentials.create = function(options) {
            sendToPython('credentials_create', {options: options ? JSON.parse(JSON.stringify(options)) : null});
            if (typeof origCreate === 'function') { return origCreate.apply(this, arguments); }
            return Promise.reject(new TypeError("navigator.credentials.create is not a function."));
        };
        if (window.PublicKeyCredential) {
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
        }
    })();
    """


# --------------------------- ---- ---------------------------#
# --------------------------- MAIN ---------------------------#
# --------------------------- ---- ---------------------------#


def start(
    task_config: api_scraper.TaskConfig,
    analysis_config: api_scraper.AnalysisConfig,
) -> dict:
    """
    Starts the Playwright browser and executes the Passkey analysis workflow.

    Args:
        task_config (api_scraper.TaskConfig): Configuration for the specific task.
        analysis_config (api_scraper.AnalysisConfig): Configuration for the current analysis.
    """
    global debug_folder, logs_folder
    debug_folder, logs_folder = None, None

    # starts timer for duration measurement of task
    start_time_mono = time.monotonic()
    url_id = get_main_domain_from_url(analysis_config.url)

    result = {
        "task_name": task_config.task_name,
        "url_id": url_id,
        "url": analysis_config.url,
        "known_passkey_site": task_config.passkey_known,
        "timeout": task_config.timeout,
        "start_time": datetime.now().isoformat(),
        "error": False,
        "api_call_detected": False,
        "fido_network_call_detected": False,
        "debug_mode": task_config.debug_mode,
        "locale": task_config.locale.value,
        "current_phase": "initial",
        "api_calls_with_rpid": [],
        "api_calls_public_key": [],
        "api_calls_federated": [],
        "api_calls_identity": [],
        "network_requests_fido": [],
        "http_errors": [],
        "workflow_errors": [],
    }

    create_folders(analysis_config, task_config)
    log_message(
        result,
        f"Starting task for URL: {analysis_config.url} with timeout {task_config.timeout}s",
    )

    def get_remaining_timeout_ms():
        """
        Calculates the remaining timeout in milliseconds.

        Returns:
            int: Remaining timeout in milliseconds.
        """
        elapsed = time.monotonic() - start_time_mono
        return max(0, (task_config.timeout - elapsed) * 1000)

    def handle_response(response: Response):
        """
        Handles HTTP responses and logs errors for non-successful responses.

        Args:
            response (Response): The Playwright Response object to handle.
        """
        if not response.ok:
            error_details = {
                "url": response.url,
                "status": response.status,
                "status_text": response.status_text,
            }
            result["http_errors"].append(error_details)
            log_message(
                result,
                f"⚠️ HTTP Error: {response.status} for {response.url}",
                level="WARN",
            )

    locale_settings = {
        "en-US": {
            "timezone_id": "America/New_York",
            "geolocation": {"latitude": 40.7128, "longitude": -74.0060},
        },
        "en-GB": {
            "timezone_id": "Europe/London",
            "geolocation": {"latitude": 51.5074, "longitude": -0.1278},
        },
        "de-DE": {
            "timezone_id": "Europe/Berlin",
            "geolocation": {"latitude": 52.5200, "longitude": 13.4050},
        },
    }

    current_locale = task_config.locale.value
    settings = locale_settings.get(current_locale, locale_settings["en-US"])

    # playwright configuration
    with sync_playwright() as p:
        browser, context, page = None, None, None
        try:
            browser = p.chromium.launch(headless=False)

            context_args = {
                "locale": current_locale,
                "timezone_id": settings["timezone_id"],
                "geolocation": settings["geolocation"],
            }
            log_message(result, f"Setting up browser context with: {context_args}")

            if task_config.debug_mode and debug_folder:
                context_args["record_video_dir"] = debug_folder

            context = browser.new_context(**context_args)

            if task_config.debug_mode and debug_folder:
                context.tracing.start(screenshots=True, snapshots=True, sources=True)

            page = context.new_page()

            # request & response handling
            page.on("response", handle_response)
            page.add_init_script(get_monkey_patch_script())
            page.on("console", lambda msg: handle_playwright_log(msg, result))

            result["current_phase"] = "loading"
            log_message(
                result, f"🧭 Phase 'loading': Navigating to {analysis_config.url}"
            )

            # remaining time check and navigate to the target URL
            remaining_ms = get_remaining_timeout_ms()
            if remaining_ms <= 0:
                raise TimeoutError("Task timeout exceeded before navigation.")
            page.goto(
                analysis_config.url, wait_until="domcontentloaded", timeout=remaining_ms
            )
            log_message(result, "Initial navigation complete.")

            # executes workflow for passkey, which should trigger api calls
            execute_passkey_workflow(page, result, analysis_config.url, task_config)

            result["current_phase"] = "final_wait"
            log_message(result, "🏁 Workflow finished. Entering final wait phase.")

            # checks if threshold is more than 5s and refresh 5s before task timeout ends, to catch possible api calls
            remaining_ms = get_remaining_timeout_ms()
            REFRESH_THRESHOLD_MS = 5000
            if remaining_ms > REFRESH_THRESHOLD_MS:
                wait_before_refresh_ms = remaining_ms - 5000
                log_message(
                    result,
                    f"⏱️ Waiting for {wait_before_refresh_ms / 1000:.2f} seconds before final refresh.",
                )
                page.wait_for_timeout(wait_before_refresh_ms)

                log_message(result, "Executing final page refresh (with 5s remaining).")
                try:
                    page.reload(wait_until="domcontentloaded", timeout=4000)
                    log_message(result, "Page reloaded. Waiting for final API calls...")
                    page.wait_for_timeout(2000)
                except PlaywrightError as e:
                    log_error(result, f"Error during final page refresh: {e}")
            elif remaining_ms > 0:
                log_message(
                    result,
                    f"Not enough time for final refresh. Waiting for remaining {remaining_ms / 1000:.2f} seconds.",
                )
                page.wait_for_timeout(remaining_ms)

        # exception catch and timeout
        except (PlaywrightError, TimeoutError) as e:
            if "timeout" in str(e).lower():
                log_error(result, f"Task timed out: {repr(e)}")
            else:
                log_error(result, f"A Playwright error occurred: {repr(e)}")
        except Exception as e:
            log_error(result, f"A critical error occurred: {repr(e)}")

        # task summary
        finally:
            results_to_check = [
                "api_calls_public_key",
                "webauthn_input_found",
                "passkey_button_found",
            ]

            if not any(result.get(key) for key in results_to_check):
                log_message(
                    result,
                    "⚠️ No Passkey related API call or Passkey element was detected during the task.",
                    level="WARNING",
                )

                if task_config.create_failed_list:
                    log_message(
                        result,
                        f"⚠️ URL failed (no API call or Passkey element). Adding to failed list: {analysis_config.url}",
                        level="WARNING",
                    )
                    write_failed_url(task_config.task_name, analysis_config.url)

            result["duration_seconds"] = time.monotonic() - start_time_mono
            result["end_time"] = datetime.now().isoformat()
            log_message(
                result,
                f"🏁 Task finished after {result['duration_seconds']:.2f} seconds.",
            )

            # cleanup
            try:
                video_path = None
                if page and not page.is_closed() and task_config.debug_mode:
                    try:
                        video_path = page.video.path()
                    except PlaywrightError as e:
                        log_message(
                            result, f"⚠️ Could not get video path: {e}", level="WARNING"
                        )

                if context and task_config.debug_mode and debug_folder:
                    safe_task_name = re.sub(
                        r"[^a-zA-Z0-9._-]", "_", result.get("task_name", "unknown_task")
                    )
                    safe_url = re.sub(
                        r"[^a-zA-Z0-9._-]", "_", result.get("url", "unknown_url")
                    )[:50]
                    trace_filename = f"{safe_task_name}_{safe_url}_trace.zip"
                    path = os.path.join(debug_folder, trace_filename)
                    context.tracing.stop(path=path)
                    log_message(result, f"⚠️ Trace file saved to: {path}")

                if context:
                    context.close()
                if browser:
                    browser.close()

                if video_path and os.path.exists(video_path):
                    safe_task_name = re.sub(
                        r"[^a-zA-Z0-9._-]", "_", result.get("task_name", "unknown_task")
                    )
                    safe_url = re.sub(
                        r"[^a-zA-Z0-9._-]", "_", result.get("url", "unknown_url")
                    )[:50]
                    video_filename = f"{safe_task_name}_{safe_url}"
                    new_video_name = f"{video_filename}.webm"
                    new_video_path = os.path.join(
                        os.path.dirname(video_path), new_video_name
                    )
                    os.rename(video_path, new_video_path)
                    log_message(result, f"⚠️ Debug video saved to: {new_video_path}")

            except Exception as e:
                log_error(result, f"Error during Playwright cleanup: {repr(e)}")

    return result
