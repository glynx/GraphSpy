import json
import os
import re
import time
import uuid
import urllib.parse

import jwt
import requests

# This module re-implements the ROADtools/roadtx interactiveauth flow so we can
# leverage the same mature logic inside GraphSpy. Huge thanks to Dirk-jan
# Mollema for the original research and implementation.

DEFAULT_NATIVE_CLIENT_REDIRECT = "https://login.microsoftonline.com/common/oauth2/nativeclient"
FIRSTPARTY_REDIRECTS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firstparty_redirects.json")
FIRSTPARTY_REDIRECTS_URL = "https://raw.githubusercontent.com/dirkjanm/ROADtools/master/roadtx/roadtools/roadtx/firstpartyscopes.json"

_firstparty_redirects_cache = None


def _log(logger, level, message):
    if not logger:
        return
    log_method = getattr(logger, level, None)
    if callable(log_method):
        log_method(message)


def add_native_client_hint(message):
    if not message:
        return message
    lowered = message.lower()
    if "aadsts50011" in lowered and "native-client redirect" not in lowered:
        return f"{message} Please switch to a client ID that supports the native-client redirect URI or one that is included in firstparty_redirects.json"
    return message


def _is_custom_scheme_uri(uri):
    if not uri:
        return False
    parsed = urllib.parse.urlparse(uri)
    return parsed.scheme.lower() not in ("http", "https")


def _load_firstparty_redirects():
    global _firstparty_redirects_cache
    if _firstparty_redirects_cache is not None:
        return _firstparty_redirects_cache
    if not os.path.exists(FIRSTPARTY_REDIRECTS_PATH):
        try:
            redirects_data = _download_firstparty_redirects()
            _firstparty_redirects_cache = redirects_data
            return redirects_data
        except Exception:
            _firstparty_redirects_cache = {}
            return _firstparty_redirects_cache
    try:
        with open(FIRSTPARTY_REDIRECTS_PATH, "r", encoding="utf-8") as f:
            _firstparty_redirects_cache = json.load(f)
    except Exception:
        _firstparty_redirects_cache = {}
    return _firstparty_redirects_cache


def _download_firstparty_redirects():
    response = requests.get(FIRSTPARTY_REDIRECTS_URL, timeout=30)
    response.raise_for_status()
    data = response.json()
    with open(FIRSTPARTY_REDIRECTS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return data


def find_redirect_uri_for_client(client_id, interactive=False, broker=True):
    redirects_data = _load_firstparty_redirects()
    apps = redirects_data.get("apps", {})
    app = apps.get(client_id.lower()) if client_id else None
    if not app:
        return DEFAULT_NATIVE_CLIENT_REDIRECT
    preferred_interactive = app.get("preferred_interactive_redirurl")
    preferred_noninteractive = app.get("preferred_noninteractive_redirurl")
    redirect_uris = app.get("redirect_uris", [])
    if broker:
        if preferred_noninteractive:
            return preferred_noninteractive
        broker_url = f"ms-appx-web://Microsoft.AAD.BrokerPlugin/{client_id.lower()}"
        if broker_url in redirect_uris:
            return broker_url
        return DEFAULT_NATIVE_CLIENT_REDIRECT
    if interactive and preferred_interactive:
        return preferred_interactive
    if preferred_noninteractive:
        return preferred_noninteractive
    return DEFAULT_NATIVE_CLIENT_REDIRECT


def _build_native_redirect_url(original_url):
    parsed = urllib.parse.urlparse(original_url)
    new_url = DEFAULT_NATIVE_CLIENT_REDIRECT
    if parsed.query:
        new_url += f"?{parsed.query}"
    if parsed.fragment:
        new_url += f"#{parsed.fragment}"
    return new_url


def _rewrite_redirect_location(location, broker_redirect):
    if not location or not broker_redirect:
        return None
    if location.lower().startswith(broker_redirect.lower()):
        return _build_native_redirect_url(location)
    return None


def _rewrite_redirect_in_body(body_bytes, broker_redirect):
    if not broker_redirect:
        return body_bytes
    marker = 'document.location.replace("'
    lower_redirect = broker_redirect.lower()
    try:
        body_text = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        body_text = body_bytes.decode("latin-1", errors="ignore")
    changed = False
    search_index = 0
    while True:
        idx = body_text.find(marker, search_index)
        if idx == -1:
            break
        url_start = idx + len(marker)
        end = body_text.find('")', url_start)
        if end == -1:
            break
        target = body_text[url_start:end]
        if target.lower().startswith(lower_redirect):
            new_url = _build_native_redirect_url(target)
            body_text = body_text[:url_start] + new_url + body_text[end:]
            changed = True
            search_index = url_start + len(new_url)
        else:
            search_index = end + 1
    if changed:
        return body_text.encode("utf-8")
    return body_bytes


def _create_playwright_redirect_handler(target_redirect, header_builder):
    target_redirect_lower = target_redirect.lower() if target_redirect else ""

    def handler(route, request):
        if not request.url.startswith("https://login.microsoftonline.com/"):
            headers = header_builder(request.headers)
            route.continue_(headers=headers)
            return
        try:
            headers = header_builder(request.headers)
            upstream_response = route.fetch(headers=headers)
        except Exception:
            headers = header_builder(request.headers)
            route.continue_(headers=headers)
            return
        headers = dict(upstream_response.headers)
        body = upstream_response.body()
        location_key = None
        for key in list(headers.keys()):
            if key.lower() == "location":
                location_key = key
                break
        if location_key:
            new_location = _rewrite_redirect_location(headers[location_key], target_redirect)
            if new_location:
                headers[location_key] = new_location
        if request.url.startswith("https://login.microsoftonline.com/appverify") and target_redirect_lower:
            new_body = _rewrite_redirect_in_body(body, target_redirect)
            if new_body != body:
                body = new_body
                headers["content-length"] = str(len(body))
        route.fulfill(status=upstream_response.status, headers=headers, body=body)

    return handler


def _extract_error_from_url(url):
    parsed_url = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed_url.query)
    if "error" in query:
        description = urllib.parse.unquote_plus(query.get("error_description", [""])[0])
        error_message = f"[{query['error'][0]}] {description}".strip()
        return add_native_client_hint(error_message)
    return None


def _extract_error_from_html(body_text):
    if not body_text:
        return None
    aadsts_match = re.search(r"(AADSTS\d{4,}:[^<]+)", body_text)
    if aadsts_match:
        return add_native_client_hint(aadsts_match.group(1).strip())
    json_error = re.search(r'"error"\s*:\s*"([^"]+)"', body_text)
    if json_error:
        description_match = re.search(r'"error_description"\s*:\s*"([^"]+)"', body_text)
        description = description_match.group(1) if description_match else ""
        error_message = f"[{json_error.group(1)}] {description}".strip()
        return add_native_client_hint(error_message)
    return None


def _extract_code_from_html(body_text):
    if not body_text:
        return None
    code_tag_match = re.search(r"<code[^>]*>([^<]+)</code>", body_text, re.IGNORECASE)
    if code_tag_match:
        return code_tag_match.group(1).strip()
    textarea_match = re.search(r"<textarea[^>]*>([^<]+)</textarea>", body_text, re.IGNORECASE)
    if textarea_match:
        potential_code = textarea_match.group(1).strip()
        return potential_code if potential_code else None
    return None


def _extract_code_from_url(url):
    parsed_url = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed_url.query)
    if "code" in query:
        return query["code"][0]
    return None


def _click_account_tile(page, user_hint, PlaywrightTimeoutError):
    selectors = [
        "[data-test-id^='userTile']",
        "[data-test-id='accountTile']",
        "[data-test-id='userTileList'] div[role='listitem']",
        "div[data-test-id='userTileContainer']",
    ]
    try:
        if user_hint:
            hint_locator = page.get_by_text(user_hint, exact=False)
            if hint_locator.count():
                hint_locator.first.click()
                page.wait_for_timeout(500)
                return True
    except PlaywrightTimeoutError:
        pass
    for selector in selectors:
        try:
            tile_locator = page.locator(selector)
            if tile_locator.count():
                tile_locator.first.click()
                page.wait_for_timeout(500)
                return True
        except PlaywrightTimeoutError:
            continue
    return False


def _handle_additional_prompts(page, PlaywrightTimeoutError):
    try:
        stay_signed_in_button = page.locator("#idSIButton9")
        if stay_signed_in_button.count():
            button_text = stay_signed_in_button.first.inner_text().lower()
            if "yes" in button_text or "ok" in button_text:
                stay_signed_in_button.first.click()
                page.wait_for_timeout(500)
    except PlaywrightTimeoutError:
        pass


def _password_prompt_detected(page, PlaywrightTimeoutError):
    selectors = [
        "#i0118",
        "input[type='password']",
        "#passwordInput",
    ]
    for selector in selectors:
        try:
            password_locator = page.locator(selector)
            if password_locator.count():
                return True
        except PlaywrightTimeoutError:
            continue
    return False


def _handle_signin_confirmation(page, PlaywrightTimeoutError):
    prompt_texts = [
        "are you trying to sign in",
        "is this you signing in",
        "approve sign in request",
        "sign in request",
    ]
    try:
        page_text = page.inner_text("body")
    except PlaywrightTimeoutError:
        page_text = ""
    page_text_lower = page_text.lower() if page_text else ""
    should_confirm = any(prompt in page_text_lower for prompt in prompt_texts)
    if not should_confirm:
        return False
    selectors = [
        "#idBtn_Accept",
        "#idSIButton9",
        "button:has-text(\"Yes\")",
        "input[type='submit'][value='Yes']",
        "button[formaction*='Allow']",
    ]
    for selector in selectors:
        try:
            button = page.locator(selector)
            if button.count():
                button.first.click()
                page.wait_for_timeout(500)
                return True
        except PlaywrightTimeoutError:
            continue
    try:
        yes_button = page.get_by_role("button", name=re.compile("yes|allow|continue", re.IGNORECASE))
        if yes_button.count():
            yes_button.first.click()
            page.wait_for_timeout(500)
            return True
    except PlaywrightTimeoutError:
        pass
    return False


def obtain_authorization_code_playwright(
    estsauthpersistent,
    estsauth,
    client_id,
    resource,
    user_hint,
    redirect_uri,
    domain_hint,
    user_agent,
    show_browser=False,
    logger=None,
):
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError, Error as PlaywrightError
    except ImportError:
        _log(
            logger,
            "error",
            "Playwright is not installed. Install it with 'pip install playwright' and run 'playwright install chromium'.",
        )
        raise ValueError("Playwright dependency not installed. Install it with 'pip install playwright' and run 'playwright install chromium'.")
    intercept_custom_redirect = _is_custom_scheme_uri(redirect_uri)
    with sync_playwright() as p:
        browser_type = p.firefox if intercept_custom_redirect else p.chromium
        browser = browser_type.launch(headless=not show_browser)
        try:
            extra_headers = {
                "Sec-CH-UA": '" Not;A Brand";v="99", "Microsoft Edge";v="103", "Chromium";v="103"',
                "Sec-CH-UA-Mobile": "?0",
                "Sec-CH-UA-Platform": '"Windows"',
                "Sec-CH-UA-Platform-Version": '"10.0.0"',
            }
            context = browser.new_context(user_agent=user_agent)
            context.set_extra_http_headers(extra_headers)

            def _build_headers(original_headers):
                headers = original_headers.copy()
                headers["user-agent"] = user_agent
                headers["Sec-CH-UA"] = extra_headers["Sec-CH-UA"]
                headers["Sec-CH-UA-Mobile"] = extra_headers["Sec-CH-UA-Mobile"]
                headers["Sec-CH-UA-Platform"] = extra_headers["Sec-CH-UA-Platform"]
                headers["Sec-CH-UA-Platform-Version"] = extra_headers["Sec-CH-UA-Platform-Version"]
                request_cookies = headers.get("cookie", "")
                cookie_parts = []
                if estsauthpersistent:
                    cookie_parts.append(f"ESTSAUTHPERSISTENT={estsauthpersistent}")
                if estsauth:
                    cookie_parts.append(f"ESTSAUTH={estsauth}")
                if request_cookies:
                    cookie_parts.append(request_cookies)
                headers["cookie"] = "; ".join(cookie_parts)
                return headers

            if intercept_custom_redirect:
                redirect_handler = _create_playwright_redirect_handler(redirect_uri, _build_headers)
                context.route("https://login.microsoftonline.com/*", redirect_handler)

            def _header_injection_route(route, request):
                headers = _build_headers(request.headers)
                route.continue_(headers=headers)

            context.route("**/*", _header_injection_route)
            authorization_result = {"code": None, "error": None}

            def _response_handler(response):
                if not response.url.startswith("https://login.microsoftonline.com/"):
                    return
                try:
                    headers = response.headers
                except Exception:
                    headers = {}
                location = None
                for key, value in headers.items():
                    if key.lower() == "location":
                        location = value
                        break
                if location:
                    decoded_location = urllib.parse.unquote(location)
                    error = _extract_error_from_url(decoded_location)
                    if error:
                        authorization_result["error"] = error
                        return
                    code = _extract_code_from_url(decoded_location)
                    if code:
                        authorization_result["code"] = code
                        return

            context.on("response", _response_handler)
            cookies = [
                {
                    "name": "ESTSAUTHPERSISTENT",
                    "value": estsauthpersistent,
                    "domain": ".login.microsoftonline.com",
                    "path": "/",
                    "secure": True,
                    "httpOnly": True,
                }
            ]
            if estsauth:
                cookies.append(
                    {
                        "name": "ESTSAUTH",
                        "value": estsauth,
                        "domain": ".login.microsoftonline.com",
                        "path": "/",
                        "secure": True,
                        "httpOnly": True,
                    }
                )
            context.add_cookies(cookies)
            page = context.new_page()
            authorize_params = {
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": redirect_uri,
                "resource": resource,
                "state": f"{uuid.uuid4()}",
                "sso_reload": "true",
            }
            if user_hint:
                authorize_params["login_hint"] = user_hint
            if domain_hint:
                authorize_params["domain_hint"] = domain_hint
            authorize_url = f"https://login.microsoftonline.com/common/oauth2/authorize?{urllib.parse.urlencode(authorize_params)}"
            navigation_failed = False
            try:
                page.goto(authorize_url, wait_until="load")
            except PlaywrightTimeoutError:
                raise ValueError("Playwright could not load login.microsoftonline.com.")
            except PlaywrightError as e:
                _log(logger, "warning", f"Playwright navigation failed for redirect '{redirect_uri}': {e}")
                navigation_failed = True
            authorization_code = None
            last_error = None
            poll_timeout_ms = 1000
            deadline = time.time() + 60
            html_content = ""
            while time.time() < deadline:
                if _password_prompt_detected(page, PlaywrightTimeoutError):
                    raise ValueError("Browser reached the password prompt. Provide ESTS cookies for the intended user or specify a login hint.")
                if authorization_result["code"]:
                    authorization_code = authorization_result["code"]
                    break
                if authorization_result["error"]:
                    last_error = authorization_result["error"]
                    break
                try:
                    _click_account_tile(page, user_hint, PlaywrightTimeoutError)
                except PlaywrightTimeoutError:
                    pass
                _handle_signin_confirmation(page, PlaywrightTimeoutError)
                _handle_additional_prompts(page, PlaywrightTimeoutError)
                current_url = page.url
                authorization_code = _extract_code_from_url(current_url)
                if authorization_code:
                    break
                error_message = _extract_error_from_url(current_url)
                html_content = ""
                try:
                    html_content = page.content()
                except PlaywrightTimeoutError:
                    html_content = ""
                if not error_message:
                    authorization_code = _extract_code_from_html(html_content)
                    if authorization_code:
                        break
                    error_message = _extract_error_from_html(html_content)
                if error_message:
                    last_error = error_message
                    break
                page.wait_for_timeout(poll_timeout_ms)
            if not authorization_code and authorization_result["code"]:
                authorization_code = authorization_result["code"]
            if not last_error and authorization_result["error"]:
                last_error = authorization_result["error"]
            if last_error:
                raise ValueError(last_error)
            if not authorization_code:
                if navigation_failed:
                    error_message = _extract_error_from_url(current_url) or _extract_error_from_html(html_content)
                    if error_message:
                        raise ValueError(error_message)
                    raise ValueError("Failed to obtain authorization code after navigation error. Redirect URI might not be supported.")
                raise ValueError("Failed to obtain authorization code. Session cookies might be invalid or expired.")
        finally:
            try:
                browser.close()
            except Exception:
                pass
    return authorization_code


def ests_cookies_to_tokens(
    estsauthpersistent,
    estsauth,
    client_id,
    resource,
    description="",
    store_refresh_token=False,
    cookie_user=None,
    cookie_tenant=None,
    user_hint=None,
):
    if not estsauthpersistent and not estsauth:
        raise ValueError("ESTSAUTHPERSISTENT or ESTSAUTH cookie is required.")
    from . import GraphSpy as core

    redirect_uri = find_redirect_uri_for_client(client_id, interactive=False, broker=True)
    user_hint_value = user_hint if user_hint else cookie_user
    domain_hint_value = cookie_tenant if cookie_tenant else None
    user_agent = core.get_user_agent()
    show_browser = core.app.config.get("show_browser", False)
    authorization_code = obtain_authorization_code_playwright(
        estsauthpersistent,
        estsauth,
        client_id,
        resource,
        user_hint_value,
        redirect_uri,
        domain_hint_value,
        user_agent,
        show_browser,
        core.gspy_log,
    )
    if not authorization_code:
        raise ValueError("Failed to obtain authorization code. Session cookies might be invalid or expired.")
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})
    token_body = {
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code": authorization_code,
        "redirect_uri": redirect_uri,
        "resource": resource,
    }
    try:
        token_response = session.post("https://login.microsoftonline.com/common/oauth2/token", data=token_body)
    except requests.RequestException as e:
        core.gspy_log.error(f"Failed to exchange authorization code for tokens: {repr(e)}")
        raise ValueError("Failed to exchange authorization code for tokens.")
    try:
        token_json = token_response.json()
    except ValueError:
        raise ValueError("Unable to parse response from the token endpoint.")
    print(token_json)
    if token_response.status_code != 200 or "access_token" not in token_json:
        if "error" in token_json:
            error_message = f"[{token_json['error']}] {token_json.get('error_description','')}"
            error_message = add_native_client_hint(error_message)
            raise ValueError(error_message)
        raise ValueError("Token response did not contain an access token.")
    token_foci = int(token_json["foci"]) if "foci" in token_json and token_json["foci"] else 0
    if description:
        access_token_description = description
        refresh_description = description
    else:
        default_description = f"Created using ESTS cookies auth ({resource})"
        prefix_parts = []
        if cookie_user:
            prefix_parts.append(cookie_user)
        if cookie_tenant:
            prefix_parts.append(cookie_tenant)
        prefix = " / ".join(prefix_parts)
        if prefix:
            access_token_description = f"{prefix} - {default_description}"
            refresh_description = access_token_description
        else:
            access_token_description = default_description
            refresh_description = default_description
    core.save_access_token(token_json["access_token"], access_token_description)
    access_token_id = core.query_db("SELECT id FROM accesstokens where accesstoken = ?", [token_json["access_token"]], one=True)[0]
    refresh_token_id = None
    if store_refresh_token and "refresh_token" in token_json:
        decoded_accesstoken = jwt.decode(token_json["access_token"], options={"verify_signature": False})
        user = "unknown"
        if "idtyp" in decoded_accesstoken and decoded_accesstoken["idtyp"] == "user":
            user = (
                decoded_accesstoken["unique_name"]
                if "unique_name" in decoded_accesstoken
                else decoded_accesstoken["upn"]
                if "upn" in decoded_accesstoken
                else "unknown"
            )
        elif "idtyp" in decoded_accesstoken and decoded_accesstoken["idtyp"] == "app":
            user = (
                decoded_accesstoken["app_displayname"]
                if "app_displayname" in decoded_accesstoken
                else decoded_accesstoken["appid"]
                if "appid" in decoded_accesstoken
                else "unknown"
            )
        else:
            user = (
                decoded_accesstoken["unique_name"]
                if "unique_name" in decoded_accesstoken
                else decoded_accesstoken["upn"]
                if "upn" in decoded_accesstoken
                else decoded_accesstoken["app_displayname"]
                if "app_displayname" in decoded_accesstoken
                else decoded_accesstoken["oid"]
                if "oid" in decoded_accesstoken
                else "unknown"
            )
        tenant = decoded_accesstoken["tid"] if "tid" in decoded_accesstoken else "unknown"
        refresh_resource = token_json["resource"] if "resource" in token_json else resource
        core.save_refresh_token(token_json["refresh_token"], refresh_description, user, tenant, refresh_resource, token_foci)
        refresh_token_id = core.query_db("SELECT id FROM refreshtokens where refreshtoken = ?", [token_json["refresh_token"]], one=True)[0]
    return {
        "access_token_id": access_token_id,
        "refresh_token_id": refresh_token_id,
        "foci": token_foci,
    }
