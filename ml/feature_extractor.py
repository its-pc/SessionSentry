import math
from collections import Counter


def parse_browser(user_agent: str) -> tuple:
    """Extract browser name and OS from user-agent string."""
    ua = (user_agent or '').lower()

    if 'edg/' in ua or 'edge' in ua:
        browser = 'Edge'
    elif 'chrome' in ua and 'chromium' not in ua:
        browser = 'Chrome'
    elif 'firefox' in ua:
        browser = 'Firefox'
    elif 'safari' in ua and 'chrome' not in ua:
        browser = 'Safari'
    elif 'opera' in ua or 'opr/' in ua:
        browser = 'Opera'
    elif 'msie' in ua or 'trident' in ua:
        browser = 'IE'
    else:
        browser = 'Unknown'

    if 'windows' in ua:
        os_info = 'Windows'
    elif 'macintosh' in ua or 'mac os' in ua:
        os_info = 'MacOS'
    elif 'linux' in ua:
        os_info = 'Linux'
    elif 'android' in ua:
        os_info = 'Android'
    elif 'iphone' in ua or 'ipad' in ua:
        os_info = 'iOS'
    else:
        os_info = 'Unknown'

    return browser, os_info


def compute_entropy(sequence: list) -> float:
    """Compute Shannon entropy of a page sequence."""
    if not sequence:
        return 0.0
    counts = Counter(sequence)
    total = len(sequence)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)
    return round(entropy, 4)


def extract_features(session_obj, logs: list) -> dict:
    """
    Given a Session object and list of RequestLog objects,
    extract ML feature vector as a dict.
    """
    if not logs:
        return _default_features()

    logs_sorted = sorted(logs, key=lambda x: x.timestamp)

    ips = [log.ip_address for log in logs_sorted]
    unique_ips = set(ips)
    ip_change = 1 if len(unique_ips) > 1 else 0
    ip_frequency = len(unique_ips)

    browsers = [log.browser for log in logs_sorted if log.browser]
    unique_browsers = set(browsers)
    browser_change = 1 if len(unique_browsers) > 1 else 0

    os_list = [log.os_info for log in logs_sorted if log.os_info]
    unique_os = set(os_list)
    os_change = 1 if len(unique_os) > 1 else 0

    initial_ua = session_obj.user_agent or ''
    ua_changes = sum(1 for log in logs_sorted if log.user_agent and log.user_agent != initial_ua)
    cookie_reuse = 1 if ua_changes > 0 else 0

    session_start = session_obj.login_time
    last_log_time = logs_sorted[-1].timestamp
    session_duration = (last_log_time - session_start).total_seconds()
    session_duration = max(session_duration, 1)

    if len(logs_sorted) > 1:
        gaps = [(logs_sorted[i + 1].timestamp - logs_sorted[i].timestamp).total_seconds()
                for i in range(len(logs_sorted) - 1)]
        session_idle_time = max(gaps) if gaps else 0
    else:
        session_idle_time = 0

    total_requests = len(logs_sorted)
    minutes = session_duration / 60.0
    request_rate = total_requests / max(minutes, 0.01)
    request_rate = round(request_rate, 2)

    if len(logs_sorted) > 1:
        intervals = [(logs_sorted[i + 1].timestamp - logs_sorted[i].timestamp).total_seconds()
                     for i in range(len(logs_sorted) - 1)]
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        request_variance = round(variance, 4)
        click_interval_avg = round(mean_interval, 4)
        click_interval_std = round(variance ** 0.5, 4)
    else:
        request_variance = 0.0
        click_interval_avg = 0.0
        click_interval_std = 0.0

    methods = [log.request_method for log in logs_sorted if log.request_method]
    post_count = methods.count('POST')
    get_count = methods.count('GET')
    post_get_ratio = round(post_count / max(get_count, 1), 4)

    pages = [log.page for log in logs_sorted if log.page]
    page_depth = len(set(pages))
    page_sequence_entropy = compute_entropy(pages)

    admin_page_attempt = 1 if any('/admin' in (p or '') for p in pages) else 0

    direct_page_access = 0
    if pages and pages[0] not in ['/', '/login', '/register']:
        direct_page_access = 1

    hours = [log.timestamp.hour for log in logs_sorted]
    night_activity_flag = 1 if any(h < 6 or h > 23 for h in hours) else 0

    initial_ip = session_obj.ip_address
    current_ip = ips[-1] if ips else initial_ip
    ip_mismatch = 1 if current_ip != initial_ip else 0

    return {
        'ip_change': ip_change,
        'ip_frequency': ip_frequency,
        'ip_mismatch': ip_mismatch,
        'browser_change': browser_change,
        'os_change': os_change,
        'cookie_reuse': cookie_reuse,
        'session_duration': round(session_duration, 2),
        'session_idle_time': round(session_idle_time, 2),
        'request_rate': request_rate,
        'request_variance': request_variance,
        'post_get_ratio': post_get_ratio,
        'total_requests': total_requests,
        'page_depth': page_depth,
        'page_sequence_entropy': page_sequence_entropy,
        'admin_page_attempt': admin_page_attempt,
        'direct_page_access': direct_page_access,
        'click_interval_avg': click_interval_avg,
        'click_interval_std': click_interval_std,
        'night_activity_flag': night_activity_flag,
    }


def _default_features() -> dict:
    return {
        'ip_change': 0,
        'ip_frequency': 1,
        'ip_mismatch': 0,
        'browser_change': 0,
        'os_change': 0,
        'cookie_reuse': 0,
        'session_duration': 0.0,
        'session_idle_time': 0.0,
        'request_rate': 0.0,
        'request_variance': 0.0,
        'post_get_ratio': 0.0,
        'total_requests': 0,
        'page_depth': 0,
        'page_sequence_entropy': 0.0,
        'admin_page_attempt': 0,
        'direct_page_access': 0,
        'click_interval_avg': 0.0,
        'click_interval_std': 0.0,
        'night_activity_flag': 0,
    }


FEATURE_COLUMNS = list(_default_features().keys())


CORE_BEHAVIORAL_FEATURES = [
    'ip_change',
    'ip_frequency',
    'ip_mismatch',
    'browser_change',
    'os_change',
    'session_duration',
    'session_idle_time',
    'request_rate',
    'request_variance',
    'page_depth',
    'page_sequence_entropy',
    'admin_page_attempt',
    'night_activity_flag',
]


def apply_feature_settings(features: dict, enabled_map: dict) -> dict:
    """
    Disabled features are neutralized so they do not influence scoring or ML.
    """
    defaults = _default_features()
    result = {}
    for key in FEATURE_COLUMNS:
        if enabled_map.get(key, True):
            result[key] = features.get(key, defaults[key])
        else:
            result[key] = defaults[key]
    return result
