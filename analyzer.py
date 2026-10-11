"""Explainable, rule-based phishing message analysis.

This module never opens or requests URLs found in submitted messages.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

MAX_MESSAGE_LENGTH = 10_000

_URL_PATTERN = re.compile(
    r"""(?ix)
    \b(?:
        https?://[^\s<>"']+
        | www\.[^\s<>"']+
        | (?:[\w-]+\.)+[a-z]{2,}(?:/[^\s<>"']*)?
    )
    """
)
_URGENCY_PATTERN = re.compile(
    r"\b(?:act\s+now|(?:act|respond|reply|click|confirm|verify|provide|send|pay|call|text)"
    r"\s+immediately|urgent(?:ly)?|within\s+\d+\s*(?:minutes?|hours?)|"
    r"final\s+notice|expires?\s+(?:today|soon)|account\s+(?:will\s+be\s+)?"
    r"(?:suspended|locked|closed)|limited\s+time|last\s+chance|avoid\s+"
    r"(?:suspension|closure))\b",
    re.IGNORECASE,
)
_CREDENTIAL_PATTERN = re.compile(
    r"\b(?:passwords?|passcodes?|one[- ]time\s+(?:password|codes?)|"
    r"verification\s+codes?|security\s+codes?|otps?|login\s+credentials?|"
    r"sign[- ]in\s+details?|account\s+credentials?)\b",
    re.IGNORECASE,
)
_DIRECT_PASSWORD_REQUEST_PATTERN = re.compile(
    r"\b(?:i|we)\s+need\s+(?:your|the)\s+passwords?\b",
    re.IGNORECASE,
)
_AUTHORITY_PATTERN = re.compile(
    r"\b(?:(?:(?:the|your|my|our)\s+)?"
    r"(?:boss(?:es)?|managers?|supervisors?|executives?|administrators?|"
    r"directors?|ceos?|principals?)\s+"
    r"(?:wanted|wants|asked|asks|told|ordered|instructed|demanded|directed|"
    r"said|says|requested|required|requires|expected|expects)"
    r"|(?:from|on\s+behalf\s+of)\s+(?:(?:the|your|a)\s+)?"
    r"(?:boss|manager|supervisor|executive|administrator|director|ceo|principal))\b",
    re.IGNORECASE,
)
_SECRECY_PATTERN = re.compile(
    r"\b(?:do\s+not|don't|dont|never)\s+"
    r"(?:tell|inform|notify|contact|discuss)\s+"
    r"(?:anyone|anybody|everyone|(?:your|the)\s+"
    r"(?:manager|supervisor|colleagues?|coworkers?|team))\b"
    r"|\b(?:do\s+not|don't|dont|never)\s+share\s+with\s+"
    r"(?:anyone|anybody|everyone|(?:your|the)\s+"
    r"(?:manager|supervisor|colleagues?|coworkers?|team))\b"
    r"|\bkeep\s+(?:this|it|the\s+request)\s+(?:secret|confidential)\b",
    re.IGNORECASE,
)
_THREAT_PATTERN = re.compile(
    r"\b(?:(?:your\s+)?(?:job|career|life)"
    r"(?:\s+and\s+(?:your\s+)?(?:job|career|life))?\s+"
    r"(?:could\s+be\s+)?at\s+stake|"
    r"you(?:\s+will|['’]ll)\s+be\s+fired|"
    r"(?:lose|losing)\s+your\s+job|fire\s+you|"
    r"disciplinary\s+action|severe\s+consequences?|"
    r"(?:harm|hurt|injure)\s+(?:you|your\s+family))\b",
    re.IGNORECASE,
)
_TIGHT_DEADLINE_PATTERN = re.compile(
    r"\b(?:at\s+)?\d{1,2}(?::\d{2})?\s*"
    r"(?:a\.m\.|p\.m\.|am\b|pm\b)\s+sharp\b"
    r"|\b(?:by|before|no\s+later\s+than)\s+"
    r"(?:\d{1,2}(?::\d{2})?\s*(?:a\.m\.|p\.m\.|am\b|pm\b)|"
    r"today|tonight|tomorrow|end\s+of\s+day)"
    r"(?=\s|[.,!?;:]|$)",
    re.IGNORECASE,
)

_SENSITIVE_PATTERN = re.compile(
    r"\b(?:social\s+security(?:\s+number)?|ssn|date\s+of\s+birth|"
    r"bank\s+(?:account|details|information)|card\s+(?:number|details)|"
    r"credit\s+card|debit\s+card|cvv|cvc|passport\s+(?:number|details)|"
    r"tax\s+(?:id|number)|personal\s+information|identity\s+documents?)\b",
    re.IGNORECASE,
)
_MONEY_PATTERN = re.compile(
    r"\b(?:wire\s+transfer|gift\s+cards?|crypto(?:currency)?|bitcoin|"
    r"payment\s+(?:is\s+)?(?:due|required)|pay\s+(?:now|immediately)|"
    r"claim\s+(?:your\s+)?(?:prize|reward|refund)|unexpected\s+refund|"
    r"(?:won|win|winning|winner\s+of)\s+(?:a\s+)?(?:prize|reward|gift|voucher)|"
    r"claim\s+(?:it|your\s+(?:prize|reward|gift|voucher))\s+now)\b",
    re.IGNORECASE,
)
_REQUEST_VERB_PATTERN = re.compile(
    r"\b(?:click|confirm|provide|send|share|submit|enter|reply|verify|"
    r"update|reset|call|text|email|visit|log\s*in|sign\s*in|"
    r"claim|won|win|winning)\b",
    re.IGNORECASE,
)

# Avoid treating common safety warnings as requests to disclose credentials.
_CREDENTIAL_WARNING_PATTERN = re.compile(
    r"\b(?:never|do\s+not|don't|dont|should\s+not|shouldn't)\s+"
    r"(?:ever\s+)?(?:share|send|provide|give|reveal|disclose|tell|enter)\b"
    r".{0,80}\b(?:passwords?|passcodes?|otps?|verification\s+codes?|"
    r"security\s+codes?|one[- ]time\s+(?:password|codes?)|"
    r"login\s+credentials?|sign[- ]in\s+details?)\b"
    r"|\b(?:passwords?|passcodes?|otps?|verification\s+codes?|"
    r"security\s+codes?|one[- ]time\s+(?:password|codes?))\b"
    r".{0,80}\b(?:never|do\s+not|don't|dont|should\s+not|shouldn't)\s+"
    r"(?:share|send|provide|give|reveal|disclose|tell)\b",
    re.IGNORECASE,
)
_TRAILING_PUNCTUATION = ".,!?;:)]}"
_SHORTENER_HOSTS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}


class MessageInputError(ValueError):
    """Raised when submitted message input does not meet the API contract."""


def _add_indicator(indicators: list[dict[str, object]], title: str, explanation: str, points: int) -> None:
    indicators.append(
        {
            "title": title,
            "explanation": explanation,
            "points": points,
        }
    )


def _clean_url(candidate: str) -> str:
    cleaned = candidate.rstrip(_TRAILING_PUNCTUATION)
    # A URL inside parentheses can legitimately have a final closing paren;
    # remove it only when it is unmatched.
    while cleaned.endswith(")") and cleaned.count(")") > cleaned.count("("):
        cleaned = cleaned[:-1]
    return cleaned


def _parse_url(candidate: str) -> tuple[str | None, str | None]:
    """Return (hostname, problem); this only parses text and never performs I/O."""
    raw = _clean_url(candidate)
    if not raw:
        return None, "The message contains a link that could not be read as a valid web address."

    normalized = raw if re.match(r"(?i)^https?://", raw) else f"https://{raw}"
    try:
        parsed = urlsplit(normalized)
        hostname = parsed.hostname
        # Accessing .port also forces urllib to validate malformed port values.
        _ = parsed.port
    except ValueError:
        return None, "The message contains a malformed or unusual link."

    if not hostname or any(char.isspace() for char in hostname):
        return None, "The message contains a malformed or unusual link."
    if not re.fullmatch(r"[a-zA-Z0-9.-]+", hostname):
        try:
            hostname.encode("idna")
        except UnicodeError:
            return None, "The message contains a malformed or unusual link."
    return hostname.lower().rstrip("."), None


def _url_indicator(candidate: str) -> tuple[str, str, int] | None:
    raw = _clean_url(candidate)
    hostname, malformed = _parse_url(raw)
    if malformed:
        return ("Unusual link format", malformed, 16)
    assert hostname is not None

    reasons: list[str] = []
    points = 0
    scheme = urlsplit(raw if re.match(r"(?i)^https?://", raw) else f"https://{raw}").scheme.lower()

    try:
        ipaddress.ip_address(hostname.strip("[]"))
        reasons.append("the address uses a raw IP address instead of a recognizable domain")
        points += 24
    except ValueError:
        pass

    if scheme == "http":
        reasons.append("it uses unencrypted HTTP rather than HTTPS")
        points += 12

    if "xn--" in hostname:
        reasons.append("the domain contains an encoded internationalized name that can disguise look-alike characters")
        points += 22

    if hostname in _SHORTENER_HOSTS:
        reasons.append("it uses a link-shortening service, which hides the final destination")
        points += 14

    labels = hostname.split(".")
    if len(labels) >= 5:
        reasons.append("it has an unusually long chain of subdomains")
        points += 12

    if "@" in raw:
        reasons.append("it includes an @ sign, which can obscure the actual destination")
        points += 20

    if not reasons:
        return None
    explanation = "The link is worth checking because " + "; ".join(reasons) + "."
    return ("Suspicious link characteristics", explanation, min(points, 32))


def analyze_message(message: str) -> dict[str, object]:
    """Analyze a message and return an explainable, bounded risk estimate."""
    if not isinstance(message, str):
        raise MessageInputError("Message must be plain text.")

    message = message.strip()
    if not message:
        raise MessageInputError("Paste a message to analyze.")
    if len(message) > MAX_MESSAGE_LENGTH:
        raise MessageInputError(
            f"Messages must be {MAX_MESSAGE_LENGTH:,} characters or fewer."
        )

    indicators: list[dict[str, object]] = []

    has_authority = bool(_AUTHORITY_PATTERN.search(message))
    has_secrecy = bool(_SECRECY_PATTERN.search(message))
    has_threat = bool(_THREAT_PATTERN.search(message))
    has_pressured_deadline = bool(
        _TIGHT_DEADLINE_PATTERN.search(message) and (has_secrecy or has_threat)
    )
    if _URGENCY_PATTERN.search(message) or has_pressured_deadline:
        _add_indicator(
            indicators,
            "Pressure to act quickly",
            "Urgent deadlines or threats can be used to stop people from checking a request carefully.",
            18,
        )
        if has_authority:
            _add_indicator(
                indicators,
                "Pressure from a claimed authority",
                "A message claiming to come from a boss or other authority can pressure someone to comply, especially when paired with secrecy or threats.",
                10,
            )
    if has_secrecy:
        _add_indicator(
            indicators,
            "Pressure to keep a request secret",
            "Instructions to hide a request from other people can prevent independent checking.",
            12,
        )
    if has_threat:
        _add_indicator(
            indicators,
            "Threats or intimidation",
            "Threats of firing, punishment, or harm can be used to pressure someone into acting.",
            28,
        )

    if (
        _CREDENTIAL_PATTERN.search(message)
        and (
            _REQUEST_VERB_PATTERN.search(message)
            or _DIRECT_PASSWORD_REQUEST_PATTERN.search(message)
        )
        and not _CREDENTIAL_WARNING_PATTERN.search(message)
    ):
        _add_indicator(
            indicators,
            "Request for sign-in information",
            "The message asks for passwords, sign-in details, or a verification code. Legitimate support teams should not ask you to share these in a message.",
            32,
        )

    if _SENSITIVE_PATTERN.search(message) and _REQUEST_VERB_PATTERN.search(message):
        _add_indicator(
            indicators,
            "Request for sensitive personal or financial information",
            "The message asks for information such as payment-card, bank, identity, or personal details.",
            28,
        )

    if _MONEY_PATTERN.search(message):
        _add_indicator(
            indicators,
            "Unusual payment or reward language",
            "The message mentions an unexpected payment, gift card, cryptocurrency, prize, or refund. Verify it independently before taking action.",
            20,
        )

    url_candidates = [_clean_url(match.group(0)) for match in _URL_PATTERN.finditer(message)]
    url_indicators: dict[tuple[str, str], int] = {}
    for candidate in url_candidates:
        found = _url_indicator(candidate)
        if found:
            title, explanation, points = found
            key = (title, explanation)
            url_indicators[key] = max(url_indicators.get(key, 0), points)
    for (title, explanation), points in url_indicators.items():
        _add_indicator(indicators, title, explanation, points)

    score = min(100, sum(int(item["points"]) for item in indicators))
    if score >= 75:
        category = "Very high risk"
    elif score >= 50:
        category = "High risk"
    elif score >= 25:
        category = "Caution"
    else:
        category = "Low risk"

    recommendations = [
        "Do not click links or reply with personal information until you verify the request.",
        "Contact the organization using a phone number or website you already know is genuine.",
        "If you entered a password or payment details, change the password through the official site and contact your bank if needed.",
    ]
    if not indicators:
        recommendations = [
            "No common warning signs were detected, but that does not prove the message is safe.",
            "Check that the sender and any request are expected before taking action.",
            "Open a website using a saved bookmark or a known address instead of relying on a message link.",
        ]

    return {
        "score": score,
        "category": category,
        "indicators": indicators,
        "recommendations": recommendations,
    }
