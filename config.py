# config.py
import re

BLOCKED_IPS = [
    "8.8.8.8",
    "192.168.1.100"
]

BLOCKED_PORTS = [
    22,
    23,
    8080
]

MALICIOUS_REGEX_PATTERNS = [
    re.compile(r"UNION SELECT", re.IGNORECASE),
    re.compile(r"<script>alert\(", re.IGNORECASE),
    re.compile(r"exec\s+\(", re.IGNORECASE),
    re.compile(r"(\.\.\/){2,}", re.IGNORECASE),
    re.compile(r"wget\s+http", re.IGNORECASE),
    re.compile(r"powershell\.exe", re.IGNORECASE),
    re.compile(r"nc\s+-l", re.IGNORECASE),
]

KNOWN_MALICIOUS_JA3_HASHES = [
    "60c73e03126780ee6df54162e071ff1e",
    "e270e5b7c7b897f903a45a6c11b0e386",
    "0f878a2e128147d3d23d8393e25b62b1",
    "73b87968e7b172a27572352882a98f1f",
    "f18830113f98e7bb664cc0854d9b626e",
    "9bf75c324c0e6e8e84d4b267104b281f",
]

FRAGMENT_TIMEOUT = 5 # This can also go here
