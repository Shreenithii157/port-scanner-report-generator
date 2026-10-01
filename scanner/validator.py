import ipaddress
import re


def validate_target(target):

    target = target.strip()

    if not target:
        return False

    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    return bool(re.match(domain_pattern, target))