#!/usr/bin/env python3
"""Opens or closes one TCP port for one IP on a Tencent Lighthouse firewall.

    lighthouse_firewall.py open  <ip> <port> <description>
    lighthouse_firewall.py close <ip> <port> <description>

Reads TC_SECRET_ID, TC_SECRET_KEY, TC_INSTANCE_ID and TC_REGION from the
environment. Uses only the standard library, so a runner needs nothing installed.

After every change it reads the rules back and fails if anything other than the
one expected rule changed. The docs don't say which fields DeleteFirewallRules
matches on, and a match on port alone would also remove the dev's own SSH rule.
"""
import datetime
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request

HOST = "lighthouse.intl.tencentcloudapi.com"
SERVICE = "lighthouse"
VERSION = "2020-03-24"
CONTENT_TYPE = "application/json; charset=utf-8"


class ApiError(Exception):
    pass


def _hmac(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def call(action, params):
    """Sends one request signed with TC3-HMAC-SHA256 and returns its Response."""
    secret_id = os.environ["TC_SECRET_ID"]
    secret_key = os.environ["TC_SECRET_KEY"]
    payload = json.dumps(params)
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = str(int(now.timestamp()))
    date = now.strftime("%Y-%m-%d")

    canonical_request = "\n".join([
        "POST",
        "/",
        "",
        f"content-type:{CONTENT_TYPE}\nhost:{HOST}\n",
        "content-type;host",
        hashlib.sha256(payload.encode("utf-8")).hexdigest(),
    ])
    scope = f"{date}/{SERVICE}/tc3_request"
    string_to_sign = "\n".join([
        "TC3-HMAC-SHA256",
        timestamp,
        scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])
    key = _hmac(("TC3" + secret_key).encode("utf-8"), date)
    key = _hmac(key, SERVICE)
    key = _hmac(key, "tc3_request")
    signature = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    request = urllib.request.Request(
        f"https://{HOST}/",
        data=payload.encode("utf-8"),
        method="POST",
        headers={
            "Authorization": (
                f"TC3-HMAC-SHA256 Credential={secret_id}/{scope}, "
                f"SignedHeaders=content-type;host, Signature={signature}"
            ),
            "Content-Type": CONTENT_TYPE,
            "Host": HOST,
            "X-TC-Action": action,
            "X-TC-Version": VERSION,
            "X-TC-Timestamp": timestamp,
            "X-TC-Region": os.environ["TC_REGION"],
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = json.load(response)
    except urllib.error.HTTPError as err:
        raise ApiError(f"{action}: HTTP {err.code}") from err
    result = body.get("Response", {})
    if "Error" in result:
        error = result["Error"]
        raise ApiError(f"{action}: {error.get('Code')}: {error.get('Message')}")
    return result


def list_rules(instance_id):
    """Returns the rules as comparable tuples."""
    result = call("DescribeFirewallRules", {"InstanceId": instance_id, "Limit": 100})
    return sorted(
        (
            rule.get("Protocol", ""),
            rule.get("Port", ""),
            rule.get("CidrBlock", ""),
            rule.get("Action", ""),
        )
        for rule in result.get("FirewallRuleSet", [])
    )


def main():
    if len(sys.argv) != 5 or sys.argv[1] not in ("open", "close"):
        sys.exit(__doc__)
    command, ip, port, description = sys.argv[1:]
    instance_id = os.environ["TC_INSTANCE_ID"]
    cidr = f"{ip}/32"
    rule = {
        "Protocol": "TCP",
        "Port": port,
        "CidrBlock": cidr,
        "Action": "ACCEPT",
        "FirewallRuleDescription": description[:64],
    }
    wanted = ("TCP", port, cidr, "ACCEPT")

    before = list_rules(instance_id)
    if command == "open":
        call("CreateFirewallRules", {"InstanceId": instance_id, "FirewallRules": [rule]})
        expected = sorted(before + [wanted])
    else:
        call("DeleteFirewallRules", {"InstanceId": instance_id, "FirewallRules": [rule]})
        expected = sorted(r for r in before if r != wanted)

    after = list_rules(instance_id)
    if after != expected:
        # Rule contents stay out of the log; counts are enough to act on.
        sys.exit(
            f"{command}: firewall rules changed unexpectedly: {len(before)} before, "
            f"{len(after)} after, {len(expected)} expected. Check the firewall in the console."
        )
    print(f"{command}: done, {len(before)} rule(s) before, {len(after)} after")


if __name__ == "__main__":
    try:
        main()
    except ApiError as err:
        sys.exit(str(err))
