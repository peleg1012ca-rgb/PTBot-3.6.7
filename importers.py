"""Parse uploaded captures in memory; never execute imported requests or commands."""

import base64
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit
from pt_toolkit.models import validate_url
from scope_engine import check_scope
from audit_log import redact_url
from execution import response_observations, observation
import workbench_store as store


def xml_root(data, tag):
    if len(data) > 8 * 1024 * 1024:
        raise ValueError("Import exceeds 8 MiB")
    if b"<!ENTITY" in data.upper() or b"\x00" in data:
        raise ValueError("XML entities and non-UTF8 XML are unsupported")
    root = ET.fromstring(data)
    if root.tag != tag:
        raise ValueError("Wrong XML format")
    return root


def burp_records(data):
    root = xml_root(data, "items")
    items = root.findall("item")
    if not items or len(items) > 50:
        raise ValueError("Import between 1 and 50 Burp Save items responses")
    result = []
    for item in items:
        url = item.findtext("url", "")
        validate_url(url)
        element = item.find("response")
        if element is None:
            continue
        raw = element.text or ""
        raw = (
            base64.b64decode("".join(raw.split()), validate=True)
            if element.get("base64", "false").lower() == "true"
            else raw.encode()
        )
        head, sep, body = raw.partition(b"\r\n\r\n")
        if not sep:
            head, sep, body = raw.partition(b"\n\n")
        if not sep or len(head) > 65536:
            raise ValueError("Invalid HTTP response")
        lines = head.decode("latin1").splitlines()
        status = int(lines[0].split()[1])
        if not 100 <= status <= 599:
            raise ValueError("Invalid HTTP status")
        headers = [
            tuple(p.strip() for p in line.split(":", 1))
            for line in lines[1:]
            if ":" in line
        ]
        encoded = any(
            k.lower() in ("content-encoding", "transfer-encoding")
            and v.lower() not in ("identity", "")
            for k, v in headers
        )
        complete = not encoded and len(body) <= 65536
        text = body.decode("utf8", errors="replace") if complete else ""
        result.append(
            (url, response_observations(url, status, headers, text, complete))
        )
    if not result:
        raise ValueError("No responses found")
    return result


def nmap_records(data):
    root = xml_root(data, "nmaprun")
    hosts = root.findall("host")
    if not hosts or len(hosts) > 50:
        raise ValueError("Import between 1 and 50 hosts")
    result = []
    import ipaddress

    for host in hosts:
        address = host.find("address")
        if address is None:
            continue
        ip = str(ipaddress.ip_address(address.get("addr", "")))
        ports = host.findall("./ports/port")
        if len(ports) > 1024:
            raise ValueError("Too many port records")
        items = []
        for port in ports:
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            number = int(port.get("portid", "0"))
            if not 1 <= number <= 65535:
                raise ValueError("Invalid port")
            protocol = port.get("protocol", "")
            if protocol not in ("tcp", "udp"):
                continue
            items.append(
                observation(
                    "imported_service",
                    "Imported open port",
                    "Reported by the uploaded Nmap XML; not independently checked by this application.",
                    f"{protocol}/{number}",
                )
            )
        result.append((ip, items))
    return result


def import_records(path, eid, kind, data):
    records = (
        burp_records(data)
        if kind == "burp"
        else nmap_records(data) if kind == "nmap" else None
    )
    if records is None:
        raise ValueError("Choose a supported import format")
    # Validate the entire input before writing anything.
    for target, _ in records:
        if not check_scope(path, eid, target).allowed:
            raise ValueError(
                "Every imported target must belong to this approved engagement"
            )
    ids = []
    # Stage all rows inside a single transaction to avoid partial imports.
    with store.connect(path) as c:
        from scope_engine import check_scope_connection

        c.execute("BEGIN IMMEDIATE")
        for target, items in records:
            if not check_scope_connection(c, eid, target).allowed:
                raise ValueError("Scope changed during import")
            reference = redact_url(target) if "://" in target else target
            rid = c.execute(
                "INSERT INTO investigation_runs(engagement_id,action_type,target_reference,status,finished_at) VALUES (?,?,?,'response',CURRENT_TIMESTAMP)",
                (eid, "offline_import", reference),
            ).lastrowid
            c.execute(
                "INSERT INTO run_metadata(run_id,source,summary) VALUES (?,?,?)",
                (rid, "import:" + kind, "Imported evidence; no requests were sent"),
            )
            for item in items:
                oid = c.execute(
                    "INSERT INTO observations(run_id,check_type,severity,title,explanation) VALUES (?,?,?,?,?)",
                    (
                        rid,
                        item["check"],
                        item["severity"],
                        item["title"],
                        item["detail"],
                    ),
                ).lastrowid
                if item.get("evidence"):
                    c.execute(
                        "INSERT INTO evidence_refs(observation_id,evidence_kind,reference_text) VALUES (?,?,?)",
                        (oid, "import_summary", item["evidence"]),
                    )
            ids.append(rid)
    return ids
