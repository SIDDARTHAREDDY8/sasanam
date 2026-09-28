"""F192 (wave-175) closure: ONE shared display schema for the approval
packet's carrier disclosures.

The finding: F191 bound ``memory_provenance[].input_carrier`` and
``attachment_carriers`` into the MAC-bound approval packet (packet
version 5), but neither the web packet panel nor the CLI decision view
rendered them — the packet digest bound what the approver never saw.

This module is the single renderer for those fields. Both human
decision surfaces — the web packet panel
(:func:`gov.approval_web._packet_panel`) and the CLI decision view
(:func:`gov.approvals._print_records`) — consume it, so packet and
display cannot drift silently again.

Design rules:

* Stdlib only, never raises on hostile input: provenance items may be
  missing keys or hold non-strings; the function degrades to explicit
  ``(unknown ...)`` markers rather than hiding the row.
* The carrier field is ALWAYS named per provenance item — even when
  ``input_carrier`` is absent (rendered as "none declared"). A field
  that is omitted when empty can silently regress into the F192 gap;
  a field that is always named makes absence visible.
* Returns plain-text display strings only; HTML escaping stays in the
  web surface, line prefixes in the CLI. There is exactly one
  normalizer of the carrier values, not two.
"""

#: Sentinel used when a record predates the F191 backstop and carries
#: no carrier field at all. Rendering it explicitly keeps pre-F191
#: records from being confused with "no audio carrier" records.
CARRIER_NONE = "none declared"


def normalize_carrier(carrier):
    """Return the display form of an ``input_carrier`` /
    ``attachment_carriers`` value. One normalizer, both surfaces.

    Never raises: non-string values are str()'d; blanks map to the
    explicit none-declared sentinel.
    """
    if carrier is None:
        return CARRIER_NONE
    try:
        text = str(carrier).strip()
    except Exception:
        return CARRIER_NONE
    return text if text else CARRIER_NONE


def provenance_display_items(packet):
    """Return the normalized display model for the packet's memory
    provenance — one dict per item, same keys every time.

    Each dict has ``mem_key``, ``principal``, ``provenance_class``,
    ``detail`` and ``input_carrier`` (the raw value; surfaces render it
    via :func:`normalize_carrier`). Non-dict items are skipped; missing
    fields degrade to explicit markers instead of disappearing.
    """
    packet = packet if isinstance(packet, dict) else {}
    items = packet.get("memory_provenance") or []
    if not isinstance(items, (list, tuple)):
        items = []
    out = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        out.append({
            "mem_key": entry.get("mem_key") or "(unknown key)",
            "principal": entry.get("principal") or "(unknown principal)",
            "provenance_class": entry.get("provenance_class") or "",
            "detail": entry.get("detail") or "",
            "input_carrier": entry.get("input_carrier"),
        })
    return out


def format_provenance_item(item):
    """Render ONE memory-provenance item as a single plain-text line.

    The carrier is always named (F192's core: absence must be visible,
    not silent). No HTML — the web surface escapes the result.
    """
    item = item if isinstance(item, dict) else {}
    carrier_txt = normalize_carrier(item.get("input_carrier"))
    detail = item.get("detail") or ""
    klass = item.get("provenance_class") or ""
    what = " — ".join(part for part in (klass, detail) if part)
    if what:
        what = " (%s)" % what
    return "%s%s — principal %s — audio carrier: %s" % (
        item.get("mem_key") or "(unknown key)",
        what,
        item.get("principal") or "(unknown principal)",
        carrier_txt,
    )


def format_memory_provenance(packet):
    """Render the packet's memory-provenance disclosure as plain text.

    Every provenance item names its ``input_carrier`` — the F192 fix.
    """
    items = provenance_display_items(packet)
    if not items:
        return ("(none disclosed — no un-elevated reads at queue time)")
    return "; ".join(format_provenance_item(item) for item in items)


def format_attachment_carriers(packet):
    """Render the packet's ``attachment_carriers`` (tool-arg audio) as
    plain text — the F192 fix's second half."""
    packet = packet if isinstance(packet, dict) else {}
    carriers = packet.get("attachment_carriers") or []
    if not isinstance(carriers, (list, tuple)):
        carriers = []
    seen = []
    for carrier in carriers:
        if carrier is None:
            continue
        try:
            text = str(carrier).strip()
        except Exception:
            continue
        if text and text not in seen:
            seen.append(text)
    if not seen:
        return CARRIER_NONE
    return ", ".join(seen)
