import json
import base64
import binascii
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)


def decode_ndef_hex(hex_string):
    """Server-side NDEF/hex inspection and decode."""
    try:
        clean = hex_string.replace(" ", "").replace(":", "").replace("-", "").upper()
        if not all(c in "0123456789ABCDEF" for c in clean):
            return {"error": "Invalid hex string"}
        raw = bytes.fromhex(clean)
        result = {
            "hex": clean,
            "byteLength": len(raw),
            "base64": base64.b64encode(raw).decode(),
            "decimal": list(raw),
            "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in raw),
            "hexDump": _hex_dump(raw),
            "ndefRecords": _parse_ndef_bytes(raw),
        }
        return result
    except Exception as e:
        return {"error": str(e)}


def _hex_dump(data):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append({"offset": f"{i:04X}", "hex": hex_part, "ascii": ascii_part})
    return lines


def _parse_ndef_bytes(data):
    """Minimal NDEF TLV parser."""
    records = []
    i = 0
    while i < len(data):
        if data[i] == 0x00:  # NULL TLV
            i += 1
            continue
        if data[i] == 0xFE:  # Terminator TLV
            break
        if data[i] == 0x03:  # NDEF Message TLV
            i += 1
            if i >= len(data):
                break
            length = data[i]
            if length == 0xFF:
                if i + 2 >= len(data):
                    break
                length = (data[i + 1] << 8) | data[i + 2]
                i += 3
            else:
                i += 1
            msg_data = data[i : i + length]
            records.extend(_parse_ndef_message(msg_data))
            i += length
        else:
            i += 1
    return records


def _parse_ndef_message(data):
    records = []
    i = 0
    while i < len(data):
        if i >= len(data):
            break
        flags = data[i]
        mb = (flags >> 7) & 1
        me = (flags >> 6) & 1
        cf = (flags >> 5) & 1
        sr = (flags >> 4) & 1
        il = (flags >> 3) & 1
        tnf = flags & 0x07
        i += 1
        if i >= len(data):
            break
        type_length = data[i]
        i += 1
        if sr:
            if i >= len(data):
                break
            payload_length = data[i]
            i += 1
        else:
            if i + 3 >= len(data):
                break
            payload_length = (
                (data[i] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]
            )
            i += 4
        id_length = 0
        if il:
            if i >= len(data):
                break
            id_length = data[i]
            i += 1
        rec_type = data[i : i + type_length].decode("latin-1")
        i += type_length
        rec_id = data[i : i + id_length].decode("latin-1") if id_length else ""
        i += id_length
        payload = data[i : i + payload_length]
        i += payload_length
        tnf_names = {
            0: "empty",
            1: "well-known",
            2: "mime-media",
            3: "absolute-url",
            4: "external",
            5: "unknown",
            6: "unchanged",
            7: "reserved",
        }
        rec = {
            "tnf": tnf,
            "tnfName": tnf_names.get(tnf, "unknown"),
            "type": rec_type,
            "id": rec_id,
            "payloadHex": payload.hex().upper(),
            "payloadLength": len(payload),
            "payloadBase64": base64.b64encode(payload).decode(),
            "payloadAscii": "".join(chr(b) if 32 <= b < 127 else "." for b in payload),
        }
        if tnf == 1 and rec_type == "T":
            status = payload[0] if payload else 0
            lang_len = status & 0x3F
            encoding = "UTF-16" if (status >> 7) else "UTF-8"
            lang = payload[1 : 1 + lang_len].decode("ascii", errors="replace") if len(payload) > 1 else ""
            text_bytes = payload[1 + lang_len :]
            rec["parsed"] = {
                "kind": "text",
                "language": lang,
                "encoding": encoding,
                "text": text_bytes.decode(encoding.lower().replace("-", ""), errors="replace"),
            }
        elif tnf == 1 and rec_type == "U":
            prefixes = {
                0x00: "", 0x01: "http://www.", 0x02: "https://www.", 0x03: "http://",
                0x04: "https://", 0x05: "tel:", 0x06: "mailto:", 0x07: "ftp://anonymous:anonymous@",
                0x08: "ftp://ftp.", 0x09: "ftps://", 0x0A: "sftp://", 0x0B: "smb://",
                0x0C: "nfs://", 0x0D: "ftp://", 0x0E: "dav://", 0x0F: "news:",
                0x10: "telnet://", 0x11: "imap:", 0x12: "rtsp://", 0x13: "urn:",
                0x14: "pop:", 0x15: "sip:", 0x16: "sips:", 0x17: "tftp:",
                0x18: "btspp://", 0x19: "btl2cap://", 0x1A: "btgoep://",
                0x1B: "tcpobex://", 0x1C: "irdaobex://", 0x1D: "file://",
                0x1E: "urn:epc:id:", 0x1F: "urn:epc:tag:", 0x20: "urn:epc:pat:",
                0x21: "urn:epc:raw:", 0x22: "urn:epc:", 0x23: "urn:nfc:",
            }
            prefix_code = payload[0] if payload else 0
            prefix = prefixes.get(prefix_code, "")
            suffix = payload[1:].decode("utf-8", errors="replace") if len(payload) > 1 else ""
            rec["parsed"] = {"kind": "url", "url": prefix + suffix}
        records.append(rec)
        if me:
            break
    return records


def decode_uid(uid_hex):
    """Decode UID string into manufacturer and format info."""
    clean = uid_hex.replace(":", "").replace(" ", "").upper()
    manufacturers = {
        "04": "NXP Semiconductors",
        "02": "STMicroelectronics",
        "05": "Infineon Technologies",
        "07": "Texas Instruments",
        "08": "Fujitsu",
        "16": "Sony",
        "1B": "Broadcom",
        "28": "Renesas",
        "38": "Samsung",
        "3E": "Motorola",
        "56": "EM Microelectronic",
        "E0": "NXP (ISO15693)",
    }
    chip_types = {
        4: "MIFARE Classic / MIFARE Mini",
        7: "NTAG / MIFARE Ultralight / DESFire",
        10: "Triple UID Extended",
    }
    byte_len = len(clean) // 2
    first_byte = clean[:2] if len(clean) >= 2 else "00"
    manufacturer = manufacturers.get(first_byte, f"Unknown (0x{first_byte})")
    chip_type = chip_types.get(byte_len, f"Unknown ({byte_len}-byte UID)")
    bytes_list = [clean[i : i + 2] for i in range(0, len(clean), 2)]
    colon_sep = ":".join(bytes_list)
    reversed_hex = "".join(reversed(bytes_list))
    try:
        decimal_be = int(clean, 16)
        decimal_le = int(reversed_hex, 16)
    except ValueError:
        decimal_be = 0
        decimal_le = 0
    return {
        "rawHex": clean,
        "colonSeparated": colon_sep,
        "reversedHex": reversed_hex,
        "decimalBE": decimal_be,
        "decimalLE": decimal_le,
        "byteLength": byte_len,
        "manufacturer": manufacturer,
        "chipType": chip_type,
        "firstByte": f"0x{first_byte}",
    }


@app.route("/")
def index():
    uid = request.args.get("uid", "")
    data = request.args.get("data", "")
    tag_type = request.args.get("type", "")
    payload = request.args.get("payload", "")
    return render_template(
        "index.html",
        launch_uid=uid,
        launch_data=data,
        launch_type=tag_type,
        launch_payload=payload,
    )


@app.route("/api/decode", methods=["POST"])
def api_decode():
    body = request.get_json(force=True, silent=True) or {}
    hex_data = body.get("hex", "")
    uid = body.get("uid", "")
    result = {}
    if hex_data:
        result["ndef"] = decode_ndef_hex(hex_data)
    if uid:
        result["uid"] = decode_uid(uid)
    if not hex_data and not uid:
        return jsonify({"error": "Provide 'hex' or 'uid' in request body"}), 400
    return jsonify(result)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "NFCUR"})


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
