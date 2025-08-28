import csv, json, re, sys
from typing import Dict, Any, Tuple

PHONE_RE = re.compile(r'(?<!\d)(\d{10})(?!\d)')
AADHAR_RE = re.compile(r'(?<!\d)(\d{4})[ \-]?(\d{4})[ \-]?(\d{4})(?!\d)')
PASSPORT_RE = re.compile(r'(?<![A-Za-z0-9])([A-PR-WYa-pr-wy])[ \-]?(\d{7})(?!\d)')
UPI_RE = re.compile(r'\b([A-Za-z0-9][A-Za-z0-9.\-_]{0,})@([A-Za-z]{2,})\b')
EMAIL_RE = re.compile(r'(?i)\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b')
IPV4_RE = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')

def mask_middle(s: str, keep_start: int, keep_end: int, mask_char: str='X') -> str:
    if len(s) <= keep_start + keep_end:
        return mask_char * len(s)
    return s[:keep_start] + (mask_char * (len(s) - keep_start - keep_end)) + s[-keep_end:]

def redact_phone(val: str) -> str:
    def repl(m):
        return mask_middle(m.group(1), 2, 2)
    return PHONE_RE.sub(repl, val)

def redact_aadhar(val: str) -> str:
    def repl(m):
        start = m.group(1)
        mid = m.group(2)
        end = m.group(3)
        return f"{start} XXXX {end}"
    return AADHAR_RE.sub(repl, val)

def redact_passport(val: str) -> str:
    def repl(m):
        ch = m.group(1)
        digits = m.group(2)
        return ch + ('X' * (len(digits)-2)) + digits[-2:]
    return PASSPORT_RE.sub(repl, val)

def redact_upi_or_email_local(val: str, pattern: re.Pattern) -> str:
    
    def repl(m):
        local = m.group(1)
        domain = m.group(2)
        if len(local) <= 2:
            masked_local = 'X' * len(local)
        else:
            masked_local = local[:2] + 'X' * (len(local) - 2)
        return f"{masked_local}@{domain}"
    return pattern.sub(repl, val)

def redact_ip(val: str) -> str:
    def repl(m):
        parts = m.group(1).split('.')
        if len(parts) == 4:
            parts[-1] = 'xxx'
            return '.'.join(parts)
        return m.group(1)
    return IPV4_RE.sub(repl, val)

def redact_device_id(val: str) -> str:
    
    if len(val) <= 4:
        return 'X' * len(val)
    return 'X' * (len(val) - 4) + val[-4:]

def is_valid_ipv4(ip: str) -> bool:
    parts = ip.split('.')
    if len(parts) != 4: return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def detect_full_name(data: Dict[str, Any]) -> Tuple[bool, Dict[str, str]]:
    redactions = {}
    has_full_name = False
    if 'name' in data and isinstance(data['name'], str):
        tokens = [t for t in data['name'].strip().split() if t]
        if len(tokens) >= 2:
            has_full_name = True
            
            masked = ' '.join([t[0] + 'X' * (len(t)-1) if len(t) > 1 else 'X' for t in tokens])
            redactions['name'] = masked
    if (('first_name' in data and isinstance(data['first_name'], str) and data['first_name'].strip()) and
        ('last_name' in data and isinstance(data['last_name'], str) and data['last_name'].strip())):
        has_full_name = True
        redactions['first_name'] = data['first_name'][0] + 'X' * (len(data['first_name']) - 1) if len(data['first_name'])>0 else ''
        redactions['last_name']  = data['last_name'][0]  + 'X' * (len(data['last_name']) - 1) if len(data['last_name'])>0 else ''
    return has_full_name, redactions

def detect_email(data: Dict[str, Any]) -> Tuple[bool, Dict[str, str]]:
    redactions = {}
    found = False
    for key in ['email', 'contact', 'username']:
        val = data.get(key)
        if isinstance(val, str) and EMAIL_RE.search(val or ''):
            found = True
            redactions[key] = redact_upi_or_email_local(val, EMAIL_RE)
    return found, redactions

def detect_physical_address(data: Dict[str, Any]) -> Tuple[bool, Dict[str, str]]:
   
    redactions = {}
    addr = data.get('address')
    has_addr = isinstance(addr, str) and len(addr.strip()) >= 6 
    has_city = isinstance(data.get('city'), str) and data.get('city').strip() != ''
    has_state = isinstance(data.get('state'), str) and data.get('state').strip() != ''
    pin = str(data.get('pin_code')) if 'pin_code' in data else None
    has_pin = isinstance(pin, str) and re.fullmatch(r'\d{6}', pin.strip()) is not None
    found = has_addr and (has_city or has_state or has_pin)
    if found:
        if has_addr:
            redactions['address'] = '[REDACTED_ADDRESS]'
        if has_pin:
            redactions['pin_code'] = pin[:2] + 'XXXX'
      
        if has_city: redactions['city'] = '[REDACTED_CITY]'
        if has_state: redactions['state'] = '[REDACTED_STATE]'
    return found, redactions

def detect_device_or_ip(data: Dict[str, Any]) -> Tuple[bool, Dict[str, str]]:
    redactions = {}
    found = False
    ip = data.get('ip_address')
    if isinstance(ip, str) and is_valid_ipv4(ip):
        found = True
        redactions['ip_address'] = redact_ip(ip)
    dev = data.get('device_id')
    if isinstance(dev, str) and len(dev.strip()) > 0:
        found = True
        redactions['device_id'] = redact_device_id(dev)
    return found, redactions

def redact_standalone_strings(s: str) -> Tuple[str, bool]:
   
    found = False
    redacted = s
    before = redacted
    redacted = redact_aadhar(redacted)
    found = found or (before != redacted)
    before = redacted
    redacted = redact_passport(redacted)
    found = found or (before != redacted)
    before = redacted
    redacted = redact_phone(redacted)
    found = found or (before != redacted)
    before = redacted
   
    redacted2 = redact_upi_or_email_local(redacted, UPI_RE)
    if redacted2 != redacted:
        
        found = True
    redacted = redacted2
    return redacted, found

def process_record(raw_json: str) -> Tuple[str, bool]:
    data = {}
    try:
        data = json.loads(raw_json)
        if not isinstance(data, dict):
            data = {}
    except Exception:
        
        data = {"_raw": raw_json}

    
    pii_found = False

    
    def walk_and_redact(obj):
        nonlocal pii_found
        if isinstance(obj, dict):
            for k, v in list(obj.items()):
                if isinstance(v, str):
                    new_v, hit = redact_standalone_strings(v)
                    if hit:
                        pii_found = True
                        obj[k] = new_v
                elif isinstance(v, (int, float)):
                    
                    s = str(v)
                    new_s, hit = redact_standalone_strings(s)
                    if hit:
                        pii_found = True
                        obj[k] = new_s
                elif isinstance(v, list):
                    obj[k] = [walk_and_redact(x) for x in v]
                elif isinstance(v, dict):
                    obj[k] = walk_and_redact(v)
        return obj

    data = walk_and_redact(data)

  
    name_found, name_red = detect_full_name(data)
    email_found, email_red = detect_email(data)
    addr_found, addr_red = detect_physical_address(data)
    dev_found, dev_red = detect_device_or_ip(data)

    combinatorial_count = sum([1 if x else 0 for x in [name_found, email_found, addr_found, dev_found]])

    combinatorial_pii = combinatorial_count >= 2

    if combinatorial_pii:
        pii_found = True
        
        for k,v in {**name_red, **email_red, **addr_red, **dev_red}.items():
            data[k] = v

   
    redacted_json = json.dumps(data, ensure_ascii=False)

    return redacted_json, bool(pii_found)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector_aman_kumar_samant.py <input_csv_path>")
        sys.exit(1)

    input_csv = sys.argv[1]
    output_csv = "redacted_output_aman_kumar_samant.csv"

    with open(input_csv, newline='', encoding='utf-8') as fin, \
         open(output_csv, 'w', newline='', encoding='utf-8') as fout:
        reader = csv.DictReader(fin)
        fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            record_id = row.get('record_id')
            raw_json = row.get('data_json', '')

            redacted, is_pii = process_record(raw_json)

            writer.writerow({
                'record_id': record_id,
                'redacted_data_json': redacted,
                'is_pii': str(bool(is_pii))
            })

if __name__ == '__main__':
    main()
