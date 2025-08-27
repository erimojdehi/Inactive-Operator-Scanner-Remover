import configparser
import csv
import datetime as dt
import os
import shutil
import subprocess
import smtplib
import time
import os, sys
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import List, Optional, Dict, Tuple

# ======================== Helpers ========================

def app_dir() -> Path:
    # When frozen by PyInstaller, use the EXE folder; else use script folder.
    return Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent

def get_config_path() -> Path:
    # 1) explicit env override
    env = os.environ.get("IOR_CONFIG")
    if env:
        p = Path(env)
        if p.exists():
            return p

    # 2) prefer next to EXE/script
    candidates = [
        app_dir() / "config.ini",
        Path.cwd() / "config.ini",  # if you run from a shell
        Path(r"***************local address****************"),  # fallback
    ]
    for p in candidates:
        if p.exists():
            return p

    # 3) clear error with all places listed
    tried = "\n - ".join(str(p) for p in candidates)
    raise FileNotFoundError(f"Missing config.ini. Looked in:\n - {tried}")


# ======================== Config ========================

def load_config(cfg_path: Path) -> configparser.ConfigParser:
    if not cfg_path.exists():
        raise FileNotFoundError(f"Missing config.ini at {cfg_path}")
    cfg = configparser.ConfigParser(inline_comment_prefixes=(';', '#'))
    cfg.read(cfg_path, encoding="utf-8")
    for section in ("PATHS", "SERVER", "UPLOAD", "EMAIL"):
        if section not in cfg:
            raise ValueError(f"[{section}] missing in config.ini")
    return cfg

# ======================== Email helpers ========================

EMAIL_CSS = """
<style>
  body { font-family: Arial, sans-serif; font-size: 14px; margin: 24px; }
  table { border-collapse: collapse; width: 600px; table-layout: fixed; margin-bottom: 0; }
  table + table { margin-top: 20px; }
  th { width: 200px; background-color: #f2f2f2; border: 1px solid #999; padding: 10px; font-size: 14px; text-align: left; vertical-align: top; }
  td { width: 400px; border: 1px solid #999; padding: 10px; font-size: 14px; text-align: left; vertical-align: top; word-wrap: break-word; }
  h2 { margin: 0 0 10px 0; font-size: 20px; }
  h3 { margin: 26px 0 8px 0; font-size: 18px; }
  ul { margin: 0 0 14px 18px; }
  hr { margin: 24px 0; }
</style>
"""

def build_operator_table(op: Dict[str, str]) -> str:
    return (
        "<table>"
        f"<tr><th>Operator ID</th><td>{op.get('OPER_oper_no','')}</td></tr>"
        f"<tr><th>Operator Name</th><td>{op.get('oper_name','')}</td></tr>"
        f"<tr><th>Department ID</th><td>{op.get('DEPT_dept_code','')}</td></tr>"
        f"<tr><th>Fuel Card Number</th><td>{op.get('fuel_card','')}</td></tr>"
        "</table>"
    )

def send_email_html(from_addr: str, to_addrs: List[str], subject: str, html: str) -> Tuple[bool, Optional[str]]:
    try:
        msg = MIMEMultipart()
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)
        msg["Subject"] = subject
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP("***********", 25, timeout=30) as s:
            s.starttls()
            s.send_message(msg)
        return True, None
    except Exception as e:
        return False, str(e)

# ======================== CSV & XML ========================

EXPECTED_COLS = ["OPER_oper_no", "oper_name", "DEPT_dept_code", "fuel_card"]

def read_records(csv_path: Path) -> List[Dict[str, str]]:
    """Read CSV into list of dicts with expected keys."""
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.reader(f))
    if not rows:
        return []

    first_row = rows[0]
    lower = [c.strip().lower() for c in first_row]
    header_aliases: Dict[str, List[str]] = {
        "OPER_oper_no": ["oper_oper_no", "oper no", "oper_no", "operator id", "oper id", "id"],
        "oper_name": ["oper_name", "operator name", "name"],
        "DEPT_dept_code": ["dept_dept_code", "department id", "dept id", "dept_code", "dept code"],
        "fuel_card": ["fuel_card", "fuel card", "fuelcard", "fuel card number"],
    }

    def map_header_indices() -> Dict[str, int]:
        idx_map: Dict[str, int] = {}
        for idx, name in enumerate(lower):
            for key, aliases in header_aliases.items():
                if name in aliases:
                    idx_map.setdefault(key, idx)
        return idx_map if all(k in idx_map for k in EXPECTED_COLS) else {}

    header_map = map_header_indices()
    if header_map:
        data_rows = rows[1:]
    else:
        header_map = {
            "OPER_oper_no": 0,
            "oper_name": 1 if len(first_row) > 1 else 0,
            "DEPT_dept_code": 2 if len(first_row) > 2 else 0,
            "fuel_card": 3 if len(first_row) > 3 else 0,
        }
        data_rows = rows

    def safe(r, idx): return (r[idx].strip() if idx is not None and idx < len(r) else "")

    out: List[Dict[str, str]] = []
    for r in data_rows:
        if not r:
            continue
        rec = {
            "OPER_oper_no": safe(r, header_map["OPER_oper_no"]),
            "oper_name": safe(r, header_map["oper_name"]),
            "DEPT_dept_code": safe(r, header_map["DEPT_dept_code"]),
            "fuel_card": safe(r, header_map["fuel_card"]),
        }
        if rec["OPER_oper_no"]:
            out.append(rec)
    return out

def parse_operator_ids_from_csv(csv_path: Path) -> List[str]:
    return [rec["OPER_oper_no"] for rec in read_records(csv_path)]

def write_inactive_xml(csv_path: Path, xml_path: Path):
    """Write Excel 2003 XML per your FA template."""
    operator_ids = parse_operator_ids_from_csv(csv_path)
    if not operator_ids:
        raise ValueError("No operator IDs found.")

    ns0 = 'xmlns="urn:schemas-microsoft-com:office:spreadsheet"'
    nso = 'xmlns:o="urn:schemas-microsoft-com:office:office"'
    nsx = 'xmlns:x="urn:schemas-microsoft-com:office:excel"'
    nss = 'xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"'
    nsh = 'xmlns:html="http://www.w3.org/TR/REC-html40"'

    def cell_str(v: str, style: str = "") -> str:
        style_attr = f' ss:StyleID="{style}"' if style else ""
        return f'    <Cell{style_attr}><Data ss:Type="String">{v}</Data></Cell>'
    def cell_num(v: str, style: str = "") -> str:
        style_attr = f' ss:StyleID="{style}"' if style else ""
        return f'    <Cell{style_attr}><Data ss:Type="Number">{v}</Data></Cell>'

    rows_xml: List[str] = []
    rows_xml.append('   <Row ss:AutoFitHeight="0">')
    rows_xml.append(cell_num("2022", "s63"))
    rows_xml.append(cell_str("101:2", "s63"))
    rows_xml.append(cell_str("103:32", "s63"))
    rows_xml.append(cell_str("104:2", "s63"))
    rows_xml.append(cell_str("106:10", "s63"))
    rows_xml.append('   </Row>')

    for op in operator_ids:
        rows_xml.append('   <Row ss:AutoFitHeight="0">')
        rows_xml.append(cell_str("[u:1]"))
        rows_xml.append(cell_num(op) if op.isdigit() else cell_str(op))
        rows_xml.append(cell_str("N"))
        rows_xml.append(cell_str(""))
        rows_xml.append(cell_str(""))
        rows_xml.append('   </Row>')

    expanded_rows = 1 + len(operator_ids)
    utc_now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    xml_lines = [
        '<?xml version="1.0"?>',
        '<?mso-application progid="Excel.Sheet"?>',
        f'<Workbook {ns0} {nso} {nsx} {nss} {nsh}>',
        ' <DocumentProperties xmlns="urn:schemas-microsoft-com:office:office">',
        '  <Author>InactiveOperatorRemover</Author>',
        f'  <Created>{utc_now}</Created>',
        '  <Version>16.00</Version>',
        ' </DocumentProperties>',
        ' <ExcelWorkbook xmlns="urn:schemas-microsoft-com:office:excel">',
        '  <ProtectStructure>False</ProtectStructure>',
        '  <ProtectWindows>False</ProtectWindows>',
        ' </ExcelWorkbook>',
        ' <Styles>',
        '  <Style ss:ID="Default" ss:Name="Normal"><Alignment ss:Vertical="Bottom"/><Font ss:FontName="Calibri" ss:Size="11"/></Style>',
        '  <Style ss:ID="s63"><NumberFormat ss:Format="@"/></Style>',
        ' </Styles>',
        ' <Worksheet ss:Name="Work Order Center">',
        f'  <Table ss:ExpandedColumnCount="5" ss:ExpandedRowCount="{expanded_rows}" x:FullColumns="1" x:FullRows="1">',
        '   <Column ss:Index="2" ss:Width="97.5"/>',
        '   <Column ss:AutoFitWidth="0" ss:Width="84"/>',
        '   <Column ss:AutoFitWidth="0" ss:Width="246.75"/>',
    ] + rows_xml + [
        '  </Table>',
        ' </Worksheet>',
        '</Workbook>',
    ]

    xml_path.parent.mkdir(parents=True, exist_ok=True)
    xml_path.write_text("\n".join(xml_lines), encoding="utf-8")

# ======================== FA logs & utility ========================

def find_latest_txt(root: Path) -> Optional[Path]:
    if not root.exists():
        return None
    cands = [p for p in root.rglob("*.txt") if p.is_file()]
    return max(cands, key=lambda p: p.stat().st_mtime) if cands else None

def append_full_loader_log(program_log: Path, loader_txt: Optional[Path]):
    with program_log.open("a", encoding="utf-8") as out:
        out.write("\n=== FADataLoader LOG (copied) ===\n")
        if not loader_txt:
            out.write("(No .txt log found)\n")
            return
        out.write(f"Source: {loader_txt}\n----- BEGIN -----\n")
        out.write(loader_txt.read_text(encoding="utf-8", errors="replace"))
        out.write("\n----- END -----\n")

def remove_old_files(dir_path: Path, pattern: str, days: int) -> int:
    """Return how many files were removed."""
    if days <= 0 or not dir_path.exists():
        return 0
    cutoff = (dt.datetime.now() - dt.timedelta(days=days)).timestamp()
    removed = 0
    for p in dir_path.glob(pattern):
        try:
            if p.is_file() and p.stat().st_mtime < cutoff:
                p.unlink()
                removed += 1
        except Exception:
            pass
    return removed

# ======================== Main ========================

def main():
    cfg_path = get_config_path()
    cfg = load_config(cfg_path)

    base_dir = Path(cfg["PATHS"]["base_dir"])
    input_dir = base_dir / "Inactive_Operators Input"
    dataload_dir = base_dir / "DataLoad_21.1.x"
    program_logs_dir = base_dir / "logs"
    emails_dir = base_dir / "Emails"
    fa_logs_2022 = dataload_dir / "logs" / "2022"

    retain_days = (
        int(cfg["RETENTION"].get("days", cfg["RETENTION"].get("retain_days", "30")))
        if "RETENTION" in cfg else 30
    )

    stamp = dt.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_path = program_logs_dir / f"{stamp}.txt"
    program_logs_dir.mkdir(parents=True, exist_ok=True)

    # Checklist fields we’ll fill as we go (strings only; no UNC paths)
    checklist: List[str] = []
    email_footer_line = "FAILED (did not run)"
    email_sent = False
    email_error: Optional[str] = None

    # Defaults for email content
    new_ops_records: List[Dict[str, str]] = []
    when_str = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    note_str = "No input file found."
    subject_status = "ISSUE"

    # === Step 1: copy & name input ===
    src_csv = Path(r"***************local address****************") / "InactiveOperators.csv"
    dst_csv = input_dir / f"InactiveOperators_{stamp}.csv"
    input_dir.mkdir(parents=True, exist_ok=True)

    src_found = src_csv.exists()
    if src_found:
        try:
            shutil.copy2(src_csv, dst_csv)
            removed_inputs = remove_old_files(input_dir, "InactiveOperators_*.csv", retain_days)
            checklist.append(f"Input file copied: {dst_csv.name}")
            if removed_inputs:
                checklist.append(f"Removed old input files older than {retain_days} days: {removed_inputs}")
        except Exception as e:
            checklist.append(f"Input file copy failed: {e}")
            src_found = False
    else:
        checklist.append("No input file found")

    # === Step 2: detect changes (vs previous file) ===
    if src_found:
        try:
            today_records = read_records(dst_csv)
            prev_files = sorted([p for p in input_dir.glob("InactiveOperators_*.csv") if p != dst_csv],
                                key=lambda p: p.stat().st_mtime, reverse=True)
            prev_ids = [r["OPER_oper_no"] for r in read_records(prev_files[0])] if prev_files else []
            prev_set = set(prev_ids)
            new_ops_records = [r for r in today_records if r["OPER_oper_no"] not in prev_set]
            checklist.append(f"New inactive operators detected: {len(new_ops_records)}")
            note_str = f"{len(new_ops_records)} new inactive operator(s) detected." if new_ops_records else "No new inactive operators since the previous run."
            subject_status = "SUCCESS"  # provisional; will finalize after FA confirmation
        except Exception as e:
            checklist.append(f"Change detection failed: {e}")
            note_str = "Change detection failed."
            subject_status = "ISSUE"

    # === Step 3: XML generation ===
    xml_generated = False
    xml_path = dataload_dir / "InactiveOperators.xml"
    if src_found:
        try:
            write_inactive_xml(dst_csv, xml_path)
            xml_generated = True
            checklist.append("XML generated: InactiveOperators.xml")
        except Exception as e:
            checklist.append(f"XML generation failed: {e}")
            subject_status = "ISSUE"
    else:
        checklist.append("XML generation skipped (no input)")

    # === Step 4: write runfile.bat ===
    try:
        dataload_dir.mkdir(parents=True, exist_ok=True)
        runfile = dataload_dir / "runfile.bat"
        host, port = cfg["SERVER"]["host"], cfg["SERVER"]["port"]
        user, pw = cfg["UPLOAD"]["fadataloader_user"], cfg["UPLOAD"]["fadataloader_pass"]
        bat = (
            f"@echo off\r\nsetlocal\r\npushd \"{dataload_dir}\"\r\n"
            f"FADATALOADER.EXE -n \"10\" -l \"logs\" -a \"{host}:{port}\" -u \"{user}\" -p \"{pw}\" -i \"InactiveOperators.xml\"\r\n"
            "popd\r\nendlocal\r\n"
        )
        runfile.write_text(bat, encoding="utf-8")
        checklist.append("Data loader command prepared")
    except Exception as e:
        checklist.append(f"Data loader command failed to write: {e}")
        subject_status = "ISSUE"

    # === Step 5: run FA (new console) + confirm with processed marker ===
    upload_confirmed = False
    fa_confirmation_line = "FAILED (did not run)"
    if xml_generated and (dataload_dir / "FADATALOADER.EXE").exists():
        try:
            processed_marker = dataload_dir / "InactiveOperators-processed.txt"
            # remove stale marker
            if processed_marker.exists():
                try:
                    processed_marker.unlink()
                except Exception:
                    pass

            flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
            # do not set cwd to UNC; the .bat does pushd
            result = subprocess.run(["cmd.exe", "/c", str(runfile)],
                                    creationflags=flags, timeout=300)

            exit_code = result.returncode
            if exit_code == 0:
                # wait up to 90s for fresh processed marker
                deadline = time.time() + 90
                found = False
                nonempty = False
                while time.time() < deadline:
                    if processed_marker.exists():
                        found = True
                        try:
                            nonempty = processed_marker.stat().st_size > 0
                        except Exception:
                            nonempty = False
                        break
                    time.sleep(3)

                upload_confirmed = (found and nonempty)
                if upload_confirmed:
                    fa_confirmation_line = "SUCCESS"
                else:
                    if not found:
                        fa_confirmation_line = "FAILED"
                    elif not nonempty:
                        fa_confirmation_line = "FAILED"
            else:
                fa_confirmation_line = f"FAILED (exit code {exit_code})"
        except Exception as e:
            fa_confirmation_line = f"FAILED (exception while running loader: {e})"
    elif not xml_generated:
        fa_confirmation_line = "SKIPPED (no input/XML not generated)"
    else:
        fa_confirmation_line = "FAILED (FADATALOADER.EXE not found)"

    # Finalize subject status with FA outcome
    if fa_confirmation_line.startswith("SUCCESS"):
        subject_status = "SUCCESS"
    else:
        subject_status = "ISSUE"

    # Record concise FA line to checklist
    checklist.append(f"Data loader: {fa_confirmation_line}")

    # === Step 6: build & save email HTML (always) and send (always) ===
    emails_dir.mkdir(parents=True, exist_ok=True)

    # Build management checklist (short, no paths)
    checklist_html = "<ul>" + "".join(f"<li>{line}</li>" for line in checklist) + "</ul>"

    # Build note text
    note = (
        f"{len(new_ops_records)} new inactive operator(s) detected."
        if new_ops_records
        else "No new inactive operators since the previous run."
    )

    # Operator detail tables (only if new operators exist)
    ops_html = "".join(build_operator_table(op) for op in new_ops_records) if new_ops_records else ""

    # Build clean email (no checklist_html)
    email_html = (
        f"<!DOCTYPE html><html><head>{EMAIL_CSS}</head><body>"
        f"<h2>Inactive Operator Remover — Run Report</h2>"
        f"<p>Date: {when_str}</p>"
        f"<p>{note}</p>"
        f"{ops_html}"
        f"<hr><h3>DataLoader Confirmation</h3>"
        f"<p>{fa_confirmation_line}</p>"
        f"</body></html>"
    )

    email_file = emails_dir / f"InactiveOperators_EMAIL_{stamp}.html"
    try:
        email_file.write_text(email_html, encoding="utf-8")
        # Retention for Emails
        removed_emails = remove_old_files(emails_dir, "InactiveOperators_EMAIL_*.html", retain_days)
        if removed_emails:
            checklist.append(f"Removed old email reports older than {retain_days} days: {removed_emails}")
    except Exception as e:
        checklist.append(f"Email HTML save failed: {e}")

    # Send email (always)
    from_addr = cfg["EMAIL"]["from_address"].strip()
    recips = [x.strip() for x in cfg["EMAIL"]["recipients"].split(",") if x.strip()]
    subject = f"[Inactive Operators] Report — {when_str} — {subject_status} — {len(new_ops_records)} new"
    email_sent, email_error = send_email_html(from_addr, recips, subject, email_html)
    if email_sent:
        checklist.append("Email report generated and sent")
    else:
        checklist.append(f"Email send failed: {email_error}")

    # === Step 7: write concise program log, then append FA txt log block ===
    # Retention for Inputs and Logs
    removed_inputs_2 = remove_old_files(input_dir, "InactiveOperators_*.csv", retain_days)
    removed_logs = remove_old_files(program_logs_dir, "*.txt", retain_days)

    # Only add housekeeping lines if not already added
    if removed_inputs_2:
        checklist.append(f"Removed old input files older than {retain_days} days: {removed_inputs_2}")
    if removed_logs:
        checklist.append(f"Removed old logs older than {retain_days} days: {removed_logs}")

    # Write succinct management log
    mgmt_log = (
        f"Inactive Operator Remover — Run Report\n"
        f"Date: {when_str}\n\n"
        + "\n".join(f"• {line}" for line in checklist)
        + "\n"
    )
    log_path.write_text(mgmt_log, encoding="utf-8")

    # Append FADataLoader .txt (unchanged) from ...\\logs\\2022
    append_full_loader_log(log_path, find_latest_txt(fa_logs_2022))

if __name__ == "__main__":
    main()


