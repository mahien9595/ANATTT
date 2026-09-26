"""Kiểm thử các hàm phân tích/đối chiếu dữ liệu (chạy được trên mọi nền tảng,
không phụ thuộc Windows)."""
import os


# ---------- auto_capitalize ----------
def test_auto_capitalize_basic(m):
    assert m.auto_capitalize("nguyễn văn a") == "Nguyễn Văn A"


def test_auto_capitalize_preserves_spacing(m):
    # Giữ nguyên nhiều dấu cách
    assert m.auto_capitalize("a  b") == "A  B"


def test_auto_capitalize_keeps_existing_upper(m):
    assert m.auto_capitalize("CAX tri phú") == "CAX Tri Phú"


# ---------- _normalize_serial ----------
def test_normalize_serial_strips_ampersand_suffix(m):
    assert m._normalize_serial("ABC&000") == "abc"


def test_normalize_serial_removes_separators(m):
    assert m._normalize_serial("A-B_C 1") == "abc1"


def test_normalize_serial_empty(m):
    assert m._normalize_serial(None) == ""


# ---------- _fmt_size_gb ----------
def test_fmt_size_tb(m):
    assert m._fmt_size_gb(2 * 1024 ** 4) == "2.0 TB"


def test_fmt_size_gb(m):
    assert m._fmt_size_gb(500 * 1024 ** 3) == "500.0 GB"


def test_fmt_size_invalid(m):
    assert m._fmt_size_gb("x") == "Không xác định"
    assert m._fmt_size_gb(0) == "Không xác định"


# ---------- parse_vuln_file ----------
def test_parse_vuln_file(m, root):
    entries = m.parse_vuln_file(os.path.join(root, "windows_vulnerabilities.txt"))
    assert len(entries) > 100
    first = entries[0]
    assert first["cve"].startswith("CVE-")
    assert isinstance(first["kbs"], list)
    # KB phải được chuẩn hóa hoa
    for e in entries:
        for kb in e["kbs"]:
            assert kb == kb.upper()


def test_parse_vuln_file_missing(m):
    assert m.parse_vuln_file("/khong/ton/tai.txt") == []


# ---------- scan_os_vulnerabilities (logic đối chiếu, không cần Windows) ----------
def test_scan_marks_patched_by_kb(m, monkeypatch):
    monkeypatch.setattr(m, "get_installed_hotfixes", lambda: {"KB4013389"})
    monkeypatch.setattr(m, "parse_vuln_file", lambda p: [
        {"cve": "CVE-2017-0144", "name": "EternalBlue", "severity": "CRITICAL",
         "kbs": ["KB4013389"], "min_build": ""},
    ])
    assert m.scan_os_vulnerabilities("dummy", "0") == []


def test_scan_reports_unpatched(m, monkeypatch):
    monkeypatch.setattr(m, "get_installed_hotfixes", lambda: set())
    monkeypatch.setattr(m, "parse_vuln_file", lambda p: [
        {"cve": "CVE-2017-0144", "name": "EternalBlue", "severity": "CRITICAL",
         "kbs": ["KB4013389"], "min_build": ""},
    ])
    findings = m.scan_os_vulnerabilities("dummy", "0")
    assert len(findings) == 1 and "CVE-2017-0144" in findings[0]


def test_scan_patched_by_min_build(m, monkeypatch):
    monkeypatch.setattr(m, "get_installed_hotfixes", lambda: set())
    monkeypatch.setattr(m, "parse_vuln_file", lambda p: [
        {"cve": "CVE-2020-0796", "name": "SMBGhost", "severity": "CRITICAL",
         "kbs": ["KB4551762"], "min_build": "18000"},
    ])
    # Build hiện tại (19000) >= build tối thiểu đã vá -> coi như đã vá
    assert m.scan_os_vulnerabilities("dummy", "19000") == []


# ---------- parse_malware_signatures ----------
def test_parse_malware_signatures(m, root):
    fams = m.parse_malware_signatures(os.path.join(root, "malware_signatures.txt"))
    assert len(fams) > 10
    names = [f["name"] for f in fams]
    assert "WannaCry" in names
    wc = next(f for f in fams if f["name"] == "WannaCry")
    assert any(p.endswith(".exe") for p in wc["process"])


# ---------- format helpers ----------
def test_format_vuln_text_empty(m):
    out = m.format_vuln_text([])
    assert "Không phát hiện" in out[0]


def test_format_vuln_text_extracts_cve(m):
    out = m.format_vuln_text([
        "CVE-2017-0144 - EternalBlue (Mức độ: CRITICAL) - CHƯA phát hiện bản vá",
    ])
    assert "CVE-2017-0144" in out[0]


def test_format_malware_text_empty(m):
    out = m.format_malware_text([])
    assert "Không phát hiện" in out[0]


# ---------- _same_subnet ----------
def test_same_subnet(m):
    assert m._same_subnet("192.168.1.10", "192.168.1.20") is True
    assert m._same_subnet("192.168.1.10", "192.168.2.20") is False
    assert m._same_subnet("bad", "192.168.1.1") is False
