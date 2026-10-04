# CIP-A106 Lab 03: TeslaCrypt Ransomware Unpacking and Memory Analysis

Student: Perry Koko, C1126EHIT17343

This package contains the submission for CIP-A106 Laboratory 3 (packed ransomware sample, controlled unpacking, entry point analysis, memory acquisition). It holds no live malware, no unpacked executable image and no raw memory dump. The exercise archive name is provenance only; the report does not state a malware family as a finding.

## 1. Contents

| Folder or file | What it is |
|---|---|
| `01_Report/` | Technical report (DOCX and PDF): environment, packer assessment, debugger observations, memory analysis, IOC table, ATT&CK mapping, confidence, conclusion |
| `02_Evidence_Appendix/` | Evidence appendix (DOCX and PDF): labelled screenshots E01 to E64 and rebuilt text exports |
| `03_Evidence_Manifest/` | Chronological evidence manifest and findings matrix (DOCX, PDF, CSV) and a per-screenshot manifest (CSV) |
| `04_Logs/` | Evidence log (`.txt`, rebuilt) and the x32dbg log excerpt (S4, lines 86 to 160) |
| `05_Screenshots/` | The 64 screenshots, renamed in capture order, with `SHA256SUMS.txt` |
| `06_Text_Exports_Rebuilt/` | Ten text exports copied out of the VM as console text, with a note on hashes |
| `README.md` | This file |
| `PRE_PUSH_CHECKLIST.md` | Checks to run before pushing to GitHub |

## 2. Safety rules followed (and deviations)

From the brief: handle the archive and extracted files only in the isolated VM; no bridged networking, NAT, VPN, shared folders, clipboard sharing or drag and drop; do not let the sample touch real user files or external networks; snapshot before handling; record SHA-256 of the source, every unpacked copy and each memory artefact; do not upload the live executable or raw memory dump.

Deviations declared in the report (section 11): a short connected-adapter window (11:18:57 to 11:29:48 on 2026-10-03) to bring in the archive; Guest Isolation showed drag and drop and copy/paste enabled (as found); one uncontrolled run at 12:45:25 on 2026-10-03 that encrypted files inside the VM; the baseline transcript was encrypted and is not recoverable.

## 3. Lab setup used

- VMware Workstation, VM FLARE-VM (Windows 11 Pro 10.0.26200, 8 GB, 4 vCPU), network adapter Host-only with both connection checkboxes unchecked.
- Folders (inside the VM): `C:\Labs\CIP-A106-Lab03\{original,work,evidence,memory,unpacked}`.
- Tools: PEStudio 9.61, Sysinternals Strings 2.54, x32dbg (May 27 2026 build, elevated, ScyllaHide), System Informer 3.2.25113.1114, 7-Zip 23.01, PowerShell 5.1.

## 4. Recreating the lab, step by step

All commands are PowerShell in the isolated VM. Run each in a new console and redefine the variables:

```powershell
$lab = "C:\Labs\CIP-A106-Lab03"; $ev = "$lab\evidence"
```

### Task A: environment and evidence preparation
1. Confirm the adapter is Host-only with Connected and Connect at power on unchecked; Shared Folders Disabled; take the snapshot **Lab03_Clean_Baseline** before touching the archive.
2. Create folders: `New-Item -ItemType Directory -Force "$lab\original","$lab\work","$ev","$lab\memory","$lab\unpacked" | Out-Null`
3. Start a transcript (`Start-Transcript "$ev\transcript.txt"`) and record the environment: `Get-ComputerInfo | Select OsName,OsVersion,CsName`, `$PSVersionTable`.
4. Record a baseline BEFORE any execution: `Get-Process | Sort Id`, `Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run,HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`, `Get-NetAdapter`, `Get-PSDrive C`. (In the original exercise this baseline was encrypted by the sample, see section 9.)
5. Extract the archive with 7-Zip into `$lab\original`, hash each layer: `Get-FileHash <file> -Algorithm SHA256`. Expected sample SHA-256: `5343947829609F69E84FE7E8172C38EE018EDE3C9898D4895275F596AC54320D` (368,640 bytes).
6. Make the working copy and hash it: `Copy-Item "$lab\original\sample\malware sample 4\demo1_ransomware.bin" "$lab\work\demo1_ransomware.exe"; Get-FileHash "$lab\work\demo1_ransomware.exe"`
7. Snapshot **Lab03_PreDebug**.

### Task B: triage and packer assessment
1. Open the working copy in PEStudio. Record: SHA-256, sections and entropy (.data 7.648, .crt 7.883, CODE 7.860), imports (6 in 4 libraries), entry RVA 0x3C40, resources (13), debug RSDS (`E:\Tools\aolfed\release\osc.pdb`), strings count (10,696).
2. `strings64.exe -n 8 "$lab\work\demo1_ransomware.exe"` (Strings 2.54): 162 ASCII and 34 Unicode strings. Look for the absence of the payload domains and note names (they are only in the unpacked image).
3. Conclude "packed" from low import count, writable high-entropy sections with virtual size larger than raw size, and the small entry stub. Do not name a packer without a signature.

### Task C: controlled unpacking and entry point analysis
Do this only after the snapshot, in the VM, with the sample loaded in x32dbg (never double-click it).
1. Open `work\demo1_ransomware.exe` in x32dbg (elevated, ScyllaHide enabled). Run to the entry point `00403C40`.
2. Set breakpoints: `bp VirtualAlloc`, `bp VirtualProtect`, `bp CreateFileW`, `bp CreateProcessW`, `bp ExitProcess`. For each, set Log text to the arguments (for VirtualProtect, a log format such as `addr={mem;4@esp+4} size={mem;4@esp+8} prot={mem;4@esp+C}`; the exact format-string syntax depends on the x32dbg build, so check its Help) and continue.
3. Add hardware execute breakpoints with `bphws 00403C40,x` (maximum 4: the original used 00403C40, 0041EAA0, 0041FEB0, 004265E8).
4. Run. Expected: 3 VirtualAlloc hits, 6 VirtualProtect calls (addr, size, new protection):
   `0x400000 0x9E000 RW`, `0x400000 0x400 R`, `0x401000 0x2F3D0 RX (.text)`, `0x431000 0xA9C0 R (.rdata)`, `0x43C000 0x45304 RW (.data)`, `0x482000 0x2BD8 R (.reloc)`, then the hardware breakpoint hit at `004265E8` (OEP).
5. At the OEP, screenshot the Breakpoints tab (hit counts), Memory Map and Log. The Log tab accumulates across sessions; Log > Save writes `log-YYYYMMDD-HHMMSS.txt` in `C:\Tools\x64dbg\release\x32\`.
6. If the sample is allowed to continue, it writes self-copies and a Run value (`HKCU\...\Run`, `cmd.exe /c start "" "<copy>"`) and exits with code 1 under the debugger. Remove these afterwards and record their hashes.

### Task D: memory acquisition and artefact validation
1. While stopped at the OEP, open System Informer, select the process, right click, **Create dump file** (MDMP). Move it to `$lab\memory`. Hash it.
2. Validate: the first 4 bytes are `4D 44 4D 50` (MDMP); count streams, regions and modules; locate the module at `0x400000` (size 0x85000). The original validator was a C# script (`Add-Type`) because the system Python was unusable. It parses the MDMP directory, ModuleList and Memory64List, extracts the image at `0x400000`, and hashes each section.
3. Check the unpacked header: TimeDateStamp `0x56D208AF`, EntryRVA `0x265E8`, SizeOfImage `0x85000`, 4 sections (.text 0x1000, .rdata 0x31000, .data 0x3C000, .reloc 0x82000).
4. Compare string counts (ASCII and UTF-16) between the dump and the disk file for: the three domains, `.onion`, the victim ID, the Bitcoin-format address, `_RECOVERY_`, `wmic`, `vssadmin`, `CurrentVersion\Run`, `.mp3`. Expect the domains and `.onion` in the OEP dump but not on disk, and the victim ID and address only in a post-run dump.
5. Hash the extracted image and each section. Do not submit raw dumps or images.

### Task E: findings and reporting
Build the IOC table (defang domains and URLs), ATT&CK mapping with confidence, and the findings matrix (artefact, confidence, limitation). Label every statement Observed, Inferred or Not observed.

## 5. Verifying this package

```
cd 05_Screenshots
sha256sum -c SHA256SUMS.txt          # Linux / macOS / Git Bash
```
PowerShell: `Get-Content SHA256SUMS.txt | ForEach-Object { $h,$f = $_ -split '\s+',2; if ((Get-FileHash $f).Hash -ne $h) { "MISMATCH $f" } }`

## 6. Rebuilt files

The files in `06_Text_Exports_Rebuilt` and `04_Logs` were rebuilt from console text copied out of the VM. Their line endings differ from the originals, so their hashes differ; the original hashes are in the Evidence Manifest.

## 7. Known limits

See report section 11. Highlights: no packet capture; cipher not analysed; baseline lost; three extra self-copies from debug sessions S1 to S3; S2 PID and the parent of PID 7152 not captured; the full 26 KB x32dbg log is included only as an excerpt.

## 8. Handling

Keep this repository **private** until grading is finished. It contains indicators (defanged) and screenshots of a ransomware run but no executable content.

## 9. Final VM step (do after the package is downloaded and confirmed)

1. Restore the snapshot **Lab03_Clean_Baseline** (VM > Snapshot > Snapshot Manager > select > Go To).
2. In a new PowerShell window, run the baseline once and save the output as a "post-restore verification" (not a pre-execution record):
```powershell
Start-Transcript "C:\Labs\post_restore_verification.txt"
Get-Date; Get-Process | Sort-Object Id | Select-Object Id,ProcessName
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Format-List
Get-NetAdapter | Format-Table Name,Status,InterfaceDescription
Get-PSDrive C
Get-ChildItem C:\Windows -Filter *.exe -Force | Where-Object { $_.Length -eq 368640 }
Stop-Transcript
```
