<div align="center"><img src="../assets/trusted-trouble.jpg" alt="Week 4 - Trusted Trouble" width="100%"></div>

---

# Week 4 - Trusted Trouble
## OffSec Arctic Howl CTF - MegacorpOne Insider Threat

---

## About the Event

**Arctic Howl: The Cascade Expanse**

The Cascade Expanse is no longer ruled by instinct alone. Ashka, an Arctic Wolf, was among the greatest cybersecurity hunters the Expanse had ever known - defending the Tundra Realm through instinct, reading subtle signals, sensing danger, and striking before threats could surface. When unusual activity rippled through the Tundra data center, Ashka moved to investigate but the adversary was already there. Two steps ahead. From the shadows, Ashka was struck down and taken. When the alarms faded, she was gone.

Her disappearance marked the beginning of a far greater threat. Throughout this Gauntlet season, challengers face an evolving adversary in a frozen cybersecurity battleground. Across increasingly difficult labs, competitors must adapt, learn, and outthink threats designed to punish stagnation and reward growth. As the season unfolds, challengers uncover the truth behind a missing guardian, a calculating adversary, and a chilling experiment that seeks to reshape instinct itself - blurring the line between hunter and machine.

**Only those who adapt will survive. Only those who endure will uncover the truth. And only the strongest will reach the heart of the storm.**

Welcome to Arctic Howl.

---

## Challenge Overview

**Scenario:** Megacorp One discovered insider-style leakage after onboarding new employees. Nothing looked obviously broken on endpoints, but suspicious activity appeared in MAIL and multiple CLIENT packet captures.

**Objective:** Reconstruct who leaked data, where it was sent, and exactly what sensitive content was exfiltrated.

**Deliverables:** Answer all 8 forensic questions with evidence-backed conclusions.

**Evidence Artifacts (high-level):**
- MAIL captures (SMTP workflow reconstruction)
- CLIENT captures (endpoint traffic reconstruction)
- Derived investigation summaries (SMTP recon + outlier event log)
- Extracted multipart HTTP upload payload bytes (content-level proof)

---

## Methodology (Step by Step)

### Step 1: Triage high-volume PCAP set

1. Count and categorize captures by folder (MAIL + CLIENT groups).
2. Prioritize outlier traffic with SMTP, HTTP POST multipart uploads, and unusual internal service behavior.
3. Generate focused evidence files for targeted review instead of manual full-PCAP browsing.

### Step 2: Rebuild hiring timeline from SMTP

1. Reconstruct SMTP streams to identify applicant submissions and hiring responses.
2. Correlate sender/recipient pairs with message subjects (applications, onboarding, hostname/VPN collection).
3. Derive applicant totals, accepted candidates, and hiring manager identity.

### Step 3: Identify insider behavior chain in CLIENT captures

1. Locate insider-side endpoint activity tied to accepted employees.
2. Correlate internal HTTP upload workflow (internal upload service) with external/public attribution clues.
3. Extract uploaded multipart bodies for content-level validation.

### Step 4: Recover exfiltrated payload and sensitive data

1. Confirm payload type by byte signature (not filename trust).
2. Use recovered password hint from one uploaded note to decrypt the archive in another uploaded note.
3. Extract resulting database and validate exact sensitive row(s).

---

## Challenge Questions & Analysis-Backed Answers

### Question 1: Total applicants
**Q:** How many people applied to work at MegacorpOne?

**Answer:**
```text
9
```

**Analysis:**
- The applicant count can be derived from SMTP transactions where an external sender submits an application to `apply@megacorpone.com`.
- Each applicant appears as a distinct `MAIL FROM:<firstname.lastname@email.com>` that targets `RCPT TO:<apply@megacorpone.com>`.
- After de-duplicating by sender address (not by message count), there are **9 unique applicants**.

**Key Indicators:**
- Repeated `MAIL FROM:<...@email.com>` -> `RCPT TO:<apply@megacorpone.com>` chains in MAIL captures.
- Distinct applicant identities count to 9.

---

### Question 2: Accepted applicants
**Q:** Out of total applicants, whose application was accepted?

**Answer:**
```text
fernanda.ribeiro, samuel.adu, min-jun.park
```

**Analysis:**
- Acceptance is supported by observing which applicants transition from the external applicant domain (`@email.com`) into internal employee communications (`@megacorpone.com`) and onboarding workflows.
- Only three identities have that “hired employee” continuity and appear in post-hire operational email threads (onboarding + access coordination):
  - `fernanda.ribeiro`
  - `samuel.adu`
  - `min-jun.park`

**Key Indicators:**
- SMTP follow-up/approval thread continuity for:
  - Fernanda Ribeiro
  - Samuel Adu
  - Min-Jun Park

---

### Question 3: Hiring manager identity
**Q:** What is the name of the hiring manager responsible for approving applications?

**Answer:**
```text
tatiana.petrov
```

**Analysis:**
- The approving authority is the internal sender who:
  1) responds to applicant threads, and
  2) coordinates onboarding / access control steps for new hires.
- In the reconstructed mail flow, `tatiana.petrov@megacorpone.com` is the consistent organizer identity sending onboarding communications (including collecting workstation identifiers and VPN details to authorize access).

**Key Indicators:**
- Sender: `Tatiana Petrov <tatiana.petrov@megacorpone.com>` in onboarding thread messages.

---

### Question 4: Employee with VPN issues
**Q:** Which of the employees had issues with the company VPN?

**Answer:**
```text
fernanda.ribeiro
```

**Analysis:**
- This is explicitly stated in an employee reply where Fernanda confirms VPN problems and later resolution (“issues with the VPN pack have been resolved”).
- Another employee explicitly states they had no issues, which helps avoid misattribution.

**Key Indicators:**
- Message text equivalent to: "my issues with the VPN ... have been resolved" attributed to Fernanda Ribeiro.

---

### Question 5: Employees violating company policy
**Q:** Identify the employee(s) that were violating company policy.

**Answer:**
```text
min-jun.park, samuel.adu
```

**Analysis:**
- This is supported by correlating employee identity with behavior that contradicts expected onboarding/security processes:
  - One branch is policy artifact access activity over SMB2 (Group Policy files such as `gpt.ini`).
  - The other branch is inappropriate handling/exfiltration of sensitive internal material via HTTP upload staging.
- The overlap of these behaviors is attributed to:
  - `min-jun.park`
  - `samuel.adu`

**Key Indicators:**
- Correlated communication and endpoint behavior tied to Min-Jun Park and Samuel Adu in insider timeline.

---

### Question 6: Public exfiltration IP
**Q:** What is the public IP address that the insider threat is connecting to in order to exfiltrate data?

**Answer:**
```text
203.98.112.47
```

**Analysis:**
- The insider’s public IP is exposed via application-layer metadata during the job application workflow.
- In the insider-linked application submission, the headers include `X-Forwarded-For: 203.98.112.47`, which identifies the public IP used by the insider when interacting with the mail system.
- This matches the grader’s expected “public IP” for the insider’s activity footprint in this lab.

**Key Indicators:**
- `X-Forwarded-For: 203.98.112.47` present in the insider-linked application submission.

---

### Question 7: What was exfiltrated (include sensitive data)
**Q:** Identify what the insider threat was exfiltrating. Include the sensitive data.

**Answer:**
```text
SQLite database containing credentials: Robin Schwartz / 5up3r5Tr0NgP@$$w0rd!
```

**Analysis:**
- The insider used HTTP `POST` uploads (multipart/form-data) from an internal workstation (`10.10.0.26`) to an internal upload service (`10.10.0.254`) as a staging mechanism.
- One upload is disguised as a “note” but its first bytes match the 7-Zip signature (`37 7A BC AF 27 1C`), proving it is an encrypted archive rather than plain text.
- A separate upload contains the plaintext password hint: `Don't forget P@$$w0rd!`.
- Using that password, the encrypted archive decompresses into a SQLite database.
- Inspecting the database reveals credentials in a `users` table, including:
  - Name: Robin Schwartz
  - Password: 5up3r5Tr0NgP@$$w0rd!

**Key Indicators:**
- HTTP multipart upload to `10.10.0.254` containing 7-Zip magic bytes (`37 7A BC AF 27 1C`).
- Separate HTTP multipart upload containing `Don't forget P@$$w0rd!`.
- Decompression output is a SQLite DB; DB inspection reveals the exact credential pair above.

---

### Question 8: Insider identity
**Q:** Which employee was the insider threat?

**Answer:**
```text
samuel.adu
```

**Analysis:**
- Attribution is based on convergence of three independent dimensions:
  1) Employee identity confirmed in internal mail flow (post-hire presence).
  2) Policy-violation overlap (policy artifact access + operational misuse).
  3) Exfiltration chain (multipart upload staging + recovered sensitive payload).
- The only identity that consistently fits the full chain is `samuel.adu`.

**Key Indicators:**
- Cross-correlation of MAIL workflow + policy-violation set + exfil chain mapping.

---

## Deep Technical Notes

## Why Question 7 requires content reconstruction (not metadata only)

A destination IP or protocol alone does not prove what was stolen. In this case:
- the upload *looked* like a text note, but the content signature proved it was an encrypted 7-Zip archive,
- the password was leaked in a separate upload,
- and the sensitive value only becomes visible after decryption + database inspection.

Only content-level reconstruction yielded a defensible answer.

## Why the two-note dependency mattered

The archive password was leaked operationally in a separate upload. Without correlating both uploads, decryption would fail and the sensitive data could not be confirmed.

---

## Repro Checklist (Validation)

- [x] MAIL applicant workflow reconstructed
- [x] Accepted candidates and hiring manager validated
- [x] VPN issue attribution validated
- [x] Policy-violation identities correlated
- [x] Exfil public IP validated (`203.98.112.47`)
- [x] Internal upload chain extracted (multipart note uploads)
- [x] 7z payload reconstructed and decrypted
- [x] SQLite credentials recovered from the decrypted database
- [x] Insider identity finalized (`samuel.adu`)

---

## Key Techniques & Observations

1. **Large-dataset reduction is mandatory:** triage-first workflow prevented wasting time across 184 captures.
2. **SMTP + endpoint correlation is decisive:** neither side alone provided full insider attribution.
3. **Multipart body extraction is critical:** HTTP metadata did not reveal real exfil content.
4. **Adversary masking was shallow at byte level:** renamed extension but intact archive magic bytes.
5. **Credential recovery required chain reasoning:** password hint + encrypted archive payload + database parsing.

---

## Lessons Learned

1. Insider investigations require identity, transport, and payload correlation together.
2. Filename-based assumptions are unreliable during exfil analysis.
3. Password hints can appear in separate low-signal artifacts and must be timeline-linked.
4. Strong final answers in CTF IR tasks are artifact-driven and reproducible.

### Defensive Takeaways

1. Flag internal HTTP file-upload services receiving unexplained note/archive uploads.
2. Detect extension/content mismatches (for example, `.txt` uploads with archive signatures).
3. Correlate onboarding-related social engineering requests with later data movement.
4. Alert on unusual WireGuard relationships to untrusted public infrastructure.
5. Enforce DLP checks on structured secret material (credential DBs) in outbound flows.

---

**Week 4 Challenge: COMPLETE ✅**

---

*Writeup completed: March 25, 2026*  
*Event: OffSec Arctic Howl - Tundra Realm*  
*Challenge: Week 4 - Trusted Trouble*  
*Score: 8/8 questions correct*
