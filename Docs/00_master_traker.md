# 0xGrimoire — Master Build Tracker

Check off each item as completed. Do not skip ahead in a phase — later phases depend on earlier ones being real and working, not stubbed.

---

## Phase 1 — Data Foundation (ingestion/)
Everything downstream depends on this existing and being correct.

- [ ] `ingestion/sources/nvd.py` — pull CVE + CVSS + CPE + CWE (bundled in NVD response)
- [ ] `ingestion/sources/epss.py` — pull EPSS scores
- [ ] `ingestion/sources/exploitdb.py` — parse Exploit-DB CSV export
- [ ] `ingestion/sources/metasploit.py` — parse local Metasploit module index
- [ ] `ingestion/sources/kev.py` — pull CISA KEV catalog
- [ ] `ingestion/crosswalks/cwe_to_attack.py` — static CWE→ATT&CK technique table
- [ ] `ingestion/crosswalks/cwe_to_owasp.py` — static CWE→OWASP Top 10 table
- [ ] `ingestion/join.py` — merges all sources into one record per CVE (see schema in `docs/milestones/01_schema.md`)
- [ ] Sanity check: spot-check 5-10 known CVEs manually, confirm joined record is accurate
- **Milestone:** `data/processed/cve_store.json` (or DB) exists, populated, joined, and manually verified for a handful of CVEs.

---

## Phase 2 — Retrieval Pipeline (retrieval/)
Depends on Phase 1's store existing.

- [ ] `retrieval/dictionary/canonical_products.yaml` — seed with common web/service products (Apache, nginx, OpenSSH, common CMSs)
- [ ] `retrieval/tier1_clean.py` — regex OS-noise stripping + dictionary lookup → (product, version) or "unrecognized"
- [ ] `retrieval/tier2_deterministic.py` — CPE exact/range match against the store
- [ ] `retrieval/tier3_semantic.py` — embedding fallback (only fires if Tier 2 empty)
- [ ] `retrieval/rank.py` — composite scoring (KEV boost + EPSS + exploit-availability + CVSS)
- [ ] Test against `tests/fixtures/banners.csv` (raw banner → expected product/version/CVE)
- **Milestone:** given a raw banner string, the pipeline returns ranked, tiered, confidence-flagged CVE candidates — correct on your test fixtures.

---

## Phase 3 — Generation Harness (generation/)
Depends on Phase 2 producing real candidate data to generate from.

- [ ] Define Pydantic schema (`Finding`, `Verdict` enum) per `docs/milestones/01_schema.md`
- [ ] Wire up `instructor` + local model (Ollama/Qwen2.5)
- [ ] System prompt: strict grounding, no parametric-memory answers, explicit "no_match_found" instruction
- [ ] Post-generation validator: citation must exist in retrieved candidates, or reject/flag
- [ ] Manual test: run 10-15 known findings through, check for hallucination by hand
- **Milestone:** given ranked candidates, the model reliably returns schema-valid, grounded `Finding` objects — spot-checked manually.

---

## Phase 4 — Report Builder (report/)
Depends on Phase 3's validated Finding objects.

- [ ] `report/templates/finding.md.j2` — per-finding template (CVE detail, CVSS/EPSS/KEV context, ATT&CK/OWASP labels, remediation)
- [ ] `report/templates/executive_summary.md.j2` — built from aggregate stats, not free LLM synthesis
- [ ] `report/build.py` — assembles full report: cover/scope, exec summary, prioritized action table, per-asset findings, appendix
- [ ] Explicit "manual verification/evidence" placeholder section per finding
- [ ] Optional stretch: Markdown → PDF export
- **Milestone:** a full, real-looking Markdown report generated end-to-end from a sample recon input.

---

## Phase 5 — API + Wiring (api/)
Depends on Phases 1-4 all working independently first.

- [ ] FastAPI endpoint: accepts raw recon text + optional labels, runs full pipeline, returns report
- [ ] Scheduled ingestion job (cron or simple scheduler) to refresh Phase 1's store periodically
- [ ] Basic error handling (unparseable input, no matches at all, model/API failures)
- **Milestone:** one API call, from raw recon text to finished report, works end-to-end.

---

## Phase 6 — Evaluation & Benchmarking (tests/)
Can start in parallel with Phase 2 once fixtures exist, but final numbers come after Phase 4-5 are done.

- [ ] Finalize `tests/fixtures/banners.csv` — ground-truth set (banner → expected product/version/CVE)
- [ ] Measure: parsing accuracy (Tier 1), retrieval precision/recall (Tier 2/3), hallucination rate (Phase 3 output vs ground truth)
- [ ] Write results into README, same discipline as Project 1's benchmark section
- **Milestone:** real, documented accuracy/hallucination numbers, not vibes.

---

## Phase 7 — Deployment & Docs
Last, deliberately — matches the "short-lived EC2 window" cost-conscious pattern from Project 1.

- [ ] Docker Compose for the full stack
- [ ] Short-lived EC2 deploy window (1-2 days), capture screenshots/demo evidence
- [ ] Architecture diagram
- [ ] README + case study writeup
- **Milestone:** documented, demoed, screenshots captured, instance torn down.

---

## Notes / Parking Lot
*(Use this space for ideas or issues that come up mid-build but shouldn't derail the current phase — write it here, keep moving.)*

-
