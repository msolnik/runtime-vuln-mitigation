# Verification results — <CVE-ID>

*Phase 5 output. Record the exact command, N, oracle, and observed result per cell. The report quotes this verbatim. Gate passes only if every cell is green.*

| Cell | Setup | Command | N | Oracle | Result |
|------|-------|---------|---|--------|--------|
| A | unpatched + PoC | `run_n.sh N all` | | run.sh (MODE=<...>) | ⬜ exploited every run |
| Control | unpatched + benign | `benign_suite.sh` | — | golden baseline | ⬜ baseline recorded |
| B | patched + PoC (+variants) | `run_n.sh N none` | | run.sh (same oracle) | ⬜ blocked every run |
| C | patched + benign | `benign_suite.sh` | — | vs baseline | ⬜ matches (no false positives) |

## Anti-overfitting sweep (Cell B variants)
- Variants tried (same root cause, different bytes/encoding/path): <list>
- All blocked? <yes/no>

## Evidence
- Cell A: <ASan class / signal / sentinel observed>
- Cell B: <filter-fired log line proving block at the root cause; attach confirmed>
- Cell C: <baseline diff — outputs/exit codes/latency>

## Gate
- [ ] A=exploited  [ ] B=blocked (incl. variants)  [ ] C=matches baseline  [ ] control=stable
