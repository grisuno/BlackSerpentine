# Concepts

Nouns map atomically to file sets (EXTRACTED); verbs aggregate structural edges (INFERRED).

- `beacon` | files=2 | mentions=8 | `beacon.py`, `lazyown_minimal_c2.py`
- `bof` | files=2 | mentions=5 | `beacon.py`, `loader_wrapper.c`
- `loader` | files=2 | mentions=5 | `beacon.py`, `loader_wrapper.c`
- `con` | files=2 | mentions=2 | `beacon.py`, `lazyown_minimal_c2.py`
- `decrypt` | files=2 | mentions=2 | `beacon.py`, `lazyown_minimal_c2.py`
- `download` | files=2 | mentions=2 | `beacon.py`, `lazyown_minimal_c2.py`
- `encrypt` | files=2 | mentions=2 | `beacon.py`, `lazyown_minimal_c2.py`

## Dialectic

- Thesis: `beacon` centralizes 2 files; Antithesis: `con` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `beacon` centralizes 2 files; Antithesis: `decrypt` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `beacon` centralizes 2 files; Antithesis: `download` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `beacon` centralizes 2 files; Antithesis: `encrypt` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `bof` centralizes 2 files; Antithesis: `loader` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `con` centralizes 2 files; Antithesis: `decrypt` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `con` centralizes 2 files; Antithesis: `download` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `con` centralizes 2 files; Antithesis: `encrypt` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `decrypt` centralizes 2 files; Antithesis: `download` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `decrypt` centralizes 2 files; Antithesis: `encrypt` pulls 2 files with 2 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
