## Project Structure
```
ZIDS/
├─ client/
│  ├─ offline/
│  │  └─ param_setup.py                # Step 0 — GOT: base OT/extension setup
│  │                                     # API: generate_ot_keys(kappa) -> (pk, sk)
│  ├─ online/
│  │  ├─ ot_query_builder.py           # Step 6 — QOT: build 1-of-256 OT queries per input symbol
│  │  │                                   # API: build_queries(pk, x_bytes, n) -> [q_1..q_n]
│  │  └─ gdfa_evaluator.py             # Step 8 — evaluate transited path on garbled DFA
│  │                                      # API: eval(gdfa_stream, keys_seq, outmax, cmax) -> 0 or attack_id
│  └─ io/
│     └─ payload_reader.py             # Read suspicious payload bytes
│
├─ server/
│  ├─ offline/
│  │  ├─ rules_to_dfa/
│  │  │  ├─ snort_parser.py            # Step 1 — parse Snort rules (content, pcre) → regexes
│  │  │  ├─ regex_to_dfa.py            # Step 1 — regex→DFA, plus chaining with ε as in paper
│  │  │  └─ chain_rules.py             # Step 1 — chain content/pcre; OR as required
│  │  ├─ dfa_combiner.py               # Step 2 — OR all rule DFAs, label accepting states with attack IDs
│  │  ├─ dfa_optimizer/
│  │  │  ├─ minimization.py            # Step 3 — DFA minimization (Watson–Daciuk/Hopcroft)
│  │  │  ├─ sparsity_analysis.py       # Step 3 — compute (outmax, cmax), per-state char groups
│  │  │  └─ char_grouping.py           # Step 3 — build groups C_j[z] for ASCII alphabet
│  │  ├─ key_generator.py              # Step 4 — fresh symmetric keys for garbling, per row/state/group
│  │  ├─ gdfa_builder.py               # Step 5 — build permuted & garbled DFA matrix (GDFA)
│  │  │                                   # Supports semi-pipelined row streaming to reduce memory
│  │  └─ export/
│  │     └─ gdfa_packager.py           # Package {PER, GDFA rows, outmax, cmax, params} for client
│  ├─ online/
│  │  └─ ot_response_builder.py        # Step 7 — AOT: answer 1-of-256 queries (wrap 8×1-of-2 + extension)
│  │                                      # API: answer(pk, q_vec, S_table_bytes) -> a_vec
│  └─ io/
│     └─ rule_loader.py                # Load rule sets for offline build
│
├─ common/
│  ├─ odfa/
│  │  ├─ matrix.py                     # DFA matrix M_!, row/col addressing for tuples; PER generation
│  │  ├─ permutation.py                # PER row permutations per paper
│  │  ├─ params.py                     # Outmax, cmax, security params {k, κ, s}, lengths
│  │  └─ packing.py                    # Fixed-length encodings; tuple packing for cells
│  ├─ crypto/
│  │  ├─ prg.py                        # G(seed, out_len) for pads (HMAC-SHA256-CTR/HKDF)
│  │  ├─ prf.py                        # PRF, domain separation for labels
│  │  └─ hmac.py                       # HMAC utilities (if not using stdlib, in this project we use stdlib)
│  ├─ ot/
│  │  ├─ base_ot2/
│  │  │  ├─ ddh_ot.py                  # 1-of-2 base OT (Naor–Pinkas)
│  │  │  └─ iknp_extension.py          # OT extension for many parallel OT2 (and long strings)
│  │  ├─ ot_1ofm.py                    # log(m) × OT2 composition
│  │  └─ ot_1of256.py                  # 1-of-256 wrapper (8×OT2), bytes in/out (GOT/QOT/AOT/DOT facades)
│  ├─ net/
│  │  └─ messages.py                   # (pk, q), a, GDFA row chunks, parameter exchange schemas
│  └─ utils/
│     ├─ encode.py                     # I2OSP/OS2IP, fixed-length byte ops
│     └─ checks.py                     # Subgroup checks, range checks, schema validation
│
├─ scripts/
│  ├─ build_gdfa_offline.py            # Server: Steps 1–5 pipeline driver, persists artifacts
│  └─ run_online_demo.py               # Client/Server demo for Steps 6–8
│
├─ tests/
│  ├─ unit/
│  │  ├─ test_ot_1of256.py
│  │  ├─ test_gdfa_builder.py
│  │  ├─ test_sparsity_analysis.py
│  │  └─ test_evaluator.py
│  └─ integration/
│     └─ test_end_to_end_smallset.py
└─ README.md
```