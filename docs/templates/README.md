# Templates

| file | what it is |
|---|---|
| `gold.csv` | the human worksheet, **filled in** so a reviewer can see what a finished row looks like. Five illustrative rows, not real corpus data. |
| `gold.jsonl` | the same five rows after `gold import`, i.e. the published label format. |
| `silver.jsonl` | one model label, showing the provenance fields `--silver` requires. |

`skillguard gold sample` writes the *empty* version of `gold.csv`: same header,
`label`/`confidence`/`rationale`/`reviewer`/`reviewed_at` blank. Do not sample into
these files — they are documentation, and a test asserts they parse.
