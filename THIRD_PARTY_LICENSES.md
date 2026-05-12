# Third-Party Licenses

TDDF bundles small curated subsets of two upstream research benchmarks. Both are MIT-licensed; their copyright notices and full license text are reproduced below as required by the MIT attribution clause.

## AgentDojo

- **Upstream:** [`ethz-spylab/agentdojo`](https://github.com/ethz-spylab/agentdojo)
- **License:** MIT
- **What TDDF redistributes:** `src/tddf/data/agentdojo_curated.yaml` — a hand-picked subset of AgentDojo's banking and workspace task suites, materialised into TDDF's trap schema. AgentDojo itself is also a runtime dependency via the optional `tddf[agentdojo]` extra (not bundled in the wheel).
- **Citation (academic):** Debenedetti, E., Zhang, J., Balunovic, M., Beurer-Kellner, L., Fischer, M., & Tramèr, F. (2024). *AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents.* NeurIPS 2024 Datasets & Benchmarks Track.

```
MIT License

Copyright (c) 2024 Edoardo Debenedetti, Jie Zhang, Mislav Balunovic, Luca Beurer-Kellner, Marc Fischer, and Florian Tramèr

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## InjecAgent

- **Upstream:** [`uiuc-kang-lab/InjecAgent`](https://github.com/uiuc-kang-lab/InjecAgent) (note: the upstream file is spelled `LICENCE`)
- **License:** MIT
- **What TDDF redistributes:** `src/tddf/data/injecagent_curated.yaml` — a curated subset of InjecAgent's data-stealing base test cases, materialised into TDDF's trap schema. The InjecAgent corpus itself is fetched at import time via `tddf import injecagent`; it is not bundled in the wheel. The fixture at `tests/fixtures/injecagent/data/test_cases_ds_base.json` is for development only and is excluded from the published wheel.
- **Citation (academic):** Zhan, Q., Liang, Z., Ying, Z., & Kang, D. (2024). *InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents.* arXiv:2403.02691.

```
MIT License

Copyright (c) 2023 Qiusi Zhan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Runtime dependencies (not bundled)

TDDF's runtime Python dependencies (`pydantic`, `pyyaml`, `rich`, `typer`, and the optional `agentdojo` extra) are installed by pip from PyPI as separate packages and are not redistributed in TDDF's wheel. Their licenses apply to the installed copies, not to TDDF.
