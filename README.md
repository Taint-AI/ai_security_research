# Taint AI Security Research

This repository publishes reproducible studies on the security evaluation of AI models and agents. Each study is self-contained under `studies/`, with its own code, tests, synthetic fixtures, public aggregate data, and a README that states its methods, results, and evidence limitations.

Published by [Taint](https://taint.ai).

## Research Index

| # | Study | Summary |
| :--- | :--- | :--- |
| 001 | [Command continuation and cloud metadata proposals](studies/001-command-continuation/) | Tests whether an unfinished shell command in context can steer a defensive assistant toward proposing cloud metadata URLs. Reports aggregates from 300,000 historical recorded episodes across three models, plus a dependency-free offline harness with synthetic fixtures for new prospective experiments. Detector flags describe generated text, not executed requests or exfiltration. |

## Conventions

- Studies do not execute model-generated commands, and do not commit credentials, raw private model outputs, or local run outputs.
- Historical evidence and new offline apparatus are reported separately. Synthetic fixtures test plumbing, not model behavior.
- Model names identify the systems evaluated and do not imply affiliation with or endorsement by any provider.

## Running a study

Each study documents its own commands. For example:

```sh
cd studies/001-command-continuation
python3 -m unittest discover -s tests -v
python3 lab.py demo
```

## License

Repository-level content is MIT licensed; see [LICENSE](LICENSE). Individual studies may carry their own license and attribution; see each study's `LICENSE` file.
