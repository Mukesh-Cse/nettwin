# Architecture

JSON scenario → validated dataclasses → first-match ACL evaluator → assertion report.

The mutation engine constructs single-rule variants. The diagnosis engine removes one rule at a time and reruns the full assertion set. The repair engine tries deletion, action flips and exact-match prepended rules, and accepts only an all-assertions-passing variant.

The API, CLI and dashboard use the same core functions. No generated commands are executed on the host.
