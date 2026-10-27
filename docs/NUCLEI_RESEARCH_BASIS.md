# Nuclei research basis

The SecureScope v5.3.0 implementation was designed after reviewing the current
official ProjectDiscovery documentation and source repository.

## Confirmed design decisions

1. **Use the local CLI.** Nuclei's primary open-source integration surface is
   the command-line tool. SecureScope invokes it with a subprocess argument
   list and never builds a shell command.
2. **No local API key requirement.** Open-source local scans operate without an
   API key. ProjectDiscovery Cloud authentication is optional.
3. **Durable JSONL evidence.** `-jsonl-export` provides one structured finding
   per line for normalization and report generation.
4. **Bounded scanning.** `-rate-limit`, `-bulk-size` and `-concurrency` control
   global request rate, hosts per template and templates in parallel.
5. **Target files.** `-list` is used for exact per-job target lists.
6. **Operational telemetry.** `-stats -stats-json` supports live requests,
   matches, errors and percent data without parsing human progress text.
7. **Template maintenance.** Community templates are maintained with
   `-update-templates` and their version is read with `-templates-version`.
8. **Optional authentication and cloud.** Authenticated targets can use the
   official secret-file mechanism in future; cloud result upload is deliberately
   disabled by default.

## Sources

- https://docs.projectdiscovery.io/opensource/nuclei/install
- https://docs.projectdiscovery.io/opensource/nuclei/running
- https://docs.projectdiscovery.io/opensource/nuclei/input-formats
- https://docs.projectdiscovery.io/opensource/nuclei/authenticated-scans
- https://docs.projectdiscovery.io/opensource/nuclei/go-sdk
- https://docs.projectdiscovery.io/templates/introduction
- https://github.com/projectdiscovery/nuclei
- https://github.com/projectdiscovery/nuclei-templates
