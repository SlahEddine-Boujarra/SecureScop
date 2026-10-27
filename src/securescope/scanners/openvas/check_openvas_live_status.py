"""Read-only Greenbone task status/progress diagnostic for SecureScope."""

from __future__ import annotations

import json

from dotenv import load_dotenv
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

from securescope.paths import ENV_FILE
from securescope.scanners.openvas.openvas_worker_service import (
    GMP_FAST_STATUS_TIMEOUT_SECONDS,
    GVM_PASSWORD,
    GVM_USERNAME,
    make_gmp_connection,
    require_gmp_tunnel,
)

load_dotenv(dotenv_path=ENV_FILE, override=False)


def first(values: list[object], default: str = "") -> str:
    return str(values[0]) if values else default


def main() -> int:
    require_gmp_tunnel()
    rows: list[dict[str, object]] = []
    with GMP(
        connection=make_gmp_connection(
            timeout_seconds=GMP_FAST_STATUS_TIMEOUT_SECONDS,
        ),
        transform=EtreeCheckCommandTransform(),
    ) as gmp:
        gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)
        response = gmp.get_tasks(
            filter_string="rows=-1 sort-reverse=creation_time",
            details=False,
            ignore_pagination=True,
        )
        nodes = list(response.xpath("./task")) or list(response.xpath(".//task"))
        for node in nodes:
            name = first(node.xpath("./name/text()"))
            if not name.startswith("securescope-scan-"):
                continue
            rows.append(
                {
                    "task_id": str(node.get("id") or ""),
                    "name": name,
                    "status": first(node.xpath("./status/text()"), "Unknown"),
                    "progress": first(node.xpath("./progress/text()"), "0"),
                    "current_report_id": first(node.xpath("./current_report/report/@id")),
                    "last_report_id": first(node.xpath("./last_report/report/@id")),
                }
            )
    print(json.dumps(rows, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
