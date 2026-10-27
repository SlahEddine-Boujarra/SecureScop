"""
Streamlit UI for custom Nmap profiles.

Can run standalone through app_nmap_custom_page.py or be imported into the main app.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List

import pandas as pd
import streamlit as st
from securescope.ui.components.navigation import module_tabs

from securescope.core.output_sanitizer import display_tool_output
from securescope.scanners.nmap.nmap_profile_builder import (
    PROFILE_PRESETS,
    build_nmap_command,
    command_to_display,
    grouped_options,
    infer_asset_classification,
    parse_nmap_xml,
    run_nmap,
    validate_target_text,
)


def render_nmap_custom_scan_page() -> None:
    st.markdown(
        (
            "\n        <style>\n        .nmap-hero {\n            padding: "
            "1.35rem 1.55rem;\n            border-radius: 1.15rem;\n       "
            "     background: linear-gradient(135deg, #061b35, "
            "#0e6b90);\n            color: white;\n            "
            "margin-bottom: 1rem;\n        }\n        .nmap-hero h1 { "
            "color: white !important; margin: 0; }\n        .nmap-hero p "
            "{ color: #dbeafe !important; margin: .45rem 0 0 0; }\n       "
            " .scan-card {\n            background: white;\n            "
            "border: 1px solid #dbe3ef;\n            border-radius: "
            "1rem;\n            padding: 1rem;\n            box-shadow: 0 "
            "10px 24px rgba(15,23,42,.06);\n        }\n        input, "
            'textarea, div[data-baseweb="select"] span {\n            '
            "color: #0f172a !important;\n            "
            "-webkit-text-fill-color: #0f172a !important;\n        }\n     "
            '   </style>\n        <div class="nmap-hero">\n          '
            "<h1>Nmap Custom Scan Builder</h1>\n          <p>No forced "
            "Step 2. Choose the exact scan type/options you need, "
            "preview the command, then run it.</p>\n        </div>\n       "
            " "
        ),
        unsafe_allow_html=True,
    )

    scans_dir = Path("scans")
    scans_dir.mkdir(exist_ok=True)

    with st.sidebar:
        st.subheader("Target")
        target = st.text_input("Target / CIDR / hostname", value="192.168.100.0/24")
        authorized = st.checkbox("I am authorized to scan this target", value=False)
        nmap_binary = st.text_input("Nmap binary", value="nmap")
        timeout_seconds = st.number_input(
            "Execution timeout seconds", min_value=60, max_value=14400, value=1800, step=60
        )

    profile_name = st.selectbox("Scan profile", list(PROFILE_PRESETS.keys()))
    profile = PROFILE_PRESETS[profile_name]
    st.caption(profile["description"])

    include_advanced = st.toggle("Show advanced / noisy options", value=False)

    default_flags = profile.get("options", [])
    selected_flags: List[str] = []

    tabs = module_tabs(
        ["Basic options", "Ports & timing", "Scripts", "Command preview", "Run & results"]
    )

    with tabs[0]:
        st.subheader("Choose Nmap options")

        for category, options in grouped_options(include_advanced=include_advanced).items():
            with st.expander(
                category, expanded=category in {"Host discovery", "Scan technique", "Detection"}
            ):
                labels = {f"{opt.flag} — {opt.label}": opt.flag for opt in options}
                defaults = [label for label, flag in labels.items() if flag in default_flags]
                chosen = st.multiselect(
                    f"{category} options",
                    list(labels.keys()),
                    default=defaults,
                    key=f"nmap_opts_{category}",
                )
                selected_flags.extend(labels[label] for label in chosen)

                for opt in options:
                    st.caption(f"`{opt.flag}` — {opt.description}")

        st.info("Note: OS detection is `-O`. `-sO` is IP protocol scan, not OS detection.")

    with tabs[1]:
        st.subheader("Ports and timing")

        col1, col2, col3 = st.columns(3)

        with col1:
            top_ports = st.number_input(
                "Top ports value",
                min_value=1,
                max_value=65535,
                value=int(profile.get("top_ports", 1000)),
                step=100,
                help="Used only when --top-ports is selected.",
            )

        with col2:
            ports = st.text_input(
                "Ports for -p",
                value=str(profile.get("ports", "")),
                placeholder="22,80,443 or 1-1000 or -",
                help="Used only when -p is selected.",
            )

        with col3:
            max_retries = st.number_input(
                "Max retries",
                min_value=0,
                max_value=10,
                value=int(profile.get("max_retries", 2)),
                help="Used only when --max-retries is selected.",
            )

        host_timeout = st.text_input(
            "Host timeout",
            value=str(profile.get("host_timeout", "5m")),
            help="Used only when --host-timeout is selected. Examples: 300s, 5m, 20m.",
        )

    with tabs[2]:
        st.subheader("NSE scripts and custom arguments")

        scripts = st.text_input(
            "Scripts for --script",
            value=str(profile.get("scripts", "")),
            placeholder="default,safe or ntp-info",
            help="Used only when --script is selected.",
        )

        custom_args = st.text_area(
            "Extra custom Nmap arguments",
            value="",
            placeholder="Example: --reason --defeat-rst-ratelimit",
            help=(
                "Advanced. These arguments are appended before the target. Do not "
                "include shell operators."
            ),
        )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_xml = str(
        scans_dir
        / f"nmap_custom_{profile_name.lower().replace(' ', '_').replace('/', '_')}_{timestamp}.xml"
    )

    valid, message = validate_target_text(target)

    command_args = build_nmap_command(
        target=target,
        selected_flags=selected_flags,
        output_xml=output_xml,
        top_ports=top_ports,
        ports=ports,
        scripts=scripts,
        max_retries=max_retries,
        host_timeout=host_timeout,
        custom_args=custom_args,
        nmap_binary=nmap_binary,
    )

    with tabs[3]:
        st.subheader("Generated command")
        if not valid:
            st.error(message)
        if "-sn" in command_args and any(x in command_args for x in ["-sV", "-O", "-A", "-sC"]):
            st.warning(
                (
                    "You selected `-sn` with detection options. `-sn` disables port "
                    "scanning, so service/OS results may not appear."
                )
            )
        if "-sO" in command_args:
            st.warning("`-sO` is IP protocol scan, not OS detection. For OS detection use `-O`.")

        st.code(command_to_display(command_args), language="powershell")
        st.caption(f"XML output will be saved to: `{display_tool_output(output_xml)}`")

    with tabs[4]:
        st.subheader("Run scan")

        if not authorized:
            st.warning("Check the authorization box in the sidebar before running.")
        run_clicked = st.button(
            "Run selected Nmap scan",
            type="primary",
            width="stretch",
            disabled=not authorized or not valid,
        )

        if run_clicked:
            with st.spinner("Running Nmap scan..."):
                result = run_nmap(command_args, timeout_seconds=int(timeout_seconds))

            if result["ok"]:
                st.success(f"Nmap completed in {result['duration_seconds']} seconds.")
            else:
                st.error(f"Nmap failed or timed out. Return code: {result['returncode']}")

            with st.expander("Nmap stdout", expanded=False):
                st.code(display_tool_output(result["stdout"] or ""), language="text")

            with st.expander("Nmap stderr", expanded=False):
                st.code(display_tool_output(result["stderr"] or ""), language="text")

            assets = parse_nmap_xml(output_xml)
            if assets:
                enriched = []
                for asset in assets:
                    row = {
                        "ip": asset.get("ip"),
                        "hostname": asset.get("hostname"),
                        "status": asset.get("status"),
                        "mac_address": asset.get("mac_address"),
                        "mac_vendor": asset.get("mac_vendor"),
                        "open_ports": ", ".join(
                            f"{p.get('port')}/{p.get('protocol')} {p.get('service') or ''}".strip()
                            for p in asset.get("open_ports", [])
                        ),
                        "os_guess": asset.get("os_guess"),
                    }
                    row.update(infer_asset_classification(asset))
                    enriched.append(row)

                df = pd.DataFrame(enriched)
                st.subheader("Parsed inventory preview")
                st.dataframe(df, width="stretch", hide_index=True)

                st.download_button(
                    "Download parsed inventory CSV",
                    data=df.to_csv(index=False).encode("utf-8-sig"),
                    file_name=f"nmap_inventory_{timestamp}.csv",
                    mime="text/csv",
                    width="stretch",
                )
            else:
                st.info(
                    (
                        "No parsed hosts found. This can happen if the scan found no live "
                        "hosts or XML output was not created."
                    )
                )
