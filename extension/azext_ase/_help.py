from knack.help_files import helps

helps["ase"] = """
type: group
short-summary: Diff, deploy, and read Sentinel incidents and the WAF block list.
"""

helps["ase incident"] = """
type: group
short-summary: Read open Microsoft Sentinel incidents.
"""

helps["ase incident list"] = """
type: command
short-summary: List open incidents and their IPv4 addresses.
"""

helps["ase incident show"] = """
type: command
short-summary: Show one incident and its IPv4 addresses.
"""

helps["ase block"] = """
type: group
short-summary: Read the pinned Application Gateway WAF policy.
"""

helps["ase block list"] = """
type: command
short-summary: List SentinelAutoBlock addresses on the pinned policy.
"""

helps["ase diff"] = """
type: command
short-summary: Read the target resource group and compare it with the PoC profile.
"""

helps["ase deploy"] = """
type: command
short-summary: Show the deploy plan. Pass --apply to run scripts/deploy.ps1.
"""
