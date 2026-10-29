from knack.help_files import helps

helps["ase"] = """
type: group
short-summary: Diff and deploy the ASE Sentinel WAF proof of concept.
"""

helps["ase diff"] = """
type: command
short-summary: Read the target resource group and compare it with the PoC profile.
"""

helps["ase deploy"] = """
type: command
short-summary: Show the deploy plan. Pass --apply to run scripts/deploy.ps1.
"""
