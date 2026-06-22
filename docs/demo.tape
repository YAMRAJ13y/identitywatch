# IdentityWatch demo recording — renders docs/demo.gif
#
# Install VHS once:  https://github.com/charmbracelet/vhs  (winget/scoop, or WSL/Git Bash).
# Then from the repo root:
#     pip install -e .          # so the `identitywatch` command exists
#     vhs docs/demo.tape        # produces docs/demo.gif
#
# Embed it near the top of README.md with:  ![IdentityWatch demo](docs/demo.gif)

Output docs/demo.gif

Set FontSize 15
Set Width 1180
Set Height 840
Set Theme "Dracula"
Set Padding 18
Set TypingSpeed 55ms

Type "identitywatch scan examples/sample_auth_log.jsonl"
Sleep 500ms
Enter
Sleep 8s
