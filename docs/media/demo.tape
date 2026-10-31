# Demo clip and screenshots for the README, recorded with VHS (https://github.com/charmbracelet/vhs):
#   vhs docs/media/demo.tape
# Expects a Windows 11 ISO at ~/Downloads/Win11_26H2_German_x64.iso (HOME is set below) and about 90 GiB free.
# The waits for the inventory and the build are hidden, the clip shows the wizard and the result.

Output docs/media/lean11-demo.gif

Require lean11

Set Shell bash
Set FontFamily "JetBrains Mono"
Set FontSize 15
Set Width 1600
Set Height 920
Set Padding 18
Set Margin 22
Set MarginFill "#1e1e2e"
Set WindowBar Colorful
Set BorderRadius 10
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set Framerate 24

Hide
Type "export HOME=/home/demo LANG=en_US.UTF-8 PS1='$ ' && cd ~ && rm -rf lean11-work lean11.iso && clear"
Enter
Sleep 500ms
Show

Type "lean11 tui"
Sleep 600ms
Enter
Sleep 2s

# 1 Mode: the three builds
Down
Sleep 700ms
Down
Sleep 900ms
Up
Sleep 500ms
Up
Sleep 800ms
Screenshot docs/media/mode.png
Enter
Sleep 1s

# 2 Source: an ISO from Microsoft (d downloads the latest one)
Type "t"
Sleep 400ms
Type "~/Downloads/Win11_26H2_German_x64.iso"
Sleep 600ms
Enter
Sleep 800ms
Enter

# 3 Edition
Wait+Screen@90s /Windows 11 Pro for Workstations/
Sleep 2s
Enter

# 4 Components: every item with its traffic-light rating and what removing it does
Sleep 1500ms
Down@400ms 3
Sleep 1s
Screenshot docs/media/components.png
Down@300ms 18
Sleep 1500ms
Enter

# 5 Privacy: verified settings, r = all recommended
Sleep 1200ms
Type "r"
Sleep 800ms
Down@350ms 4
Sleep 1500ms
Screenshot docs/media/privacy.png
Enter

# 6 Custom: the full inventory of the image (read in the background)
Sleep 2s
Hide
Wait+Screen@400s /Apps [1-9]/
Show
Sleep 1500ms
Tab@500ms 4
Sleep 800ms
Type "/"
Sleep 300ms
Type "Rpc"
Enter
Sleep 600ms
Down@500ms 2
Sleep 1500ms
Screenshot docs/media/custom.png
Sleep 1s
Enter

# 7 Software: installed at the end of setup
Sleep 1s
Down
Space
Sleep 400ms
Down@200ms 7
Space
Sleep 1500ms
Screenshot docs/media/software.png
Enter

# 8 Settings
Sleep 2s
Enter

# 9 Review
Sleep 2500ms
Screenshot docs/media/review.png
Enter

# 10 Build
Sleep 6s
Hide
Wait+Screen@75m /Done: lean11.iso/
Show
Sleep 5s
Screenshot docs/media/build.png
Sleep 2s
