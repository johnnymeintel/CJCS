#!/bin/bash
# Auto-fix all .sh files in shared folder

echo "Converting Windows line endings to Unix..."

find /media/sf_CJCS/Baseline -type f -name "*.sh" -exec dos2unix {} \;
find /media/sf_CJCS/Baseline -type f -name "*.sh" -exec chmod +x {} \;

echo "All scripts converted and made executable"