#!/bin/bash
# Sysmon events with better readability - FIXED
sudo tail -f /var/ossec/logs/archives/archives.json | 
  grep --line-buffered -i "sysmon" | jq -c '
  def safeget($path): try .data.win.eventdata[$path] catch null;
  {
    t: (.timestamp | split("T")[1] | split(".")[0]),
    host: (.agent.name | split(".")[0]),
    evt: .data.win.system.eventID,
    proc: (
      safeget("image") // 
      safeget("sourceImage") // 
      safeget("targetImage") // 
      "?" | 
      gsub("\\\\\\\\"; "/") | 
      split("/") | 
      last
    ),
    user: (
      safeget("user") // 
      safeget("sourceUser") // 
      safeget("targetUser") // 
      "?" | 
      gsub("\\\\\\\\"; "/") | 
      split("/") | 
      last
    )
  }'