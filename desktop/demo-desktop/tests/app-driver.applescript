on run arguments
    if (count of arguments) < 2 then error "缺少 bundle id 或动作"
    set targetBundleId to item 1 of arguments
    set requestedAction to item 2 of arguments
    set targetName to ""
    if (count of arguments) > 2 then set targetName to item 3 of arguments

    tell application "System Events"
        set matchingProcesses to every application process whose bundle identifier is targetBundleId
        if (count of matchingProcesses) is 0 then error "目标桌面应用未运行"
        set targetProcess to item 1 of matchingProcesses

        if requestedAction is "pid" then
            return (unix id of targetProcess) as text
        end if

        set frontmost of targetProcess to true
        if (count of windows of targetProcess) is 0 then error "目标桌面应用没有窗口"
        set allElements to entire contents of window 1 of targetProcess

        repeat with candidate in allElements
            try
                if (role of candidate is "AXButton") and (name of candidate is targetName) then
                    if requestedAction is "button-exists" then return "true"
                    if requestedAction is "click-button" then
                        click candidate
                        return "true"
                    end if
                end if
            end try
        end repeat

        if requestedAction is "button-exists" then return "false"
        error "找不到目标按钮"
    end tell
end run
