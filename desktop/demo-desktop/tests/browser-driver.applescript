on run arguments
    if (count of arguments) is 0 then error "缺少浏览器动作"
    set requestedAction to item 1 of arguments

    if requestedAction is "current-url" then
        tell application "System Events"
            set browserProcess to first application process whose frontmost is true
            set browserBundleId to bundle identifier of browserProcess
            if browserBundleId is not "com.google.Chrome" and browserBundleId is not "com.apple.Safari" and browserBundleId is not "com.brave.Browser" and browserBundleId is not "com.microsoft.edgemac" and browserBundleId is not "company.thebrowser.Browser" and browserBundleId is not "org.mozilla.firefox" then
                error "前台应用不是受支持的系统浏览器"
            end if
            if (count of windows of browserProcess) is 0 then error "系统浏览器没有窗口"
            repeat with candidate in (entire contents of window 1 of browserProcess)
                try
                    if role of candidate is "AXTextField" or role of candidate is "AXComboBox" then
                        set candidateValue to value of candidate as text
                        if candidateValue starts with "http://" or candidateValue starts with "https://" or candidateValue starts with "localhost:9000/" then
                            return browserBundleId & linefeed & candidateValue
                        end if
                    end if
                end try
            end repeat
            error "找不到系统浏览器地址栏"
        end tell
    end if

    if requestedAction is not "fill-login" then error "不支持的浏览器动作"
    if (count of arguments) < 4 then error "登录表单参数不完整"
    set browserBundleId to item 2 of arguments
    set loginEmail to item 3 of arguments
    set loginPassword to item 4 of arguments

    tell application "System Events"
        set matchingProcesses to every application process whose bundle identifier is browserBundleId
        if (count of matchingProcesses) is 0 then error "系统浏览器未运行"
        set browserProcess to item 1 of matchingProcesses
        set frontmost of browserProcess to true
        if (count of windows of browserProcess) is 0 then error "系统浏览器没有窗口"

        set webArea to missing value
        repeat with candidate in (entire contents of window 1 of browserProcess)
            try
                if role of candidate is "AXWebArea" then
                    set webArea to candidate
                    exit repeat
                end if
            end try
        end repeat
        if webArea is missing value then error "找不到登录页可访问性区域"

        set emailField to missing value
        set passwordField to missing value
        set submitButton to missing value
        repeat with candidate in (entire contents of webArea)
            try
                set candidateRole to role of candidate
                if candidateRole is "AXTextField" or candidateRole is "AXSecureTextField" then
                    set candidateSubrole to ""
                    try
                        set candidateSubrole to subrole of candidate
                    end try
                    if candidateRole is "AXSecureTextField" or candidateSubrole is "AXSecureTextField" then
                        if passwordField is missing value then set passwordField to candidate
                    else if emailField is missing value then
                        set emailField to candidate
                    else if passwordField is missing value then
                        -- 部分浏览器只把密码框暴露成第二个普通 AXTextField。
                        set passwordField to candidate
                    end if
                else if (candidateRole is "AXButton") and (name of candidate is "登录") then
                    set submitButton to candidate
                end if
            end try
        end repeat

        if emailField is missing value then error "找不到邮箱输入框"
        if passwordField is missing value then error "找不到密码输入框"
        if submitButton is missing value then error "找不到登录按钮"

        set value of emailField to loginEmail
        set value of passwordField to loginPassword
        click submitButton
        return "true"
    end tell
end run
