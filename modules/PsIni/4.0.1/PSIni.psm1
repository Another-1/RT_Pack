#region Configuration
$script:NoSection = "_"
$script:CommentPrefix = "__Comment"
function Export-Ini {
    <#
    .Synopsis
        Write hash content to INI file

    .Description
        Write hash content to INI file

    .Inputs
        System.String
        System.Collections.IDictionary

    .Example
        Export-Ini $IniVar "C:\myinifile.ini"
        -----------
        Description
        Saves the content of the $IniVar Hashtable to the INI File c:\myinifile.ini

    .Example
        $IniVar | Export-Ini "C:\myinifile.ini" -Force
        -----------
        Description
        Saves the content of the $IniVar Hashtable to the INI File c:\myinifile.ini and overwrites the file if it is already present

    .Example
        $file = Export-Ini $IniVar -FilePath "C:\myinifile.ini" -PassThru
        -----------
        Description
        Saves the content of the $IniVar Hashtable to the INI File c:\myinifile.ini and saves the file into $file. Writes exported data to console, as a powershell object.

    .Example
        $Category1 = @{"Key1"="Value1";"Key2"="Value2"}
        $Category2 = @{"Key1"="Value1";"Key2"="Value2"}
        $NewINIContent = @{"Category1"=$Category1;"Category2"=$Category2}
        Export-Ini -InputObject $NewINIContent -FilePath "C:\MyNewFile.ini"
        -----------
        Description
        Creating a custom Hashtable and saving it to C:\MyNewFile.ini

    .Example
        $Winpeshl = @{
            LaunchApp = @{
                AppPath = %"SYSTEMDRIVE%\Fabrikam\shell.exe"
            }
            LaunchApps = @{
                "%SYSTEMDRIVE%\Fabrikam\app1.exe" = $null
                '%SYSTEMDRIVE%\Fabrikam\app2.exe, /s "C:\Program Files\App3"' = $null
            }
        }
        Export-Ini -InputObject $Winpeshl -FilePath "winpeshl.ini" -SkipTrailingEqualSign
        -----------
        Description
        Example as per https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpeshlini-reference-launching-an-app-when-winpe-starts

    .Link
        Import-Ini
        ConvertFrom-Ini
        ConvertTo-Ini
    #>

    [CmdletBinding( SupportsShouldProcess )]
    [OutputType( [Void] )]
    param(
        # Specifies the Hashtable to be written to the file.
        # Enter a variable that contains the objects or type a command or expression that gets the objects.
        [Parameter( Mandatory, ValueFromPipeline )]
        [System.Collections.IDictionary]
        $InputObject,

        # Specifies the path to the output file.
        [Parameter( Mandatory, Position = 0, ParameterSetName = "Path") ]
        [ValidateScript( { Invoke-ConditionalParameterValidationPath -InputObject $_ } )]
        [Alias( "Path" )]
        [String]
        $FilePath,

        # Specifies the path to the output file.
        # The LiteralPath parameter is used exactly as it's typed.
        # Wildcard characters aren't accepted.
        # If the path includes escape characters, enclose it in single quotation marks.
        # Single quotation marks tell PowerShell not to interpret any characters as escape sequences.
        # For more information, see about_Quoting_Rules.
        [Parameter( Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = "LiteralPath" )]
        [Alias( "PSPath", "LP" )]
        [String]
        $LiteralPath,

        # Adds the output to the end of an existing file, instead of replacing the file contents.
        [Switch]
        $Append,

        # Specifies the file encoding.
        # The default is UTF8.
        # The supported values are system dependent and can be listed with:
        # `(Get-Help -Name Out-File).parameters.parameter | ? name -eq Encoding`
        [Parameter()]
        [ValidateScript( { Invoke-ConditionalParameterValidationEncoding -InputObject $_ } )]
        [String]
        $Encoding = "UTF8",

        # Allows the cmdlet to overwrite an existing read-only file.
        # Even using the Force parameter, the cmdlet cannot override security restrictions.
        [Parameter()]
        [Switch]
        $Force,

        # NoClobber prevents an existing file from being overwritten and displays a message
        # that the file already exists.
        # By default, if a file exists in the specified path, it will be overwritten without warning.
        [Parameter()]
        [Alias( "NoOverwrite" )]
        [Switch]
        $NoClobber,

        # Specifies the character used to indicate a comment.
        [Parameter()]
        [String]
        $CommentChar = ";",

        # Determines the format of how to write the file.
        #
        # The following values are supported:
        #  - pretty: will write the file with an empty line between sections and whitespaces around the `=` sign
        #  - minified: will write the file in as few characters as possible
        [Parameter()]
        [ValidateSet("pretty", "minified")]
        [String]
        $Format = "pretty",

        # Will not write comments to the output file
        [Parameter()]
        [Switch]
        $IgnoreComments,

        # Does not add trailing = sign to keys without value.
        # This behavior is needed for specific OS files, such as:
        # https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpeshlini-reference-launching-an-app-when-winpe-starts
        [Parameter()]
        [Switch]
        $SkipTrailingEqualSign
    )

    begin {
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"

        $delimiter = if ($Format -eq "pretty") { ' = ' } else { '=' }

        $fileParameters = @{
            Encoding = $Encoding
            Path     = $Path
            Force    = $Force
        }
        Write-DebugMessage "Using the following parameters when writing to file:"
        Write-DebugMessage ($fileParameters | Out-String)
    }

    process {
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Creating file content in memory"
        $fileContent = @()

        foreach ($section in $InputObject.GetEnumerator().Name) {
            Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing Section: [$section]"

            # Add section header to the content array
            # Note: this relies on an OrderedDictionary for the keys without a section to be at the top of the file
            if ($section -ne $script:NoSection) {
                $fileContent += "[$section]"
            }

            $outKeyParam = @{
                InputObject           = $InputObject[$section]
                Delimiter             = $delimiter
                IgnoreComments        = $IgnoreComments
                CommentChar           = $CommentChar
                SkipTrailingEqualSign = $SkipTrailingEqualSign
            }
            $fileContent += Out-Key @outKeyParam

            # TODO: what when the Input is only a simple hash?

            # Separate Sections with whiteSpace
            if ($Format -eq "pretty") { $fileContent += "" }
        }

        Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing to file: $Path"
        $ofsplat = @{
            InputObject = $fileContent
            NoClobber   = $NoClobber
            Append      = $Append
            Encoding    = $Encoding
        }
        if ($LiteralPath) {
            if ($PSCmdlet.ShouldProcess((Split-Path $LiteralPath -Leaf), "Write")) {
                Out-File @ofsplat -LiteralPath $LiteralPath
            }
        }
        else {
            if ($PSCmdlet.ShouldProcess((Split-Path $FilePath -Leaf), "Write")) {
                Out-File @ofsplat -FilePath $FilePath
            }
        }
    }

    end {
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"
    }
}

Set-Alias epini Export-Ini

Register-ArgumentCompleter -CommandName Export-Ini -ParameterName Encoding -ScriptBlock {
    Get-AllowedEncoding |
        Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new(
                $_,
                $_,
                [System.Management.Automation.CompletionResultType]::ParameterValue,
                $_
            )
        }
}

function Import-Ini {
    <#
    .Synopsis
        Gets the content of an INI file

    .Description
        Gets the content of an INI file and returns it as a hashtable

    .Inputs
        System.String

    .Outputs
        System.Collections.Specialized.OrderedDictionary

    .Example
        $FileContent = Import-Ini "C:\myinifile.ini"
        -----------
        Description
        Saves the content of the c:\myinifile.ini in a hashtable called $FileContent

    .Example
        $inifilepath | $FileContent = Import-Ini
        -----------
        Description
        Gets the content of the ini file passed through the pipe into a hashtable called $FileContent

    .Example
        C:\PS>$FileContent = Import-Ini "c:\settings.ini"
        C:\PS>$FileContent["Section"]["Key"]
        -----------
        Description
        Returns the key "Key" of the section "Section" from the C:\settings.ini file

    .Link
        Export-Ini
        ConvertFrom-Ini
        ConvertTo-Ini
    #>

    [CmdletBinding()]
    [OutputType( [System.Collections.Specialized.OrderedDictionary] )]
    param(
        # Specifies the path to an item.
        # This cmdlet gets the item at the specified location.
        # Wildcard characters are permitted.
        # This parameter is required, but the parameter name Path is optional.
        #
        # Use a dot (`.`) to specify the current location. Use the wildcard character (`*`) to specify all the items in the current location.
        [Parameter( Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = "Path", Position = 0 )]
        [ValidateNotNullOrEmpty()]
        [Alias("PSPath", "FullName")]
        [String[]]
        $Path,

        # Specifies a path to one or more locations.
        # The value of LiteralPath is used exactly as it's typed.
        # No characters are interpreted as wildcards.
        # If the path includes escape characters, enclose it in single quotation marks.
        # Single quotation marks tell PowerShell not to interpret any characters as escape sequences.
        #
        # For more information, see about_Quoting_Rules
        [Parameter( Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = "LiteralPath" )]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $LiteralPath,

        # The string representation of the INI file.
        [Parameter( Mandatory, ParameterSetName = "String" )]
        [ValidateNotNullOrEmpty()]
        [String]
        $InputString,

        # Specifies the file encoding.
        # The default is UTF8.
        [Parameter( ParameterSetName = "Path" )]
        [Parameter( ParameterSetName = "LiteralPath" )]
        [ValidateNotNullOrEmpty()]
        [System.Text.Encoding]
        $Encoding = [System.Text.Encoding]::UTF8,

        # Specify what characters should be describe a comment.
        # Lines starting with the characters provided will be rendered as comments.
        # Default: ";"
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Char[]]
        $CommentChar = @(";"),

        # Remove lines determined to be comments from the resulting dictionary.
        [Switch]
        $IgnoreComments,

        # Remove sections without any key
        [Switch]
        $IgnoreEmptySections
    )

    begin {
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"

        $listOfCommentChars = $CommentChar -join ''
        $commentRegex = "^[$listOfCommentChars](.*)$"
        $sectionRegex = "^\s*\[(.+)\]"
        $keyRegex = "^([^$listOfCommentChars]+?)=(.*)$"

        Write-DebugMessage ("commentRegex is $commentRegex")
        Write-DebugMessage ("sectionRegex is $sectionRegex")
        Write-DebugMessage ("keyRegex is $keyRegex")
    }

    process {
        if ($Path) { $Sources = (Resolve-Path $Path) }
        elseif ($LiteralPath) { $Sources = $LiteralPath }
        elseif ($InputString) { $Sources = $InputString }

        foreach ($source in $Sources) {
            if ($LiteralPath -or $Path) {
                Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing file: $source"

                $source = (Get-Item -LiteralPath $source).FullName
                try { $fileContent = [System.IO.File]::ReadAllLines($source, $Encoding) }
                catch {
                    Write-Error "Could not find file '$source'"
                    continue
                }
            }
            else {
                Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing a string"
                $fileContent = $source.split("`n")
            }

            $ini = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
            $section, $name = $null
            $commentCount = 0

            foreach ($line in $fileContent) {
                switch -Regex ($line) {
                    $sectionRegex {
                        $section = $matches[1]
                        Write-Debug "$($MyInvocation.MyCommand.Name):: Adding section : $section"
                        $ini[$section] = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
                        $commentCount = 0
                        continue
                    }
                    $commentRegex {
                        if (-not $IgnoreComments) {
                            if (-not $section) {
                                $section = $script:NoSection
                                $ini[$section] = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
                            }
                            $value = $matches[1].Trim()
                            $commentCount++
                            Write-DebugMessage ("Incremented commentCount is now $commentCount.")
                            $name = "$script:CommentPrefix$commentCount"
                            Write-Debug "$($MyInvocation.MyCommand.Name):: Adding $name with value: $value"
                            $ini[$section][$name] = $value
                        }
                        else {
                            Write-DebugMessage ("Ignoring comment $($matches[1]).")
                        }
                        continue
                    }
                    $keyRegex {
                        if (-not $section) {
                            $section = $script:NoSection
                            $ini[$section] = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
                        }
                        $name, $value = $matches[1].Trim(), $matches[2].Trim()
                        if (-not [string]::IsNullOrWhiteSpace($name)) {
                            Write-Verbose "$($MyInvocation.MyCommand.Name):: Adding key $name with value: $value"
                            if (-not $ini[$section][$name]) {
                                $ini[$section][$name] = $value
                            }
                            else {
                                if ($ini[$section][$name] -is [string]) {
                                    $oldValue = $ini[$section][$name]
                                    $ini[$section][$name] = [System.Collections.ArrayList]::new()
                                    $null = $ini[$section][$name].Add($oldValue)
                                }
                                $null = $ini[$section][$name].Add($value)
                            }
                        }
                        continue
                    }
                    Default {
                        # As seen in https://github.com/lipkau/PSIni/issues/65, some software write keys without the `=` sign.
                        if (-not $section) {
                            $section = $script:NoSection
                            $ini[$section] = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
                        }
                        $name = $_.Trim()
                        if (-not [string]::IsNullOrWhiteSpace($name)) {
                            Write-Verbose "$($MyInvocation.MyCommand.Name):: Adding key $name without a value"
                            $ini[$section][$name] = $null
                        }
                        continue
                    }
                }
            }

            if ($IgnoreEmptySections) {
                $ToRemove = [System.Collections.ArrayList]@()
                foreach ($Section in $ini.GetEnumerator().Name) {
                    if (($ini[$Section]).Count -eq 0) {
                        $null = $ToRemove.Add($Section)
                    }
                }
                foreach ($Section in $ToRemove) {
                    Write-Verbose "$($MyInvocation.MyCommand.Name):: Removing empty section $Section"
                    $null = $ini.Remove($Section)
                }
            }

            $ini
        }
    }

    end {
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"
    }
}

Set-Alias ipini Import-Ini

function Get-AllowedEncoding {
    $command = Get-Command -Name Out-File

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        (
            $command.Parameters['Encoding'].Attributes |
                Where-Object { $_ -is [ArgumentCompletions] }
        )[0].CompleteArgument('Out-File', 'Encoding', '*', $null, @{ }).CompletionText
    }
    else {
        (
            $command.Parameters['Encoding'].Attributes |
                Where-Object { $_.TypeId -eq [ValidateSet] }
        )[0].ValidValues
    }
}

function Invoke-ConditionalParameterValidationEncoding {
    param( [String] $InputObject )

    $allowedEncodings = Get-AllowedEncoding

    if ($InputObject -notin $allowedEncodings) {
        $errorItem = [System.Management.Automation.ErrorRecord]::new(
            ([System.ArgumentException]"Invalid Encoding"),
            'InvalidEncoding',
            [System.Management.Automation.ErrorCategory]::InvalidType,
            $InputObject
        )
        $errorItem.ErrorDetails = "Cannot validate argument on parameter 'Encoding'. The argument `"$InputObject`" does not belong to the set `"$($allowedEncodings -join ", ")`" specified by the ValidateSet attribute. Supply an argument that is in the set and then try the command again."
        $PSCmdlet.ThrowTerminatingError($errorItem)
    }

    return $true
}

function Invoke-ConditionalParameterValidationPath {
    param(
        $InputObject
    )

    if (-not (Test-Path $InputObject -IsValid)) {
        $errorItem = [System.Management.Automation.ErrorRecord]::new(
            ([System.ArgumentException]"Path not found"),
            'ParameterValue.FileNotFound',
            [System.Management.Automation.ErrorCategory]::ObjectNotFound,
            $InputObject
        )
        $errorItem.ErrorDetails = "Invalid path '$InputObject'."
        $PSCmdlet.ThrowTerminatingError($errorItem)
    }
    else {
        return $true
    }
}

function Out-Key {
    param(
        [Parameter( Mandatory )]
        [Char]
        $CommentChar,

        [Parameter( Mandatory )]
        [String]
        $Delimiter,

        [Parameter( ValueFromPipeline )]
        [System.Collections.IDictionary]
        $InputObject,

        [Parameter()]
        [Switch]
        $IgnoreComments,

        [Parameter()]
        [Switch]
        $SkipTrailingEqualSign
    )

    begin {
        $outputLines = @()
    }

    process {
        if (-not ($InputObject.GetEnumerator().Name)) {
            Write-Verbose "$($MyInvocation.MyCommand.Name):: No data found in '$InputObject'."
            return
        }

        foreach ($key in $InputObject.GetEnumerator().Name) {
            if ($key -like "$script:CommentPrefix*") {
                if ($IgnoreComments) {
                    Write-Verbose "$($MyInvocation.MyCommand.Name):: Skipping comment: $key"
                }
                else {
                    Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing comment: $key"
                    $outputLines += "$CommentChar$($InputObject[$key])"
                }
            }
            elseif (-not $InputObject[$key]) {
                Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing key: $key without value"
                $outputLines += if ($SkipTrailingEqualSign) { "$key" } else { "${key}${Delimiter}" }
            }
            else {
                foreach ($entry in $InputObject[$key]) {
                    Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing key: $key"
                    $outputLines += "${key}${Delimiter}${entry}"
                }
            }
        }
    }

    end {
        return $outputLines
    }
}

function Write-DebugMessage {
    [CmdletBinding()]
    param(
        [Parameter( ValueFromPipeline )]
        $Message
    )

    begin {
        $oldDebugPreference = $DebugPreference
        if (!($DebugPreference -eq "SilentlyContinue")) {
            $DebugPreference = 'Continue'
        }
    }

    process {
        Write-Debug $Message
    }

    end {
        $DebugPreference = $oldDebugPreference
    }
}


