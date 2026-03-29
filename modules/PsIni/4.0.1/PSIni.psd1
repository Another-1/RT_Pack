@{
    RootModule             = 'PSIni.psm1'
    ModuleVersion          = '4.0.1'
    GUID                   = '98e1dc0f-2f03-4ca1-98bb-fd7b4b6ac652'
    Author                 = 'Oliver Lipkau <oliver@lipkau.net>'
    CompanyName            = 'Unknown'
    Copyright              = '(c) 2025 Oliver Lipkau. All rights reserved.'
    Description            = 'Convert hashtable to INI file and back'
    PowerShellVersion      = '5.0'
    PowerShellHostName     = ''
    PowerShellHostVersion  = ''
    DotNetFrameworkVersion = ''
    CLRVersion             = ''
    ProcessorArchitecture  = ''
    RequiredModules        = @()
    RequiredAssemblies     = @()
    ScriptsToProcess       = @()
    TypesToProcess         = @()
    FormatsToProcess       = @()
    NestedModules          = @()
    FunctionsToExport      = @('Export-Ini','Import-Ini')
    CmdletsToExport        = @()
    VariablesToExport      = @()
    AliasesToExport        = @('epini','ipini')
    ModuleList             = @()
    FileList               = @()
    PrivateData            = @{
        PSData = @{
            Tags       = @('ini', 'PSIni', 'PsIni')
            LicenseUri = 'https://github.com/lipkau/PSIni/blob/master/LICENSE'
            ProjectUri = 'https://github.com/lipkau/PSIni'
            # IconUri = ''
            # ReleaseNotes = ''
            # ExternalModuleDependencies = ''
        }
    }
}
