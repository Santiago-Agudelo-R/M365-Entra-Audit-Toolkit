@{
    Severity     = @('Error', 'Warning', 'Information')

    ExcludeRules = @(
        'PSUseDeclaredVarsMoreThanAssignments'
    )

    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.4')
        }
    }
}
