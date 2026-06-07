@{
    Severity     = @('Error', 'Warning')
    IncludeRules = @(
        'PSAvoidDefaultValueSwitchParameter',
        'PSAvoidGlobalVars',
        'PSAvoidUsingCmdletAliases',
        'PSAvoidUsingEmptyCatchBlock',
        'PSAvoidUsingInvokeExpression',
        'PSAvoidUsingPlainTextForPassword',
        'PSAvoidUsingUsernameAndPasswordParams',
        'PSMisleadingBacktick',
        'PSMissingModuleManifestField',
        'PSPossibleIncorrectComparisonWithNull',
        'PSPossibleIncorrectUsageOfAssignmentOperator',
        'PSPossibleIncorrectUsageOfRedirectionOperator',
        'PSUseCmdletCorrectly',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSUseOutputTypeCorrectly',
        'PSUsePSCredentialType',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSupportsShouldProcess'
    )
    ExcludeRules = @(
        # The module intentionally prints a concise completion summary for interactive operators.
        'PSAvoidUsingWriteHost',
        # Existing public API includes Build-* / Sync-* commands and plural snapshot names; keep compatibility stable.
        'PSUseApprovedVerbs',
        'PSUseSingularNouns',
        # The audit API uses age/threshold parameter names such as IncludeAclPrivilegedUsers and PasswordAgeDays,
        # not username/password credential pairs.
        'PSAvoidUsingUsernameAndPasswordParams',
        # Several AD collector parameters are consumed inside nested functions/scriptblocks that PSScriptAnalyzer
        # cannot reliably resolve.
        'PSReviewUnusedParameter',
        # Exported report writers are intentionally imperative and file-oriented.
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSupportsShouldProcess'
    )
    Rules = @{
        PSUseConsistentIndentation = @{
            Enable              = $true
            Kind                = 'space'
            PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
            IndentationSize     = 4
        }
        PSUseConsistentWhitespace = @{
            Enable          = $true
            CheckInnerBrace = $true
            CheckOpenBrace  = $true
            CheckOpenParen  = $true
            CheckOperator   = $true
            CheckPipe       = $true
            CheckSeparator  = $true
        }
    }
}
