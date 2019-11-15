param (
    $user = $(throw "-user is a required option.  Use DOMAIN\username formatting.")
)

Import-module activedirectory
 
Function Check-ADUserPermission(
    [System.DirectoryServices.DirectoryEntry]$entry, 
    [string]$user, 
    [string]$permission)
{
    $dse = [ADSI]"LDAP://Rootdse"
    $ext = [ADSI]("LDAP://CN=Extended-Rights," + $dse.ConfigurationNamingContext)
 
    $right = $ext.psbase.Children | 
        ? { $_.DisplayName -eq $permission }
 
    if($right -ne $null)
    {
        $perms = $entry.psbase.ObjectSecurity.Access |
            ? { $_.IdentityReference -eq $user } |
            ? { $_.ObjectType -eq [GUID]$right.RightsGuid.Value }
 
        return ($perms -ne $null)
    }
    else
    {
        Write-Warning "Permission '$permission' not found."
        return $false
    }
}
 
Function Check-ReplicateChanges([string]$userName)
{
    # Globals
    $replicationPermissionName = "Replicating Directory Changes"
 
    # Main()
    $dse = [ADSI]"LDAP://Rootdse"
 
    $entries = @(
        [ADSI]("LDAP://" + $dse.defaultNamingContext) #, [ADSI]("LDAP://" + $dse.configurationNamingContext)
        );
    Write-Host " User '$userName': "
 
    foreach($entry in $entries)
    {
        $result = Check-ADUserPermission $entry $userName $replicationPermissionName
        if($result)
        {
            Write-Host "   has '$replicationPermissionName' permissions on '$($entry.distinguishedName)'" `
        }
        else
        {
            Write-Host "   does NOT have '$replicationPermissionName' permissions on '$($entry.distinguishedName)'" `
        }
    }
}
 
Check-ReplicateChanges $user