####################################################################################
####Version: 1.0                                                                   #
####Date: 11/04/2024                                                               #
####Author: M Jones                                                                #
####Description:Script to pull security details from SQL Server and place a summary#
####            in a text document                                                 #
####################################################################################
### Version History:                                                               #
### Version    Date      Author                      Details                       #
####################################################################################
### 1.0         11/04/24 M Jones             Initial Document                      #
####################################################################################

#list of modules which may need importing before running script
#Import-Module SQLServer
#Import-Module Az-Accounts
#Install-Module -Name Az -Repository PSGallery -Force -Scope CurrentUser
#init variables and other details 
$run_date = get-date -DisplayHint Date 
$instance_name = ''
$connectionstring = 'Server=tcp:'+$instance_name+';Persist Security Info=False;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Authentication="Active Directory Integrated"'; #currently configured for Azure MI, change as required 
$instance_file =  $instance_name.Substring(0,$instance_name.IndexOf('.')) + $run_date.Year + $run_date.Month + $run_date.Day
$Document_location = "" + $instance_file + ".txt"
$loginarray = New-Object collections.arraylist
$rolearray=@()
$rolefinal = @()
$database = @()
$userarray = @()
$userfinal = @()
$orphanarray = @()
$orphanfinal = @()
$propertyarray =@()
$propertyfinal = @()
$database_listing = "select a.name,isnull(b.name ,'No Owner')'login' from sys.databases a 
left outer join sys.syslogins b on a.owner_sid = b.sid" 
$login_script = "select name,denylogin, hasaccess,sysadmin,securityadmin, serveradmin, setupadmin, processadmin, diskadmin, dbcreator, bulkadmin,
##MS_ServerSecurityStateReader## 'MS_ServerSecurityStateReader',##MS_ServerStateManager## 'MS_ServerStateManager',##MS_DefinitionReader## 'MS_DefinitionReader',##MS_DatabaseConnector## 'MS_DatabaseConnector',##MS_DatabaseManager## 'MS_DatabaseManager'
,##MS_LoginManager## 'MS_LoginManager',##MS_PermissionDefinitionReader## 'MS_PermissionDefinitionReader',##MS_ServerPermissionStateReader## 'MS_ServerPermissionStateReader'
from sys.syslogins  "


function get_login_property($instane){ #pull current properties of all SQL logins for review

$propertyquery = "select a.name,a.is_disabled,is_policy_checked,is_expiration_checked from  sys.server_principals a
INNER JOIN sys.sql_logins b 
ON a.principal_id = b.principal_id "


$property_results = Invoke-Sqlcmd -connectionstring $connectionstring  -Query $propertyquery


foreach ($p in $property_results){

        $e = New-Object PSobject
        $e|add-member -MemberType NoteProperty -Name LoginName -Value $p.name
        $e|add-member -MemberType NoteProperty -Name Disabled -Value $p.is_disabled
        $e|add-member -MemberType NoteProperty -Name PolicyEnabled -Value $p.is_policy_checked
        $e|add-member -MemberType NoteProperty -Name ExpirationEnabled -Value $p.is_expiration_checked
        $propertyarray += @($e)
    



}


return $propertyarray


}


function get_orphans($instance,$db){ #Finds all orphaned logins in Instance databases 

$orphanedU_query = "use ["+ $db +"] SELECT SU.name FROM sysusers SU
left outer join syslogins SL on su.[SID] = SL.[SID]
where issqlrole = 0 and Su.name not in (
'guest','information_schema','sys') and Sl.name is null"



#Write-Output $orphanedU_query
$orphan_result = Invoke-Sqlcmd -connectionstring $connectionstring  -Query $orphanedU_query
#Write-Output $orphan_result

foreach($q in $orphan_result) {


    $ou = New-Object -TypeName PSObject 
    $ou|Add-Member -MemberType NoteProperty -Name DBName -value $db
    $ou|Add-Member -MemberType NoteProperty -Name orphaneduser -value $q.name
    $orphanarray += @($ou)



}

return $orphanarray

}

function get_users($instance,$db){ #lists all users in each Database and the groups they are members of 

$user_query = " use [" + $db + "] SELECT 
    DP1.name AS DatabaseRoleName
    ,ISNULL(DP2.name, 'No members') AS DatabaseUserName
    ,DP2.principal_id
    ,DP2.create_date
FROM sys.database_role_members AS DRM  
RIGHT OUTER JOIN sys.database_principals AS DP1 ON DRM.role_principal_id = DP1.principal_id  
LEFT OUTER JOIN sys.database_principals AS DP2  ON DRM.member_principal_id = DP2.principal_id  
WHERE DP1.type = 'R'
ORDER BY DP1.name, ISNULL(DP2.name, 'No members')"


$user_result = Invoke-Sqlcmd -connectionstring $connectionstring  -Query $user_query

$uniquename =  $user_result.DatabaseUserName|Where-Object{$_ -ne "No members"}
$uniquename = get-unique -InputObject $uniquename
$uniquerole = $user_result.DatabaseRoleName|get-unique

foreach ($u in $uniquename ) { #iterate through all users on the Database 
    
        $selected_users = $user_result|Where-Object{$_.DatabaseUserName -eq $u}
        foreach ($se in $selected_users) {
    
        $us = New-Object -TypeName PSObject 
        $us|Add-Member -MemberType NoteProperty -Name DBName -value $db
        $us|Add-Member -MemberType NoteProperty -Name UserName -value $se.DatabaseUserName
        foreach($ro in $uniquerole){ #iterate through all roles that the user has  
        $isrole = $(if ($se.DatabaseRoleName -eq $ro) {"1"} else {"0"})
        $us|Add-Member -MemberType NoteProperty -Name $ro -value $isrole



        }
        $userfinal += @($us)


        }

}

return $userfinal

}

function get_roles($instance,$db){ #list all custom roles on the database and their permissions 
          
$database_roles = " use [" + $db + "]  SELECT DB_NAME() AS 'DBName'
      ,p.[name] AS 'PrincipalName'
      ,p.[type_desc] AS 'PrincipalType'
      ,p2.[name] AS 'GrantedBy'
      ,dbp.[permission_name]
      ,dbp.[state_desc]
      ,so.[Name] AS 'ObjectName'
      ,so.[type_desc] AS 'ObjectType'
  FROM [sys].[database_permissions] dbp LEFT JOIN [sys].[objects] so
    ON dbp.[major_id] = so.[object_id] LEFT JOIN [sys].[database_principals] p
    ON dbp.[grantee_principal_id] = p.[principal_id] LEFT JOIN [sys].[database_principals] p2
    ON dbp.[grantor_principal_id] = p2.[principal_id]
    where p.[type_desc] = 'DATABASE_ROLE' and p.[name] not in ('public')
    order by p.[name]"


#Write-Output $database_roles
    $DBROLE = Invoke-Sqlcmd -connectionstring $connectionstring  -Query $database_roles 

    foreach ($r in $DBROLE) {
      
        $x = new-object -TypeName PSObject 
        $x| Add-Member -MemberType NoteProperty -Name DBName -value $r.DBName
        $x| Add-Member -MemberType NoteProperty -Name PrincipalName -value $r.PrincipalName
        $x| Add-Member -MemberType NoteProperty -Name PrincipalType -value $r.PrincipalType
        $x| Add-Member -MemberType NoteProperty -Name GrantedBy -value $r.GrantedBy
        $x| Add-Member -MemberType NoteProperty -Name permissionname -value $r.permission_name
        $x| Add-Member -MemberType NoteProperty -Name statedesc -value $r.state_desc
        $x| Add-Member -MemberType NoteProperty -Name ObjectName -value $r.ObjectName
        $x| Add-Member -MemberType NoteProperty -Name ObjectType -value $r.ObjectType
        $rolearray += @($x) 


    }




    return $rolearray



}

function get_logins($intance){#lists all logins and their server roles 


$loginresult = Invoke-Sqlcmd -connectionstring $connectionstring  -Query $login_script 


foreach ($t in $loginresult){

    $l = new-object -TypeName PSObject 
    $l|Add-Member -MemberType NoteProperty -Name loginname -value $t.name
    $l|Add-Member -MemberType NoteProperty -Name logindenied -value $t.denylogin
    $l|Add-Member -MemberType NoteProperty -Name serveraccess -value $t.hasaccess
    $l|Add-Member -MemberType NoteProperty -Name sysadmin -value $t.sysadmin
    $l|Add-Member -MemberType NoteProperty -Name securityadmin -value $t.securityadmin
    $l|Add-Member -MemberType NoteProperty -Name serveradmin -value $t.serveradmin
    $l|Add-Member -MemberType NoteProperty -Name setupadmin -value $t.setupadmin
    $l|Add-Member -MemberType NoteProperty -Name processadmin -value $t.processadmin
    $l|Add-Member -MemberType NoteProperty -Name diskadmin -value $t.diskadmin
    $l|Add-Member -MemberType NoteProperty -Name dbcreator -value $t.dbcreator
    $l|Add-Member -MemberType NoteProperty -Name bulkadmin -value $t.bulkadmin
    $l|Add-Member -MemberType NoteProperty -Name MSServerSecurityStateReader -value $t.MS_ServerSecurityStateReader
    $l|Add-Member -MemberType NoteProperty -Name MSServerStateManager -value $t.MS_ServerStateManager
    $l|Add-Member -MemberType NoteProperty -Name MSDefinitionReader -value $t.MS_DefinitionReader
    $l|Add-Member -MemberType NoteProperty -Name MSDatabaseConnector -value $t.MS_DatabaseConnector
    $l|Add-Member -MemberType NoteProperty -Name MSDatabaseManager -value $t.MS_DatabaseManager
    $l|Add-Member -MemberType NoteProperty -Name MSLoginManager -value $t.MS_LoginManager
    $l|Add-Member -MemberType NoteProperty -Name MSPermissionDefinitionReader -value $t.MS_PermissionDefinitionReader
    $l|Add-Member -MemberType NoteProperty -Name MSServerPermissionStateReader -value $t.MS_ServerPermissionStateReader
    $loginarray += @($l)



}
return $loginarray

} 




$database_results =  Invoke-Sqlcmd -connectionstring $connectionstring  -Query $database_listing #finds all DBs on the instance and the owners 
$loginarray = get_logins($instance_name)
$database = $database_results.name


##start the document with a list of sysadmins##

Write-Output "Security Breakdown: $run_date "|Tee-Object -FilePath $Document_location
Write-Output "" |Tee-Object -FilePath $Document_location -Append
Write-Output "Instance Name: $instance_name" |Tee-Object -FilePath $Document_location -Append
Write-Output "" |Tee-Object -FilePath $Document_location -Append
Write-Output "---SYSADMIN ACCOUNT---" |Tee-Object -FilePath $Document_location -Append
Write-Output "" |Tee-Object -FilePath $Document_location -Append

$sysadmins = $loginarray |Where-Object {$_.sysadmin -eq 1}|select loginname,logindenied,serveraccess,sysadmin|format-table -AutoSize

Write-Output $sysadmins|Tee-Object -FilePath $Document_location -Append
Write-Output "" |Tee-Object -FilePath $Document_location -Append
##Lists all logins on the system
Write-Output "System Logins"|Tee-Object -FilePath $Document_location -Append
Write-Output "" |Tee-Object -FilePath $Document_location -Append

Write-Output $loginarray|format-table|Tee-Object -FilePath $Document_location -Append 
##lists all SQL Server Logins 
Write-Output "" |Tee-Object -FilePath $Document_location -Append
Write-Output "SQL Logins Properties"|Tee-Object -FilePath $Document_location -Append
Write-Output "" |Tee-Object -FilePath $Document_location -Append

$propertyfinal = get_login_property($instance_name)
write-output $propertyfinal|format-table|Tee-Object -FilePath $Document_location -Append

Write-Output "" |Tee-Object -FilePath $Document_location -Append
#iterates through the databases for database level configs
foreach ($d in $database){
$dbowner = $database_results|Where-Object{$_.name -eq $d}|select login #shows the DB owner 
Write-Output $d|Tee-Object -FilePath $Document_location -Append
Write-Output "" |Tee-Object -FilePath $Document_location -Append
write-output "owned by: $dbowner"|Tee-Object -FilePath $Document_location -Append
Write-Output "" |Tee-Object -FilePath $Document_location -Append
$rolefinal  = get_roles -instance  $instance_name -db  $d

$userfinal = get_users -instance  $instance_name -db  $d
Write-Output "" |Tee-Object -FilePath $Document_location -Append
Write-Output "User Permissions - Groups " |Tee-Object -FilePath $Document_location -Append
Write-Output "" |Tee-Object -FilePath $Document_location -Append
if($userfinal.Length -eq 0 ) { #will list all users in the DB or state if there are none 
Write-Output "There are no users"|Tee-Object -FilePath $Document_location -Append
Write-Output "" |Tee-Object -FilePath $Document_location -Append

}
else {
Write-Output $userfinal|Format-Table|Tee-Object -FilePath $Document_location -Append
}
Write-Output "" |Tee-Object -FilePath $Document_location -Append
Write-Output "Role Breakdowns " |Tee-Object -FilePath $Document_location -Append
Write-Output "" |Tee-Object -FilePath $Document_location -Append
if ($rolefinal.Length -eq 0) { #will list all roles in the DB or state if there are none 
Write-Output "There are no roles"|Tee-Object -FilePath $Document_location -Append
Write-Output "" |Tee-Object -FilePath $Document_location -Append
}
else {
write-output $rolefinal|Format-Table|Tee-Object -FilePath $Document_location -Append
}
Write-Output "" |Tee-Object -FilePath $Document_location -Append
Write-Output "Orphaned Users " |Tee-Object -FilePath $Document_location -Append
Write-Output "" |Tee-Object -FilePath $Document_location -Append
$orphanfinal = get_orphans -instance $instance_name -db $d
if ($orphanfinal.Length -eq 0) { #will list all Orphaned users in the DB or state if there are none 
Write-Output "There are no Orphaned users"|Tee-Object -FilePath $Document_location -Append
Write-Output "" |Tee-Object -FilePath $Document_location -Append


}
else 
{

Write-Output $orphanfinal|Format-Table|Tee-Object -FilePath $Document_location -Append

}


}

