# persistence-get-winevent
***Uses the get-winevent cmdlet to query windows events of several persistence mechanisms a threat actor can use on a windows host. 
***Events queried include scheduled task creation (106 and sec 4698 events), user manipulation, group manipulation, service creation and wmi binds.
***Also checks if logs were cleared.
***Creates a file named "persistence_check.txt" in system drive.
