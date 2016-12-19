# Overview

[SQL Server Express Edition](https://www.microsoft.com/en-us/server-cloud/products/sql-server-editions/sql-server-express.aspx) is a scaled down, free edition of SQL Server, which includes the core database engine. While there are no limitations on the number of databases or users supported, it is limited to using 1 processor socket, 1 GB memory and 10 GB database files.

More information about the differences between SQL Server editions can be found on the [Microsoft website](https://msdn.microsoft.com/library/cc645993.aspx).

# Usage

## General Usage

To deploy a MSSQL Express service:

    juju deploy cs:~cloudbaseit/mssql-express --series <supported_windows_series>

# Configuration

* `version` - Choose the SQL Server Express version to be deployed. Supported
  versions: 2012, 2014. The installer specific to the version is downloaded
  from the Internet, checked for integrity with SHA1 checksum and then
  installed.

* `sa-password` - Password used by the System Administrator special login.

* `installer-url` - If provided, it overrides the default download url for the
  MSSQL installer. This should be provided, for example, when the MSSQL
  installer is found somewhere on a local web server.

NOTE: `version` and `installer-url` won't change anything
in the charm if dynamically changed. This values are used only in the `install`
hook, when service is installed.

SA password can be dynamically changed by:

    juju set mssql-express sa-password=Password123

NOTE: `sa-password` must respect the minimum complexity policy enforced by Microsoft. 
More details on this [page](https://msdn.microsoft.com/en-us/ms161959.aspx) at the section *Password Complexity*.
