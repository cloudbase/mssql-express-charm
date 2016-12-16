# Overview

[SQL Server Express Edition](https://www.microsoft.com/en-us/server-cloud/products/sql-server-editions/sql-server-express.aspx) is a scaled down, free edition of SQL Server, which includes the core database engine. While there are no limitations on the number of databases or users supported, it is limited to using 1 processor socket, 1 GB memory and 10 GB database files.

More information about the differences between SQL Server editions can be found on the [Microsoft website](https://msdn.microsoft.com/library/cc645993.aspx).

# Usage

## General Usage

To deploy a MSSQL Express service:

    juju deploy cs:~cloudbaseit/win2012r2/mssql-express

# Configuration

* `version` - Choose the SQL Server Express version to be deployed. Supported
  versions: 2012, 2014. The installer specific to the version is downloaded
  from the Internet, checked for integrity with SHA1 checksum and then
  installed.

* `sa-password` - Password used by the System Administrator special login.

* `installer-url` - If provided, it overrides the default download url for the
  MSSQL installer. This should be provided, for example, when the MSSQL
  installer is found somewhere on a local web server.

* `sha1-checksum` - Corresponds to the installer provided by the download url
  set by the user.

NOTE: `Version`, `installer-url` and `sha1-checksum` won't change anything
in the charm if dynamically changed. This values are used only in the `install`
hook, when service is installed.

SA password can be dynamically changed by:

    juju set mssql-express sa-password=Password123

NOTE: `sa-password` must respect the minimum complexity policy enforced by Microsoft. 
More details on this [page](https://msdn.microsoft.com/en-us/ms161959.aspx) at the section *Password Complexity*.

# Run unit tests

Unit tests are written in [Pester](https://github.com/pester/Pester) BDD framework. They can be executed in PowerShell on a Windows machine with Pester module installed.

Pester module can be installed on your system by running `get-requirements.ps1` script from the charm directory.

To run the unit tests, the script `run-tests.ps1` from charm directory can be used. Depending on the `TestModule` parameter given to the script, different sets of unit tests are executed.

Run unit tests for PowerShell CharmHelpers:

    run-tests.ps1 CharmHelpers

Run unit tests for MSSQL Express hooks module:

    run-tests.ps1 hooks
