Migrations:

1. go to AuthApi project directory
   Execute: ./migrate.sh

   OR

2. dotnet ef --project ../AuthApi.Data/AuthApi.Data.csproj database drop
3. dotnet ef --project ../AuthApi.Data/AuthApi.Data.csproj migrations remove
4. dotnet ef --project ../AuthApi.Data/AuthApi.Data.csproj migrations add InitialCreate
5. dotnet ef --project ../AuthApi.Data/AuthApi.Data.csproj database update
6. From AuthApi root project run "dotnet run seeddata"

Common Errors
The Body inferred error: means some services are not registered in the dependency injection class under Startup folder
project AuthApi.Core specifically either in RegisterServices or in RegisterValidators
Sometimes the fronend stop working and data stop being returned by the server. Check The Token validity. Logout and then login to solve the problem. Do not tear your hair

Publish to IIS
dotnet publish --configuration Release
Then copy the content under the below publish folder to IIS AuthApi folder
AuthApi -> /Users/ismatayash/Projects/ContactCenter/AuthApiProjects/AuthApi/bin/Release/net7.0/publish/
The folder Attachments must exist on the AuthApi folder on IIS and Modify permission should be given to it for the IISUSERS user

Logs
Log file logged daily and saved on the server under C:/Auth/logs delete from time to time

Repository Folder in the Core project
It is not used and may be deleted only kept as a sample on how to write Generic Repos and unit of work.

Method Not Allowed problem PUT and DELETE
If for any reason got a cross origin method not allowed error mainly for PUT and DELETE verbs. Go to the windows server and remove WebDav. Follow this link to achieve this https://learn.microsoft.com/en-us/answers/questions/1009216/create-application-site-which-allows-put-request-o
