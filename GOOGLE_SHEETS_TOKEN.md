# Generating Google API token
The multisig helper script requires a Google API token to work with Google Sheets (to update multsig txs info, etc.).

This is an instruction on how to generate a token yourself.

## Steps

1. Open https://console.developers.google.com/
2. Create a new project
3. `Search for APIs & Services` in `Library`:
    1. Google Drive - Enable
    2. Create credentials
    3. Which API are you using? - Google Drive API
    4. What data will you be accessing? - Application Data
    5. Are you planning to use this API with Compute Engine, Kubernetes Engine, App Engine or Cloud Functions? - No
    6. Service account details - fill in like you want and press a `Create` button
    7. Grant this service account access to the project:
        1. Select a role: Project -> Editor
    8. Grant users access to this service account - Leave it blank, press `Done`
    9. Click on your created service account to see more info about it
    10. Open `Keys` tab
    11. `ADD KEY` -> `Create new key` -> JSON -> Press create - Your key will be downloaded on your computer
    12. Open the downloaded json file -> copy `client_email` field
    13. Open a necessary spreadsheet
    14. Share access with the copied email
    15. Now you can use your downloaded token with the multisig helper!
    