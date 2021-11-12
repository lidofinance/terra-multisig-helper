# Generating Github APP ID

The multisig helper script requires a Github APP ID to work with Github (to share multsignatures, etc.).

This is an instruction on how to create an App and ID by yourself.

## Steps

1. Go to https://github.com/settings/apps
2. Click "New Github App"
3. Fill in all the neccessary (name, description) fields as you want.
4. Give persmission to the app:
    1. **Contents** - Read & write
    2. **Metadata** - Read-only
    3. **Pull requests** - Read & write
    4. **Webhook** - disabled
    5. **Where can this GitHub App be installed?** - Any account
5. Create the app
6. You'll see your APP ID on APP's *About* page

If you want to install the app on a user/repo make sure you give the app access only to selected repositories.