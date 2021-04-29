#!/usr/bin/env python3

from github import Github, BadCredentialsException
import subprocess
import click
import datetime
import json
import requests
import time
import os.path
import webbrowser

import httplib2
import apiclient.discovery
from oauth2client.service_account import ServiceAccountCredentials

TOKEN_FILE = ".token"

GITHUB_OAUTH_CODE_ENDPOINT = "https://github.com/login/device/code"
GITHUB_OAUTH_ACCESS_TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"

HEADERS = {"Accept": "application/vnd.github.v3+json"}

CREDENTIALS_FILE = 'token.json'


def get_sheet():
    credentials = ServiceAccountCredentials.from_json_keyfile_name(CREDENTIALS_FILE, [
        'https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/drive'])

    httpAuth = credentials.authorize(httplib2.Http())
    service = apiclient.discovery.build('sheets', 'v4', http=httpAuth)

    sheet = service.spreadsheets()

    return sheet


def get_threshold_number():
    config = read_config()
    sheet = get_sheet()
    result = sheet.values().get(spreadsheetId=config["spreadsheet_id"],
                                range=config["threshold_coordinates"]).execute()
    return int(result["values"][0][0])


def get_multisig_address(multisig_account_name):
    get_multisig_address_command = ["terracli", "keys", "show", multisig_account_name, "-a"]

    result = subprocess.run(
        get_multisig_address_command, capture_output=True, text=True)
    try:
        result.check_returncode()
    except subprocess.CalledProcessError:
        print("Error occurred:", result.stderr)
        exit(1)
    return result.stdout.strip("\n")


def read_access_token():
    if os.path.isfile(TOKEN_FILE):
        with open(TOKEN_FILE) as f:
            return f.read()
    return None


def save_token(access_token):
    with open(TOKEN_FILE, "w+") as f:
        f.write(access_token)
        f.flush()


def is_token_valid(access_token):
    g = Github(access_token)
    try:
        config = read_config()
        g.get_repo(config["repo_name"])
    except BadCredentialsException:
        return False
    except Exception as e:
        print("Unexpected error:", e)
        exit(1)
    return True


def key_exists(key_name, ledger):
    generate_key_command = ["terracli", "keys",
                            "show", key_name, "--output=json"]
    if ledger:
        generate_key_command.append("--ledger")

    result = subprocess.run(generate_key_command, capture_output=True, text=True)
    try:
        result.check_returncode()
    except subprocess.CalledProcessError:
        return False
    return True


def get_github_access_token():
    token = read_access_token()
    if token is not None and is_token_valid(token):
        return token

    config = read_config()

    resp = json.loads(requests.post(GITHUB_OAUTH_CODE_ENDPOINT, data={
        "client_id": config["app_client_id"], "scope": "repo"}, headers=HEADERS).text)
    if "error" in resp.keys():
        print("Error occured:", resp)
        exit(1)

    print("First copy your one-time code: %s" % resp["user_code"])
    input("Press Enter to open a browser window and paste the code...")
    webbrowser.open(resp["verification_uri"], new=2)

    while True:
        access_token_response = json.loads(requests.post(GITHUB_OAUTH_ACCESS_TOKEN_ENDPOINT, data={
            "client_id": config["app_client_id"], "device_code": resp["device_code"],
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code"}, headers=HEADERS).text)
        if "error" in access_token_response.keys():
            if access_token_response["error"] != "authorization_pending":
                print("Error occured:", resp)
                exit(1)
            else:
                time.sleep(resp["interval"])
                continue

        if "access_token" in access_token_response.keys():
            save_token(access_token_response["access_token"])
            return access_token_response["access_token"]


def read_config(config="config.json"):
    with open(config) as f:
        return json.loads(f.read())


def find_row_by_tx_id(tx_id):
    config = read_config()
    sheet = get_sheet()
    result = sheet.values().get(spreadsheetId=config["spreadsheet_id"],
                                range='Process!A2:A').execute()
    for i in range(len(result["values"])):
        if len(result["values"]) > 0 and result["values"][i][0] == tx_id:
            return i + 2  # cause first line is header
    return None


@click.group()
def cli():
    pass


@cli.command()
def list_unsigned():
    """ Lists unsigned transactions (unmerged pull requests) """

    config = read_config()

    g = Github(get_github_access_token())
    repo = g.get_repo(config["repo_name"])

    pulls = repo.get_pulls(state='open', sort='created', base='master')
    for pr in pulls:
        files = pr.get_files()
        signers = ", ".join(map(lambda f: f.filename.split("/")[1].replace("_sign.json", ""),
                                filter(lambda f: not f.filename.endswith("unsigned_tx.json"), files)))
        print("TX ID #%d - %s" %
              (pr.number, pr.title))
        if len(signers) > 0:
            print("\t Signed by: %s" % signers)


@cli.command()
@click.argument('tx_id')
@click.argument('account_name')
@click.option('--chain-id', default="", help='Chain ID of tendermint node')
@click.option('--node', default="", help='<host>:<port> to tendermint rpc interface for this chain')
@click.option('--ledger', default=False, help='Use a connected Ledger device', is_flag=True)
@click.option('--multisig-account-name', default="multi", help='Name of the multisig account on your computer. '
                                                               '"multi" by default')
def sign(tx_id, account_name, multisig_account_name, chain_id, node, ledger):
    """ Signs tx and makes a commit to an corresponding PR\n
    TX_ID is id of a transaction you want to sign (run **list-unsigned** command to see ids)\n
    ACCOUNT_NAME is the name of the your terracli account created previously"""

    g = Github(get_github_access_token())
    config = read_config()

    repo = g.get_repo(config["repo_name"])
    pull = repo.get_pull(int(tx_id))
    files = pull.get_files()

    unsigned_tx_filename = list(
        filter(lambda f: f.filename.endswith("unsigned_tx.json"), files))
    if len(unsigned_tx_filename) == 0:
        print("Failed to get unsigned_tx.json")
        exit(1)

    unsigned_tx_content = repo.get_contents(
        unsigned_tx_filename[0].filename, ref=pull.head.ref).decoded_content
    unsigned_tx_file = open("/tmp/unsigned_tx.json", "wb")
    unsigned_tx_file.write(unsigned_tx_content)
    unsigned_tx_file.flush()

    sign_command = ["terracli", "tx", "sign", "/tmp/unsigned_tx.json",
                    "--multisig=%s" % get_multisig_address(multisig_account_name), "--from=%s" % account_name]
    if chain_id != "":
        sign_command.append("--chain-id=%s" % chain_id)
    if node != "":
        sign_command.append("--node=%s" % node)
    if ledger:
        sign_command.append("--ledger")

    result = subprocess.run(
        sign_command, capture_output=True, text=True)
    try:
        result.check_returncode()
    except subprocess.CalledProcessError:
        print("Error occurred:", result.stderr)
        exit(1)

    user_sign = list(
        filter(lambda f: f.filename.endswith("%s_sign.json" % account_name), files))
    if len(user_sign) > 0:
        file = repo.update_file(unsigned_tx_filename[0].filename.replace(
            "unsigned_tx.json", "%s_sign.json" % account_name), "%s sign" % account_name, result.stdout,
            user_sign[0].sha, branch=pull.head.ref)
    else:
        file = repo.create_file(unsigned_tx_filename[0].filename.replace(
            "unsigned_tx.json", "%s_sign.json" % account_name), "%s sign" % account_name, result.stdout,
            branch=pull.head.ref)

    print("Transaction %s successfully signed by %s" % (pull.title, account_name,))
    print("See signature on github: %s" % file["content"].html_url)

    print("Updating Google Sheets...")
    sheet = get_sheet()
    row = find_row_by_tx_id(tx_id)
    if row is None:
        print("TX #%d not found" % tx_id)
        exit(1)

    signed_by = sheet.values().get(spreadsheetId=config["spreadsheet_id"],
                                   range="Process!G%d" % row).execute()
    if "values" not in signed_by.keys():
        signed_by["values"] = [[account_name]]
    else:
        signed_by["values"][0][0] += "\n%s" % account_name

    body = {
        'values': signed_by["values"]
    }

    sheet.values().update(
        spreadsheetId=config["spreadsheet_id"], range="Process!G%d" % row,
        valueInputOption="RAW", body=body).execute()
    print("Done")


@cli.command()
@click.argument('tx_id')
@click.option('--broadcast', default=False, help='Send tx the blockchain', is_flag=True)
@click.option('--chain-id', default="", help='Chain ID of tendermint node')
@click.option('--node', default="", help='<host>:<port> to tendermint rpc interface for this chain')
@click.option('--ledger', default=False, help='Use a connected Ledger device', is_flag=True)
@click.option('--multisig-account-name', default="multi", help='Name of the multisig account on your computer. '
                                                               '"multi" by default')
def issue_tx(tx_id, broadcast, chain_id, multisig_account_name, node, ledger):
    """ If enough signatures, creates a multisig transaction and merges an corresponding PR\n

    TX_ID is id of a transaction you want to issue (run **list-unsigned** command to see ids)\n"""

    g = Github(get_github_access_token())
    config = read_config()

    repo = g.get_repo(config["repo_name"])
    pull = repo.get_pull(int(tx_id))
    files = pull.get_files()

    unsigned_tx_filename = list(
        filter(lambda f: f.filename.endswith("unsigned_tx.json"), files))
    if len(unsigned_tx_filename) == 0:
        print("Failed to get unsigned_tx.json")
        exit(1)

    sigs_files = list(
        filter(lambda f: not f.filename.endswith("unsigned_tx.json"), files))

    if len(sigs_files) < get_threshold_number():
        print("Not enough signatures")
        exit(1)

    unsigned_tx_content = repo.get_contents(
        unsigned_tx_filename[0].filename, ref=pull.head.ref).decoded_content
    unsigned_tx_file = open("/tmp/unsigned_tx.json", "wb")
    unsigned_tx_file.write(unsigned_tx_content)
    unsigned_tx_file.flush()

    signatures = []
    for sig in sigs_files:
        sig_content = repo.get_contents(
            sig.filename, ref=pull.head.ref).decoded_content
        local_name = "/tmp/" + sig.filename.replace("/", "_")
        sig_file = open(local_name, "wb")
        sig_file.write(sig_content)
        sig_file.flush()
        signatures.append(local_name)

    multisign_command = ["terracli", "tx",
                         "multisign", "/tmp/unsigned_tx.json", multisig_account_name]
    multisign_command.extend(signatures)
    if chain_id != "":
        multisign_command.append("--chain-id=%s" % chain_id)
    if node != "":
        multisign_command.append("--node=%s" % node)
    if ledger:
        multisign_command.append("--ledger")

    result = subprocess.run(multisign_command, capture_output=True, text=True)
    try:
        result.check_returncode()
    except subprocess.CalledProcessError:
        print("Error occurred:", result.stderr)
        exit(1)

    file = repo.create_file(unsigned_tx_filename[0].filename.replace(
        "unsigned_tx.json", "signed_tx.json"), "signed tx", result.stdout, branch=pull.head.ref)

    time.sleep(5)  # cause PR might not be ready

    pull = repo.get_pull(int(tx_id))

    pull.merge("signed tx", "signed tx", merge_method="merge", sha=file["commit"].sha)

    print("PR #%d has merged successfully" % pull.number)

    print("Updating Google Sheets...")
    sheet = get_sheet()
    row = find_row_by_tx_id(tx_id)
    if row is None:
        print("TX #%d not found" % tx_id)
        exit(1)

    status = sheet.values().get(spreadsheetId=config["spreadsheet_id"],
                                range="Process!D%d" % row).execute()
    status["values"] = [["Signed"]]

    body = {
        'values': status["values"]
    }

    sheet.values().update(
        spreadsheetId=config["spreadsheet_id"], range="Process!D%d" % row,
        valueInputOption="RAW", body=body).execute()
    print("Done")

    if broadcast:
        print("Broadcasting tx..")
        with open("/tmp/signed_tx.json", "w+") as f:
            f.write(result.stdout)
            f.flush()
        broadcast_command = ["terracli", "tx", "broadcast", "/tmp/signed_tx.json", "--broadcast-mode=block", "-y",
                             "--output=json"]
        if chain_id != "":
            broadcast_command.append("--chain-id=%s" % chain_id)
        if node != "":
            broadcast_command.append("--node=%s" % node)
        if ledger:
            broadcast_command.append("--ledger")

        result = subprocess.run(broadcast_command, capture_output=True, text=True)
        try:
            result.check_returncode()
        except subprocess.CalledProcessError:
            print("Error occurred:", result.stderr)
            exit(1)

        result_json = json.loads(result.stdout)
        if "txhash" not in result_json.keys():
            print("Failed to parse output of tx broadcast command")
            print("Output: %s", result)
            exit(1)

        print("Updating Google Sheets...")
        body = {
            'values': [[result_json["txhash"]]]
        }

        sheet.values().update(
            spreadsheetId=config["spreadsheet_id"], range="Process!H%d" % row,
            valueInputOption="RAW", body=body).execute()
        print("Done")


@cli.command()
@click.argument('tx_type')
@click.argument('tx_file')
@click.argument('account_name')
@click.option('--description', default="", help='Description of the tx')
def new_tx(tx_type, tx_file, account_name, description):
    """Creates a new folder with unsigned_tx, makes a pull request and updates the Google Sheets spreadsheet\n

    TX_TYPE - a small title of the transaction (name, type, etc.)\n
    TX_FILE - a path to an unsigned tx file\n
    ACCOUNT_NAME is the name of the your terracli account created previously"""

    if description == "":
        description = tx_type

    g = Github(get_github_access_token())
    config = read_config()

    time = datetime.datetime.now()
    tx = open(tx_file).read()

    folder_name = "%s_%s" % (tx_type, time.date())

    repo = g.get_repo(config["repo_name"])
    master_sha = repo.get_git_ref("heads/master").object.sha

    repo.create_git_ref("refs/heads/%s" % folder_name, master_sha)
    file = repo.create_file(folder_name + "/unsigned_tx.json",
                            "unsigned_tx", tx, branch=folder_name)

    pr = repo.create_pull(title=tx_type, body=description,
                          head=folder_name, base="master")

    print("PR #%d for tx %s created" % (pr.number, tx_type))
    print("See on Github: %s" % pr.html_url)

    print("Updating Google Sheets...")
    sheet = get_sheet()
    body = {
        'values': [[pr.number, description, time.date().strftime('%m/%d/%Y'), "Signing", account_name,
                    file["content"].html_url]]
    }

    sheet.values().append(
        spreadsheetId=config["spreadsheet_id"], range="Process!A2:G2",
        body=body, valueInputOption="RAW").execute()
    print("Done")


@cli.command()
@click.argument('tx_id')
@click.argument('tx_file')
def update_tx(tx_id, tx_file):
    """Updates a tx file in PR\n"""

    g = Github(get_github_access_token())
    config = read_config()

    tx = open(tx_file).read()

    repo = g.get_repo(config["repo_name"])
    pull = repo.get_pull(int(tx_id))
    files = pull.get_files()

    unsigned_tx_file = list(
        filter(lambda f: f.filename.endswith("unsigned_tx.json"), files))
    if len(unsigned_tx_file) == 0:
        print("Failed to get unsigned_tx.json")
        exit(1)

    updated_file = repo.update_file(unsigned_tx_file[0].filename, "update unsigned tx", tx, unsigned_tx_file[0].sha,
                                    branch=pull.head.ref)

    print("Tx for PR #%d was updated" % pull.number)
    print("See on Github: %s" % updated_file["content"].html_url)


def share_pubkey_in_spreadsheet(keyname, pubkey, spreadsheet_id):
    print("Updating Google Sheets...")
    add_pubkey_command = "terracli keys add %s --pubkey=%s" % (keyname, pubkey)
    sheet = get_sheet()
    body = {
        'values': [[keyname, pubkey, add_pubkey_command]]
    }

    sheet.values().append(
        spreadsheetId=spreadsheet_id, range="Participants!A2:C2",
        body=body, valueInputOption="RAW").execute()
    print("Done")


@cli.command()
@click.option('--name', default="", help='Name of your key. By default your github username is used')
@click.option('--ledger', default=False, help='Use a connected Ledger device', is_flag=True)
def generate_key(name, ledger):
    """Generates personal Terra key, saves it to your local keybase (or ledger) and updates the spreadsheet"""

    g = Github(get_github_access_token())
    config = read_config()

    key_name = name
    if key_name == "":
        key_name = g.get_user().login

    if key_exists(key_name, ledger):
        print('Key with name "%s" already exists. Please, specify another name or remove the existed key.' % key_name)
        print('If you want to use the existed key, execute "share-pubkey" command.')
        return

    generate_key_command = ["terracli", "keys",
                            "add", key_name, "--output=json"]
    if ledger:
        generate_key_command.append("--ledger")

    result = subprocess.run(generate_key_command, capture_output=True, text=True)
    try:
        result.check_returncode()
    except subprocess.CalledProcessError:
        print("Error occurred:", result.stderr)
        exit(1)

    json_result = json.loads(result.stderr)

    print("name: %s" % json_result["name"])
    print("address: %s" % json_result["address"])
    print("pubkey: %s" % json_result["pubkey"])
    print("""\n**Important** write this mnemonic phrase in a safe place.
            It is the only way to recover your account if you ever forget your password.\n""")
    print("Mnemonic: %s" % json_result["mnemonic"])

    print()
    share_pubkey_in_spreadsheet(json_result["name"], json_result["pubkey"], config["spreadsheet_id"])


@cli.command()
@click.option('--name', default="", help='Name of your key. By default your github username is used')
@click.option('--ledger', default=False, help='Use a connected Ledger device', is_flag=True)
def share_pubkey(name, ledger):
    """Updates the spreadsheet with the existed key"""

    g = Github(get_github_access_token())
    config = read_config()

    key_name = name
    if key_name == "":
        key_name = g.get_user().login

    get_key_command = ["terracli", "keys",
                       "show", key_name, "-p"]
    if ledger:
        get_key_command.append("--ledger")

    result = subprocess.run(get_key_command, capture_output=True, text=True)
    try:
        result.check_returncode()
    except subprocess.CalledProcessError:
        print("Error occurred:", result.stderr)
        exit(1)

    share_pubkey_in_spreadsheet(key_name, result.stdout.rstrip(), config["spreadsheet_id"])


@cli.command()
@click.option('--name', default="", help='Name of your personal key. By default your github username is used')
@click.option('--ledger', default=False, help='Use a connected Ledger device', is_flag=True)
def generate_multisig_key(name, ledger):
    g = Github(get_github_access_token())
    config = read_config()

    key_name = name
    if key_name == "":
        key_name = g.get_user().login

    sheet = get_sheet()
    result = sheet.values().get(spreadsheetId=config["spreadsheet_id"],
                                range="Participants!A2:B").execute()

    for value in result["values"]:
        if value[0] != key_name:
            print("Adding key from %s..." % value[0])
            if key_exists(value[0], ledger):
                print('Key with name "%s" already exists. Remove the existed key or rename it' % value[0])
                continue

            add_pubkey_command = "terracli keys add %s --pubkey=%s" % (value[0], value[1])
            result = subprocess.run(add_pubkey_command.split(), capture_output=True, text=True)
            try:
                result.check_returncode()
            except subprocess.CalledProcessError:
                print("Error occurred:", result.stderr)
                exit(1)
            print("Done")

    participants = sorted([x[0] for x in result["values"]])
    multisig_account_name = "_".join(participants) + "_multisig"
    create_multisig_account_command = ["terracli", "keys", "add", multisig_account_name,
                                       "--multisig=%s" % ",".join(participants),
                                       "--multisig-threshold=%d" % get_threshold_number(),
                                       "--output=json"]
    if ledger:
        create_multisig_account_command.append("--ledger")

    result = subprocess.run(create_multisig_account_command, capture_output=True, text=True)
    try:
        result.check_returncode()
    except subprocess.CalledProcessError:
        print("Error occurred:", result.stderr)
        exit(1)

    print()
    print("Generating multisig account")
    result = subprocess.run("terracli keys show %s --output=json" % multisig_account_name, capture_output=True, text=True, shell=True)
    try:
        result.check_returncode()
    except subprocess.CalledProcessError:
        print("Error occurred:", result.stderr)
        exit(1)

    json_result = json.loads(result.stdout)

    print("multisig account name: %s" % json_result["name"])
    print("multisig address: %s" % json_result["address"])
    print("multisig pubkey: %s" % json_result["pubkey"])
    print()

    print("Updating Google Sheets...")
    sheet = get_sheet()
    body = {
        'values': [[json_result["address"]]]
    }

    sheet.values().append(
        spreadsheetId=config["spreadsheet_id"], range="Participants!I2",
        body=body, valueInputOption="RAW").execute()
    print("Done")


if __name__ == '__main__':
    cli()
