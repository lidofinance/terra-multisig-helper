## Terra Multisig Process Testnet

### Installing Terra software from prebuilt binaries

**There is no support of ledger devices in these prebuilt binaries. So if you want to use ledger, build binaries from sources (instructions below)**


#### Step 1. Download binaries

Download an archive with binaries for your platform from the official Terra [repository](https://github.com/terra-project/core/releases/tag/v0.4.4)

#### Step 2. Install binaries

Open a folder with the downloaded archive in a terminal and execute one the following command (depends on your platform):

##### MacOS installation:
```shell
foo@bar:~$ tar -C /usr/local/bin -xzf terra_0.4.4_Darwin_x86_64.tar && mv /usr/local/bin/libgo_cosmwasm.dylib /usr/local/lib/
```

##### Linux installation:
```shell
foo@bar:~$ tar -C /usr/local/bin -xzf terra_0.4.4_Linux_x86_64.tar
```

#### Step 4: Verify your installation

Verify that everything is OK. If you get something like the following, you've successfully installed Terra Core on your system.
```shell
foo@bar:~$ terracli version --long
name: terra
server_name: terrad
client_name: terracli
version: 0.3.0-24-g3684f77
commit: 3684f77faadf6cf200d18e15763316d5d9c5a496
build_tags: netgo,ledger
go: go version go1.13.4 darwin/amd64
```

### Building Terra software from source (skip this, if you've installed prebuilt binaries)

#### Step 1. Install Golang

`Go v1.13.1 or higher is required for Terra Core.`

If you haven't already, install Golang by following the [official docs](https://golang.org/doc/install). Make sure that your `GOPATH` and `GOBIN` environment variables are properly set up.

#### Step 2: Get Terra Core source code

Use `git` to retrieve Terra Core from the [official repo](https://github.com/terra-project/core/), and checkout the `master` branch, which contains the latest stable release. That should install the `terrad` and `terracli` binaries.

```bash
foo@bar:~$ git clone https://github.com/terra-project/core
foo@bar:~$ cd core
foo@bar:~$ git checkout master
```

#### Step 3: Build from source

You can now build Terra Core. Running the following command will install executables `terrad` (Terra node daemon) and `terracli` (CLI for interacting with the node) to your `GOPATH`.

```bash
foo@bar:~$ make install
```

#### Step 4: Verify your installation

Verify that everything is OK. If you get something like the following, you've successfully installed Terra Core on your system.
```shell
foo@bar:~$ terracli version --long
name: terra
server_name: terrad
client_name: terracli
version: 0.3.0-24-g3684f77
commit: 3684f77faadf6cf200d18e15763316d5d9c5a496
build_tags: netgo,ledger
go: go version go1.13.4 darwin/amd64
```

### Multisig Helper

#### *Disclaimer*
**At the first launch, you will be redirected to the authorization page for the Github App with permission to grant access to the account. It looks scary, but no one but you will have access to your private repositories and personal data. The helper script needs to get an Oauth token so that you can automatically create commits, pull requests and other stuff in our private repository (lido-multisigs/terra-testnet-multisigs). The token is stored only on your device (.token file in the root of repository) and is not sent anywhere. You can revoke access at any time here: https://github.com/settings/apps/authorizations**

In a multisig process participants must sign transcations, share their individual signatures with other participants, someone must
collect them, create final mutlisig transaction and broadcast it. In addition, participants should fill in Google Sheets spreadsheet to store an info about transactions.
This process is a boring and tedious so we've developed a script called `multsig_helper.py`.

The script simplifies a process of signing, sharing signatures and updating a spreadsheet.

#### Requirements
* Python 3 ([Install instructions](https://installpython3.com/))

#### Install the script

```shell
foo@bar:~$ git clone git@github.com:lidofinance/terra-multisig-helper.git

foo@bar:~$ cd terra-multisig-testnet

foo@bar:~$ pip3 install -r requirements.txt
```

#### Configuration file

Configuration of the script is located in `config.json` file:

```
{
    "repo_name": "lidofinance/terra-multisig-testnet", // Name of the repository where signatures and transations will be located
    "app_client_id": "XXXXXXXXX", // Client ID of Github App
    "spreadsheet_id": "XXXXXXXX" // ID of a spreadsheet contained tx and participants info
}
```

You don't have to fill the file manually, a correct one will be shared in the private TG group.

#### Google API token
A pre-generated Google API token (with editor rights to the testnet spreadsheet only) will be shared in the private TG group.

But just in case there is an [instruction](https://github.com/lidofinance/terra-multisig-helper/blob/master/GOOGLE_SHEETS_TOKEN.md) on how to generate the service token manually.

#### Networks
| Chain ID       | Description        | RPC Node                      |
| -------------- | ------------------ | ----------------------------- |
| `tequila-0004` | Columbus-4 Testnet | http://15.164.0.235:26657     |

#### Usage

To see all possible commands of the script, run:
```shell
foo@bar:~$ ./multisig-helper.py --help

Usage: multisig-helper.py [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  generate-key               Generates personal Terra key, saves it to your...
  generate-multisig-account  Imports public keys of another participants...
  issue-tx                   If enough signatures, creates a multisig...
  list-unsigned              Lists unsigned transactions (unmerged pull...
  new-tx                     Creates a new folder with unsigned_tx, makes a...
  share-pubkey               Updates the spreadsheet with the existed key
  sign                       Signs tx and makes a commit to an
                             corresponding...

  update-tx                  Updates a tx file in PR
```

To see more info about particular command, just specify `--help` flag when executing a command.

##### Generate keys

You'll need an account private and public key pair (a.k.a. sk, pk respectively) to be able to be a part of a multisig account.

To generate an account, just use the following command:

```shell
foo@bar:~$ ./multisig-helper.py generate-key

name: yourKeyName
address: terra1x46rqay4d3cssq8gxxvqz8xt6nwlz4td20k38v
pubkey: terrapub1addwnpepqgcxazmq6wgt2j4rdfumsfwla0zfk8e5sws3p3zg5dkm9007hmfysxas0u2

**Important** write this mnemonic phrase in a safe place.
            It is the only way to recover your account if you ever forget your password.

Mnemonic: notice oak worry limit wrap speak medal online prefer cluster roof addict wrist behave treat actual wasp year salad speed social layer crew genius

Updating Google Sheets...
Done
```

* `yourKeyName` is the name of the account. It is a reference to the account number used to derive the key pair from the mnemonic. You will use this name to identify your account when you want to sign a transaction. The helper script uses your Github username by default, but you can change it by specifying `--name` flag in the command.
The command will generate a 24-words mnemonic and save the private and public keys for account 0 at the same time. You can always recover the private key with the mnemonic.
Additionally,  the command will update the spreadsheet in Google Sheets by adding your public key to i

##### Create the multisig key

To create a multisig account you need to import a public of every participant of the process and after that generate a multisig account and save it to your local keybase.

That's a lot of commands, but with the helper script you can execute just one:

```shell
foo@bar:~$ ./multisig-helper.py generate-multisig-account

Adding key from test3...
Done
Adding key from test1...
Done

Generating multisig account
multisig account name: test1_test3_multisig
multisig address: terra_some_address
multisig pubkey: terrapub_some_public_key

Updating Google Sheets...
Done
```

The command will import public keys of another participants from the spreadsheet, generate a multisig account and update the spreadsheet with generated address of the multisig account


### Example

Let's see usage of the script on a little example where we want to send 5 Lunas from a multisig account (terra1e0fx0q9meawrcq7fmma9x60gk35lpr4xk3884m in our case) to terra17htaxslph9mvyunj4clgw9mcrglqjej4l6pcxg

##### 1) Create the multisig transaction

```shell
foo@bar:~$ terracli tx send \
    terra1e0fx0q9meawrcq7fmma9x60gk35lpr4xk3884m \
    terra17htaxslph9mvyunj4clgw9mcrglqjej4l6pcxg \
    5000000uluna \
    --gas=200000 \
    --fees=100000uluna \
    --chain-id=localterra \
    --generate-only > unsignedTx.json
```
The command will generate an unsigned transaction and save it to unsignedTx.json

##### 2) Share the unsigned tx with other participants

```shell
foo@bar:~$ ./multisig-helper.py new-tx "send_money_to_trofim" unsignedTx.json test1 --description "description of your tx, optional"
```
* "send_money_to_trofim" - just a little title of the transaction (without spaces!).
* unsignedTx.json - a path to an unsigned tx file from previous step
* test1 - a name of your private account (not a multisig!) generated previously.
* --description - optional flag to provide an additional info about the transaction

If you your output looks like that, everything is all right:
```shell
PR #1 for tx send_money_to_trofim created
See on Github: https://github.com/lidofinance/terra-multisig-testnet/pull/1
Updating Google Sheets...
Done
```

##### 3) See list of unsigned transactions

```shell
foo@bar:~$ ./multisig-helper.py list-unsigned
```

You'll see something like:
```shell
TX ID #1 - send_money_to_trofim
```
Where the most important part is TX ID. This id is required for the next steps.

##### 4) Sign a transaction

```shell
foo@bar:~$ ./multisig-helper.py sign TX_ID ACCOUNT_NAME
```

* TX_ID is a number from the previous step
* ACCOUNT_NAME is the name of the your terracli account created previously

In this case command looks like:
```shell
foo@bar:~$ ./multisig-helper.py sign 1 test1
Transaction send_money_to_trofim successfully signed by test1
See signature on github: https://github.com/lidofinance/terra-multisig-testnet/blob/send_money_to_trofim_2021-04-28/send_money_to_trofim_2021-04-28/test1_sign.json
Updating Google Sheets...
Done
```

After the command execution you can run `list-unsigned` again:
```shell
foo@bar:~$ ./multisig-helper.py list-unsigned

SigID #1 - send_money_to_trofim
	 Signed by: test1
```

And you'll see that tx is signed by test1.

##### 5) Issue tx

When a sufficient number of participants have signed a transaction, anyone can issue it:

```shell
foo@bar:~$ ./multisig-helper.py issue-tx TX_ID
```

The command will create a multisig transaction, merge a corresponding PR in the repository and update the spreadsheet.
But if you specify `--broadcast` flag, the command will broadcast the transaction right into blockchain.


In our case the command looks like:
```shell
foo@bar:~$ ./multisig-helper.py issue-tx TX_ID

PR #1 has merged successfully
Updating Google Sheets...
Broadcasting tx..
Updating Google Sheets...
Done
```
