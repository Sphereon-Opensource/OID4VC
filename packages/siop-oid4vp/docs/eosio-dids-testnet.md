# EOSIO DID creation Walk-through

---

#WARNING

**DO NOT USE THIS WALK-THROUGH**

_Currently eosio uses DIDs with a different Verfication Method then all other DIDs (verifiable conditions). This library cannot access/use the public keys in that method yet, so the EOSIO DIDs cannot be used for authentication currently.
The document is still here, because Gimly hopes to make changes to the DID driver, so that we can support EOSIO DIDs as well_

---

Although this library simply expects DIDs to be present, we provide an example how to create DIDs on the EOSIO Junle testnet. There are 75+ DID methods and creation of DIDs typically happens from code and varies quite a bit. You can use your prefered DID method of choice.

## Relying Party and SIOP should have keys and DIDs

Since the library uses DIDs for both the Relying Party and the Self-Issued OpenID Provider, we expect these DIDs to be present on both sides, If you do not have DIDs this walk-through will result in EOSIO dids for the Relying Party and the OpenID Provider respectively. If you use another DID method the creation might vary, and hopefully is a bit more automated.

### Generate EOS keypairs

Go to: [Jungle3.0 - EOS Test Network Monitor - create keys](https://monitor3.jungletestnet.io/#createKey). You will see a popup/modal that give you a public EOS key and a private EOS key.

- Save these values for the RP, for example:
  - Public Key: EOS6kKhHvCuWkJDAoNb35qxHnyGCmFQpe1eBYBj9W18iKEQ82vsKZ
  - Private key: 5JoQQVRYuXfEMBMjY9T96bvsHGfwaXMygnwFNA1enLA5coWQKSi
- Repeat for the OP, for example:
  - Public Key: EOS8ZcT5JhRUuLwdQt6j4f2b8opJH1guPrQefTpo9Fqd4fLbKCpyw
  - Private key: 5Japr2nKKCzfZQHXupqm9hWmhMnifsuePRKgCHHwW4cQsLs4wvu

### Create EOS accounts

Go to : [Jungle3.0 - EOS Test Network Monitor - create account](https://monitor3.jungletestnet.io/#account). You will see a popup/modal in which you have to specify an account name and submit an owner and active public key. Lastly the reCaptcha needs to be checked after which the Create button can be used. Important: Only submit the public keys, never submit private keys! Use the public keys from the above respective steps.

- Create an account for the RP:
  - Account name example: sioprptest11 (needs to be unique and exactly 12 character and only allows a-z and 1-5!)
  - Owner Public Key: EOS6kKhHvCuWkJDAoNb35qxHnyGCmFQpe1eBYBj9W18iKEQ82vsKZ (RP key from above step)
  - Active Public Key: EOS6kKhHvCuWkJDAoNb35qxHnyGCmFQpe1eBYBj9W18iKEQ82vsKZ (RP key from above step)

You will see debug output and red text, which might look like an error at first, but actually this means it succeeded

- Create an account for the OP:
  - Account name example: siopoptest11 (needs to be unique and exactly 12 character and only allows a-z and 1-5!)
  - Owner Public Key: EOS8ZcT5JhRUuLwdQt6j4f2b8opJH1guPrQefTpo9Fqd4fLbKCpyw (RP key from above step)
  - Active Public Key: EOS8ZcT5JhRUuLwdQt6j4f2b8opJH1guPrQefTpo9Fqd4fLbKCpyw (RP key from above step)

You will see debug output and red text, which might look like an error at first, but actually this means it succeeded

### Add balances using a Faucet

Go to : [Jungle3.0 - EOS Test Network Monitor - faucet](https://monitor3.jungletestnet.io/#faucet)

- For the RP:
  - Fill in the “account name”, eg "sioprptest11", confirm you are not a robot and click “send coins“.
  - This should result in a balance of 100 EOS and 100 JUNGLE
- For the OP:
  - Fill in the “account name”, eg "siopoptest11", confirm you are not a robot and click “send coins“.
  - This should result in a balance of 100 EOS and 100 JUNGLE

### Increase CPU usage limit

To execute transactions we need the correct CPU limit.
Go to [Jungle3.0 - EOS Test Network Monitor - powerup](https://monitor3.jungletestnet.io/#powerup)

- For the RP:
  - Fill in the “account name”, eg "sioprptest11", confirm you are not a robot and click “send coins“ (Don't be alarmed by the button reading 'Send Coins'. That is a mistake in the site as it should read Powerup)
  - This should result in a transaction with a powerup
- For the OP:
  - Fill in the “account name”, eg "siopoptest11", confirm you are not a robot and click “send coins“ (Don't be alarmed by the button reading 'Send Coins'. That is a mistake in the site as it should read Powerup)
  - This should result in a transaction with a powerup

### Test resolution of the DIDs.

- Go to : https://dev.uniresolver.io
- In the did-url input box past the below dids and click on the Resolve button. You should get back results:
  - did:eosio:eos:testnet:jungle:<account_name>, eg:
    - did:eosio:eos:testnet:jungle:sioprptest11
    - did:eosio:eos:testnet:jungle:siopoptest11

### Install/use eosio-did typescript library if you want to create additional DIDs

We want to use the [Gimly-Blockchain/eosio-did](https://github.com/Gimly-Blockchain/eosio-did) typescript library to create eosio did’s. We expect the user to know its way around a development IDE and have npm installed on the computer.

- git checkout https://github.com/Gimly-Blockchain/eosio-did.git
- cd eosio-git
- npm install
- This project has a test to create those did’s, “create.test.ts“. This test requires that a jungleTestKeys.json is present in the root of the project. The content looks like:

```json
{
  "name": "[ACCOUNT_NAME]",
  "private": "[PRIV_KEY]",
  "public": "[PUB_KEY]"
}
```

For the RP:

- Create a rp.json in the root of the project:

```json
{
  "name": "sioprptest11",
  "private": "5JoQQVRYuXfEMBMjY9T96bvsHGfwaXMygnwFNA1enLA5coWQKSi",
  "public": "EOS6kKhHvCuWkJDAoNb35qxHnyGCmFQpe1eBYBj9W18iKEQ82vsKZ"
}
```

- Adjust line 6 of create-test.ts to read `const jungleTestKeys = require('../rp.json');`
- Execute the test
