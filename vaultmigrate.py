#!/usr/bin/env python
from __future__ import print_function

import sys
import os
import re
import argparse
import shutil
import tempfile
import json
import yaml
import getpass
import requests
import git
from github import Github

if sys.version_info[0] < 3:
    input_func = raw_input
else:
    input_func = input


auth_token = os.environ.get("SSOTOKEN")
"""auth_token (string): Set your Rackspace auth token as $SSOTOKEN
in your shell to be included.
. . _Get your Rackspace SSO token here:
    https://identity-internal.api.rackspacecloud.com/v2.0/tokens/
"""
    
git_token = os.environ.get("GITHUBTOKEN")
"""git_token (string): Set your Github Personal Access Token as 
$GITHUBTOKEN in your shell to be included. Your account must have
permissions to the 'rpc-environments' repo. Token requires 'repo' access.
. . _Get your own Github token here: 
    https://github.com/settings/tokens/new
. . _rpc-environments:
    https://github.com/rpc-environments
"""

inventory_url = "https://index-tst.rpc.rackspace.com/api/"
"""inventory_url (string): This is the url to the rpc inventory api. Your
auth token is used for this.
"""

def __make_args():
    """Makes argparse stuff.
    
    Returns: 
        ArgumentParser: the args option used for decision making
    """ 
    parser = argparse.ArgumentParser()
    auth_cmd = "--auth"
    auth_help_txt = ("Just print out a Rax auth token and quit. "
    "Useful for: export SSOTOKEN=$({} {})")
    parser.add_argument(
        auth_cmd,
        help=auth_help_txt.format(sys.argv[0], auth_cmd),
        action="store_true")
    return parser.parse_args()
    
def authenticate(username, pinrsa):
    """Gather username and password from user and authenticate with them.
    If either username or password are None, it will ask the user for input.
    Sensitive information is masked according to modern sensibilities.
    
    Args:
        username (string): Login username
        pinsra (string): pin+rsa token
    Returns:
        json: Authentication json object. To my knowledge, no formal schema
        exists for this object, but generally you want the 'id' key
    """
    
    if username == None:
        username = input_func("SSO username: ")
    if pinrsa == None:
        pinrsa = getpass.getpass("pin+rsa: ")

    auth_url = 'https://identity-internal.api.rackspacecloud.com/v2.0/tokens/'
    
    auth_data = {
        "auth": {
            "RAX-AUTH:domain": {
                "name": "Rackspace"
            },
            "RAX-AUTH:rsaCredentials": {
                "tokenKey": pinrsa,
                "username": username
            }
        }
    }
    
    auth_headers = {
        "cache-control": "no-cache",
        "content-type": "application/json"
    }
    r = requests.post(auth_url, data=json.dumps(auth_data), headers=auth_headers)
    if 400 <= r.status_code < 500:
        print("Login failed! :'(")
        sys.exit(r.status_code)
    elif 200 <= r.status_code < 300:
        return(r.json())
    else:
        output = " ".join("Auth system returned something weird.", 
        "Warning: the following output may have some sensitive data in it:")
        print(output)
        print(r.text)
        sys.exit(r.status_code)

def __find_key(needle, haystack):
    """Recurse thru a dictionary and return a child object that matches the key.
    
    Args:
        needle (string): The key value of the object you're looking for.
        haystack (dict): The dictionary to traverse.
    Returns:
        dict: the value of haystack[...][needle]
    """
    for k,v in haystack.items():
        if k == needle:
            return haystack[k]
        elif type(v) is dict:
            attempt = __find_key(needle, v)
            if attempt is not None:
                return attempt
        elif type(v) is list:
            for d in v:
                if type(d) is dict:
                    attempt = __find_key(needle, d)
                    if attempt is not None:
                        return attempt

def __guess_key(key, keys, default_value):
    """Attempts to retrieve a key from a set of keys. There's a somewhat insane
    amount of domain specific knowledge here. The keys often change subtley,
    and therefore need some tweaking to find the right keys. This is extremely
    error prone and should not be trusted. The idea is to use this to determine
    the value in a dict, such as foo = bar[__guess_key(...)].
    
    Args:
        key (string): A string to attempt to find. Generally speaking, this
        will be one of the following, and the function will attempt to
        find anything close to it:
            - "source"
            - "pws_project_id"
            - "pws_credential_id"
            - "type"
        keys (List<string>): A list of strings to be searched.
        default_value (string): If no match was found, return this string.
    Returns:
        string: Either the closest match or the value of default_value
    """
    default_value = key
    if "cred" in key:
        key = "credential"
    elif "proj" in key:
        key = "project"
    for k in keys:
        if key in k:
            return k
    return default_value
    
def checkout_repo(repo_name):
    """Does a shallow clone from repo from the rpc-environments org into a 
    temp directory. It's your responsibility to delete this directory.
    
    Args:
        repo_name (string): The name of the github repo.
    Returns:
        string: The filesystem path to the directory containing the repository.
    """
    repo_url_tpl= "https://{}:x-oauth-basic@github.com/rpc-environments/{}"
    repo_url = repo_url_tpl.format(git_token, repo_name)
    repo_dir = tempfile.mkdtemp()
    git.Repo.clone_from(repo_url, repo_dir, depth=1)
    return repo_dir
    
    
if __name__ == "__main__":
    args = __make_args()
    if auth_token == None:
        uname = os.environ.get("SSOUSERNAME")
        rsa = os.environ.get("SSOPINRSA")
        auth_body = authenticate(uname, rsa)
        # This is unfortunately brittle
        auth_token = auth_body["access"]["token"]["id"]
    if args.auth:
        print(auth_token)
        sys.exit(0)
        
    # There's no way to tell for sure if an environment you
    # find in git matches anything in the api because there's no uuids
    # and it's all a big string matching fiasco, and environment because 
    # names change all the time. So we get the whole inventory, and try
    # and search for accounts and environments. This is literally the worst.

    inventory_headers = {"x-auth-token": auth_token,
                        "content-type": "application/json",
                        "accept": "application/vnd.rackspace.rpc.index-v1+json",
                        "cache-control": "no-cache"}

    all_accounts = requests.get(
        inventory_url + "customers",
        headers=inventory_headers,
        verify="./rax_cabundle.crt").json()

    if git_token == None:
        git_token = getpass.getpass("Github Personal Token [full repo scope]:")
    
    github_api = Github(git_token)

    results = {
        "matched_envs": [],
        "unmatched_envs": [],
        "unmatched_notfound_envs": [],
        "unmatched_decom_envs": [],
        "noenv_repos": []
    }

    repo_count = 0
    env_count = 0

    for r in github_api.get_organization("rpc-environments").get_repos():
        repo_count += 1
        account_name = r.name
        repo = checkout_repo(r.name)
        env_files = []
        used_login_nodes = []
        # Find environment.yml files in order to
        # tell what directory represents a repo
        for root, dirs, files in os.walk(repo):
            for name in files:
                if name == "environment.yml":
                    env_files.append(os.path.join(root, name))

        if len(env_files) < 1:
            results['noenv_repos'].append(r.html_url)

        # Load files into an object and extract the vault info
        for env_file in env_files:
            sys.stdout.write('.') # it hurts to watch a still terminal for this long
            sys.stdout.flush()

            env_count += 1
            file_explode = env_file.split('/')
            environment_name = file_explode[-2]
            env_url = "{}/tree/master/{}/environment.yml".format(r.html_url, environment_name)

            env_yaml = yaml.load(open(env_file, 'r'))
            # The yaml doesn't have any deterministic keys so we
            # have to find the info we're looking for.
            vault_info = __find_key('ansible-vault', env_yaml)
            # Now we hope the account and environment info is still in sync
            # and that the name matches 'core_acct_number-description'.
            # There are probably all sorts of failure scenarios here,
            # but it's really impossible to tell.
            account_format = re.compile('^\d+-')
            mo = account_format.search(account_name)
            account_number = int(mo.group().split('-')[0])
            core_device = __find_key('core-device', env_yaml)

            account_uuid = None
            environment_uuid = None
            env_data = None
            for account in all_accounts:
                if account["core_account"] == account_number:
                    account_uuid = account["id"]
                    for env in account["environments"]:
                        # try to match on environment name
                        if env["label"] == environment_name:
                            environment_uuid = env["id"]
                            env_data = env
                            used_login_nodes.append(core_device)
                            results['matched_envs'].append((env_url, "label"))
                            break
                        elif core_device == env["login_node"] and core_device not in used_login_nodes:
                            used_login_nodes.append(core_device)
                            environment_uuid = env["id"]
                            env_data = env
                            results['matched_envs'].append((env_url, "CORE device"))
                            break
            
            if None in [account_uuid, environment_uuid, env_data]:
                if not account_uuid:
                    results['unmatched_notfound_envs'].append(env_url)
                elif __find_key('state', env_yaml) == 'decommissioned':
                    results['unmatched_decom_envs'].append(env_url)
                else:
                    results['unmatched_envs'].append(env_url)
                continue
            
            unsafe_keys = vault_info.keys()
            # This is a list of proper expected keys
            vault_keys = [
                "source", 
                "pws_project",
                "pws_cred", 
                "type"]
            fixed_vault_info = {}
            # This is loop control. If we can't find all the right info in
            # the github info, we dont store it. Let a human figure it out.
            bad_data_detected = False
            for vk in vault_keys:
                clean_key = __guess_key(vk, unsafe_keys, None)
                try:
                    fixed_vault_info[vk] = vault_info[clean_key]
                except KeyError as e:
                    msg = ("Warning: vault information bad for account: {} "
                    "environment: {}. Could not find information for {}")
                    print(msg.format(
                        account_number, 
                        environment_name, 
                        clean_key))
                    on_fire = True
            if bad_data_detected:
                bad_data_detected = False
                continue
            
            # ids arent sent on edits
            env_data.pop("id", None)
            
            
            uri = inventory_url + "customers/{}/environments/{}".format(
                account_uuid,
                environment_uuid
            )
            env_data["ansible_vault"] = fixed_vault_info
            # hold onto your butts
            index_r = requests.put(uri, data=json.dumps(env_data), headers=inventory_headers, verify="./rax_cabundle.crt")
            if 200 <= index_r.status_code < 300:
                continue
                # msg = "Updated account: {} environment: {} successfully."
                # print(msg.format(account_uuid, environment_uuid))
            else:
                msg = ("Unexpected error from inventory api when sending"
                "account: {} environment: {} : ")
                print(msg.format(account_number, environment_name) + index_r.text)
        shutil.rmtree(repo)

    print("\n\nMatched environments (by method) ({}/{}):".format(len(results['matched_envs']), env_count))
    for env, method in results['matched_envs']:
        print("{: >11} - {}".format(method, env))

    print("\nUnmatched environments - no matching account number in API ({}/{}):".format(len(results['unmatched_notfound_envs']), env_count))
    for env in results['unmatched_notfound_envs']:
        print(env)

    print("\nUnmatched environments marked decom ({}/{}):".format(len(results['unmatched_decom_envs']), env_count))
    for env in results['unmatched_decom_envs']:
        print(env)

    print("\nUnmatched environments (needs investigation) ({}/{}):".format(len(results['unmatched_envs']), env_count))
    for env in results['unmatched_envs']:
        print(env)

    print("\nRepos with no environment.yml (needs investigation) ({}/{}):".format(len(results['noenv_repos']), repo_count))
    for repo in results['noenv_repos']:
        print(repo)

    all_accounts = requests.get(
        inventory_url + "customers",
        headers=inventory_headers,
        verify="./rax_cabundle.crt").json()

    print("\nEnvironments from API with no ansible_vault entry:")
    for account in all_accounts:
        for env in account['environments']:
            if 'ansible_vault' not in env.keys():
                envlink = "{}customers/{}/environments/{}".format(inventory_url, account['id'], env['id'])
                print("{:<25} {:<15}: {}".format(account['name'], env['label'], envlink))
