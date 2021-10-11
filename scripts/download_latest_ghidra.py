#!/usr/bin/env python3
import json
import os
import shutil
import sys
import urllib.request

def remove_prefix(s, prefix):
    return s[len(prefix):] if s.startswith(prefix) else s

def installed_ghidra_version(install_dir=None):
    if install_dir is None:
        install_dir = os.getenv('GHIDRA_INSTALL_DIR')
        if install_dir is None:
            return None
    props = {}
    with open(install_dir + '/Ghidra/application.properties', 'r') as prop_fp:
        for line in prop_fp:
            pair = line.strip().split('=')
            props[remove_prefix(pair[0], 'application.')] = pair[1]
    return [props.get(key, '') for key in ['version', 'release.name', 'build.date.short']]

def copy_with_progress(src, dest, size):
    size_mb = '%.1f' % (size/1024/1024)
    block_size = 8192
    dl_since_print = 0
    dl_size = 0
    print('Downloading: 0.0 / %s MiB...' % size_mb)

    while True:
        buf = src.read(block_size)
        if not buf:
            break

        dest.write(buf)
        dl_size += len(buf)
        dl_since_print += len(buf)
        if dl_since_print > size / 100:
            dl_since_print = 0
            print('\033[1ADownloading: %.1f / %s MiB...' % (dl_size/1024/1024, size_mb))

    print('\033[1ADownloading: %.1f / %s MiB...' % (dl_size/1024/1024, size_mb))

current_version = installed_ghidra_version()

releases_url = 'https://api.github.com/repos/NationalSecurityAgency/ghidra/releases'
with urllib.request.urlopen(releases_url) as jso_fp:
    jso = json.load(jso_fp)

latest_name = jso[0]['name']
if current_version is None:
    current_name = 'None'
else:
    current_name = 'Ghidra ' + current_version[0]
if current_name == latest_name:
    print('Already up to date:', current_name)
    sys.exit(0)
print('Installed:', current_name)
print('Latest:   ', latest_name)

latest_asset = jso[0]['assets'][0]
print('Downloading Ghidra release:', latest_asset['name'])
download_url = latest_asset['browser_download_url']
print(download_url)
dest_path = os.path.expanduser('~/Downloads/' + latest_asset['name'])
with urllib.request.urlopen(download_url) as remote, open(dest_path, 'wb') as dest_file:
    #shutil.copyfileobj(remote, dest_file)
    copy_with_progress(remote, dest_file, latest_asset['size'])
print('Saved to:', dest_path)
