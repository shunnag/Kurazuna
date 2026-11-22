#!/usr/bin/env python3
"""Sign one notarized Kurazuna ZIP and write its Sparkle update feed."""

import argparse
import datetime
import email.utils
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
from urllib.parse import quote
import xml.etree.ElementTree as ET
from zipfile import ZipFile


BUNDLE_ID = 'dev.soba.iscsi.kurazuna'
NAMESPACE = 'http://www.andymatuschak.org/xml-namespaces/sparkle'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--display-version', required=True)
    parser.add_argument('--tools', type=Path, required=True, help='Official Sparkle bin directory')
    parser.add_argument('--output', type=Path, default=Path('appcast.xml'))
    args = parser.parse_args()
    with ZipFile(args.archive) as archive:
        contents = 'Kurazuna.app/Contents/'
        app = plistlib.loads(archive.read(contents + 'Info.plist'))
        ext = plistlib.loads(archive.read(contents + 'Extensions/ISCSIFSExtension.appex/Contents/Info.plist'))
    build = app['CFBundleVersion']
    if not build.isdecimal() or build != ext['CFBundleVersion']:
        parser.error('The app and extension must have matching numeric build numbers.')
    if app['CFBundleIdentifier'] != BUNDLE_ID or ext['CFBundleIdentifier'] != BUNDLE_ID + '.FileSystem':
        parser.error('Unexpected app or extension identifier.')
    key = subprocess.check_output([args.tools / 'generate_keys', '--account', BUNDLE_ID, '-p'], text=True).strip()
    if key != app['SUPublicEDKey']:
        parser.error('The app does not trust this signing key.')
    signer = [args.tools / 'sign_update', '--account', BUNDLE_ID]
    signature = subprocess.check_output([*signer, '-p', args.archive], text=True).strip()
    subprocess.run([*signer, '--verify', args.archive, signature], check=True)
    ET.register_namespace('sparkle', NAMESPACE)
    sparkle = '{' + NAMESPACE + '}'
    rss = ET.Element('rss', version='2.0')
    channel = ET.SubElement(rss, 'channel')
    ET.SubElement(channel, 'title').text = 'Kurazuna'
    ET.SubElement(channel, 'link').text = 'https://github.com/shunnag/Kurazuna/releases'
    ET.SubElement(channel, 'description').text = 'Kurazuna software updates'
    item = ET.SubElement(channel, 'item')
    ET.SubElement(item, 'title').text = 'Kurazuna ' + args.display_version
    ET.SubElement(item, 'pubDate').text = email.utils.format_datetime(datetime.datetime.now(datetime.timezone.utc))
    ET.SubElement(item, sparkle + 'version').text = build
    ET.SubElement(item, sparkle + 'shortVersionString').text = args.display_version
    ET.SubElement(item, sparkle + 'minimumSystemVersion').text = app['LSMinimumSystemVersion']
    url = 'https://github.com/shunnag/Kurazuna/releases/download/' + quote(args.tag, safe='') + '/' + quote(args.archive.name)
    ET.SubElement(item, 'enclosure', {'url': url, 'length': str(args.archive.stat().st_size),
                                     'type': 'application/octet-stream', sparkle + 'edSignature': signature})
    ET.indent(rss, space='  ')
    with tempfile.TemporaryDirectory(dir=args.output.parent) as scratch:
        feed = Path(scratch) / 'appcast.xml'
        ET.ElementTree(rss).write(feed, encoding='utf-8', xml_declaration=True)
        subprocess.run([*signer, feed], check=True)
        subprocess.run([*signer, '--verify', feed], check=True)
        os.replace(feed, args.output)


if __name__ == '__main__':
    main()
