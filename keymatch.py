#!/usr/bin/python
# -*- coding: utf-8 -*-

import fcntl
import glob
import json
import os
import shutil
import sys
import tarfile
import time
import zipfile
from collections import OrderedDict
from subprocess import Popen, PIPE, call

import rarfile

# Bro Locations
noticelog = '/usr/local/seceon/bro/logs/current/notice.log'
keywords = '/usr/local/seceon/bro/share/bro/site/file-extraction/kwlist.txt'
filelocation = '/usr/local/seceon/bro/logs/current/extract_files'

# Get all keywords to be found
f = open(keywords, 'r')
keys = set(f.read().split())

# Get filename, path, source ip and destination ip from arguments
filename = sys.argv[1]
filepath = sys.argv[2]

data = OrderedDict()

data['id.orig_h'] = sys.argv[3]
data['id.orig_p'] = sys.argv[4]
data['id.resp_h'] = sys.argv[5]
data['id.resp_p'] = sys.argv[6]
data['msg'] = 'Keyword matched in file having path %s' % filepath
data['note'] = 'KeywordMatch::Matched'

# fname = os.path.basename(filepath)
fext = os.path.splitext(filename)[1]

# Global variables
complex_extensions = ['.pdf', '.docx']
plaintext_extensions = ['.txt', '.doc', '.html', 'htm', 'rtf', 'xml', 'xls', 'json']
supported_extensions = complex_extensions + plaintext_extensions
FNULL = open(os.devnull, 'w')


def notice_printer(filename):
    counter = 100
    while counter:
        try:
            with open(noticelog, 'a') as the_file:
                fcntl.flock(the_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                json.dump(data, the_file, separators=(',', ':'))
                the_file.write('\n')
                fcntl.flock(the_file, fcntl.LOCK_UN)
                break
        except RuntimeError:
            counter -= 1
            time.sleep(0.5)


def extension_pdf(filename):
    for key in keys:
        call(['pdftotext', '%s' % filename])
        new_fn = os.path.splitext(filename)
        new_fn = new_fn[0] + '.txt'
        pdf_res = call(['grep', '-ic', '%s' % key, '%s' % new_fn], stdout=FNULL)
        if pdf_res == 0:
            notice_printer(filename)
            break
    os.remove(new_fn)


def extension_docx(filename):
    docxread = Popen(['docx2txt', '%s' % filename], stdout=PIPE).communicate()[0]
    for key in keys:
        if key in docxread:
            notice_printer(filename)
            break


def extension_txt(filename):
    for key in keys:
        txt_result = call(['grep', '-ic', '%s' % key, '%s' % filename], stdout=FNULL)
        if txt_result == 0:
            notice_printer(filename)
            break


def extension_tar(filename):
    tar = tarfile.open(filename)
    for member in tar.getmembers():
        if os.path.splitext(member.name)[1] in supported_extensions:
            tar.extract(member, path='tar')
    tar.close()
    ext_tar = glob.glob("tar/*")
    for files in ext_tar:
        fn_tar = os.path.basename(files)
        fext_tar = os.path.splitext(files)[1]
        os.chdir('tar')
        if fext_tar.lower() == '.pdf':
            extension_pdf(fn_tar)
        if fext_tar.lower() == '.docx':
            extension_docx(fn_tar)
        if fext_tar.lower() in plaintext_extensions:
            extension_txt(fn_tar)
        os.chdir('..')
    if os.path.isdir('tar'):
        shutil.rmtree('tar')


def extension_targz(filename):
    targz = tarfile.open(filename, 'r:gz')
    for member in targz.getmembers():
        if os.path.splitext(member.name)[1] in supported_extensions:
            targz.extract(member, path='gz')
    targz.close()
    ext_targz = glob.glob("gz/*")
    for files in ext_targz:
        fn_targz = os.path.basename(files)
        fext_targz = os.path.splitext(files)[1]
        os.chdir('gz')
        if fext_targz.lower() == '.pdf':
            extension_pdf(fn_targz)
        if fext_targz.lower() == '.docx':
            extension_docx(fn_targz)
        if fext_targz.lower() in plaintext_extensions:
            extension_txt(fn_targz)
        os.chdir('..')
    if os.path.isdir('gz'):
        shutil.rmtree('gz')


def extension_zip(filename):
    zip_file = zipfile.ZipFile(filename, 'r')
    for member in zip_file.namelist():
        if os.path.splitext(member)[1] in supported_extensions:
            zip_file.extract(member, path='zip')
    ext_zip = glob.glob("zip/*")
    for files in ext_zip:
        fn_zip = os.path.basename(files)
        fext_zip = os.path.splitext(files)[1]
        os.chdir('zip')
        if fext_zip.lower() == '.pdf':
            extension_pdf(fn_zip)
        if fext_zip.lower() == '.docx':
            extension_docx(fn_zip)
        if fext_zip.lower() in plaintext_extensions:
            extension_txt(fn_zip)
        os.chdir('..')
    if os.path.isdir('zip'):
        shutil.rmtree('zip')


def extension_rar(filename):
    rar_file = rarfile.RarFile(filename)
    for member in rar_file.namelist():
        if os.path.splitext(member)[1] in supported_extensions:
            rar_file.extract(member, path='rar')
    ext_rar = glob.glob("rar/*")
    for files in ext_rar:
        fn_rar = os.path.basename(files)
        fext_rar = os.path.splitext(files)[1]
        os.chdir('rar')
        if fext_rar.lower() == '.pdf':
            extension_pdf(fn_rar)
        if fext_rar.lower() == '.docx':
            extension_docx(fn_rar)
        if fext_rar.lower() in plaintext_extensions:
            extension_txt(fn_rar)
        os.chdir('..')
    if os.path.isdir('rar'):
        shutil.rmtree('rar')


def main():
    os.chdir(filelocation)
    if filename.endswith('.pdf'):
        extension_pdf(filename)
    elif filename.endswith('.docx'):
        extension_docx(filename)
    elif filename.endswith('.gz'):
        extension_targz(filename)
    elif filename.endswith('.tar'):
        extension_tar(filename)
    elif filename.endswith('.zip'):
        extension_zip(filename)
    elif filename.endswith('.rar'):
        extension_rar(filename)
    elif fext.lower() in plaintext_extensions:
        extension_txt(filename)
    os.remove(filename)


if __name__ == '__main__':
    main()
