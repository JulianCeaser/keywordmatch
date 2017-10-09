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
noticelog = 'notice.log'  # '/usr/local/seceon/bro/logs/current/notice.log'
keywords = 'testing/kwlist.txt'  # '/usr/local/seceon/bro/share/bro/site/file-extraction/kwlist.txt'
filelocation = '/home/vikram/PycharmProjects/keywordmatch/testing'  # '/usr/local/seceon/bro/logs/current/extract_files'

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
complex_extensions = ['.docx']
simple_extensions = ['.pdf', '.txt', '.doc', '.html', 'htm', 'rtf', 'xml', 'xls', 'json']
compressed_extensions = ['.tar', '.gz', '.zip', 'rar']
supported_extensions = complex_extensions + simple_extensions
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


def extension_docx(filename):
    docxread = Popen(['docx2txt', '%s' % filename], stdout=PIPE).communicate()[0]
    for key in keys:
        if key in docxread:
            notice_printer(filename)
            break


def search_text(fname, ext):
    if ext == '.pdf':
        call(['pdftotext', '%s' % fname])
        new_fn = os.path.splitext(fname)
        fname = new_fn[0] + '.txt'
    var = ''
    for key in keys:
        var = '-e ' + key + ' ' + var
    cmd = ('grep -ic %s %s' % (var, fname)).split()
    txt_result = call(cmd, stdout=FNULL)
    if txt_result == 0:
        notice_printer(fname)
    if ext == 'pdf':
        os.remove(fname)


def decompress(fname, ext):
    if ext == '.tar':
        fp = tarfile.open(fname)
        for member in fp.getmembers():
            if os.path.splitext(member.name)[1] in supported_extensions:
                fp.extract(member, path='tmp')
        fp.close()
    elif ext == '.gz':
        fp = tarfile.open(fname, 'r:gz')
        for member in fp.getmembers():
            if os.path.splitext(member.name)[1] in supported_extensions:
                fp.extract(member, path='tmp')
        fp.close()
    elif ext == '.zip':
        fp = zipfile.ZipFile(fname, 'r')
        for member in fp.namelist():
            if os.path.splitext(member)[1] in supported_extensions:
                fp.extract(member, path='tmp')
        fp.close()
    elif ext == '.rar':
        fp = rarfile.RarFile(fname)
        for member in fp.namelist():
            if os.path.splitext(member)[1] in supported_extensions:
                fp.extract(member, path='tmp')
        fp.close()
    ext_files = glob.glob('tmp/*')
    for files in ext_files:
        fn_cmp = os.path.basename(files)
        fext_cmp = os.path.splitext(files)[1]
        os.chdir('tmp')
        if fext_cmp.lower() == '.docx':
            extension_docx(fn_cmp)
        elif fext_cmp.lower() in simple_extensions:
            search_text(fn_cmp, fext_cmp)
        os.chdir('..')
    if os.path.isdir('tmp'):
        shutil.rmtree('tmp')


def main():
    os.chdir(filelocation)
    if fext.lower() in simple_extensions:
        search_text(filename, fext)
    elif fext.lower() in complex_extensions:
        extension_docx(filename)
    elif fext.lower() in compressed_extensions:
        decompress(filename, fext)
    os.remove(filename)


if __name__ == '__main__':
    main()
