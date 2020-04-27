#!/usr/bin/env python
import sys
import os
import pandas as pd
import click
import random
import requests
import hashlib
import warnings
# drops the use warning around the regex in repeats()
warnings.filterwarnings("ignore", 'This pattern has match groups')

class PasswordChecker:
    def __init__(self, **kwargs):
        self.new_pass = ""
        self.pword = ""
        if kwargs is not None:
            # User has passed pwd arg - validate the password
            if 'pword' in kwargs:
                self.pword = kwargs['pword']
                df_list = []
                df_list.append(self.pword[:])
                self.df = pd.DataFrame(df_list, columns=['password'])
            # User has passed check arg - validate passwords in csv file
            if 'fname' in kwargs:
                self.df = pd.read_csv(kwargs['fname'])
            # User wants a new nist compliant password. Oblige them!
            if 'new' in kwargs:
                self.gen_pw()

    def get(self):
        return self.new_pass

    def gen_pw(self):
        wordlist = []
        with open('datasets/english_10000.txt', 'r') as wstream:
            for word in wstream:
                wordlist.append(word)
        for i in range(3):
            self.new_pass = self.new_pass+random.choice(wordlist).rstrip('\n')
    
    # pass first 5 char of sha1 hash to pwnedpasswords return T/F
    def pwn_check(self, hashed):
        hash_list = []
        prefix = hashed[:5]
        req = 'https://api.pwnedpasswords.com/range/' + prefix
        res = requests.get(req)

        for line in res.text.splitlines():
            temp = line.split(':')
            hash_list.append(prefix+temp[0])

        return (hashed in hash_list)

    # Hashes the password and passes it to pwn_check
    # seprate functions in case I ever need to change from sha1
    def check_pass(self):
        myPass = self.pword[:]
        hashObj = hashlib.sha1(myPass.encode())

        return self.pwn_check(hashObj.hexdigest().upper())
        
    # Technically the NIST standard for length is 8 but some systems
    # still use lanman passwords which divide passwords less than 15 into
    # two 7 char hashes which are trivial to crack. Forcing 15 chars bypasses
    # any legacy lanman settings (like on many windows AD domains)
    def too_short(self):

        self.df['length'] = self.df['password'].apply(len)
        self.df['too_short'] = self.df['length'] < 15
        return

    # read in the top 10,000 from the 10 million password dump
    # flag any matches
    def common_password(self):
        common_passwords = pd.Series(pd.read_csv('datasets/top_10000.txt', \
            header=None,squeeze=True))

        self.df['common_password'] = self.df['password'].isin(common_passwords)
        return

    # read in top 10,000 common words from google corpus and flag
    def common_word(self):
        words = pd.Series(pd.read_csv('datasets/english_10000.txt', \
            header=None, squeeze=True))

        self.df['common_word'] = self.df['password'].isin(words.str.lower())
        return

    # passwords with >= 4 repeated chars
    def repeats(self):
        self.df['too_many_repeats'] = self.df['password'].str.contains(r'(.)\1{3}')
        return

    # Flagging all passwords that are bad
    def bad_pass(self):
        self.df['bad_password'] = ((self.df['too_short'] == True) |\
            (self.df['common_password'] == True) |\
            (self.df['common_word'] == True) |\
            (self.df['too_many_repeats'] == True))

    # run all checks except sha1
    def do_checks(self):
        try:
            self.too_short()
            self.common_password()
            self.common_word()
            self.repeats()
            self.bad_pass()
        except Exception as e:
            print(e)

# pw_checker args
@click.command()
@click.option('-c','--check', default='', is_flag=False, \
    help='Checks csv file containing passwords against NIST standards')
@click.option('-p', '--pwd', default='', is_flag=False, \
    help='checks pwd against known lists to see if it has been exposed')
@click.option('-g', '--gen', default='', is_flag=False, \
    help='generates a new NIST compliant password')

# pw_checker main
def pw_checker(check,pwd,gen):

    if check:
        try:
            if os.path.exists(check) and os.path.getsize(check) > 0:
                df_tocheck = PasswordChecker(fname=check)
        except OSError as e:
            print(e)
        df_tocheck.do_checks()
        print('Writing bad passwords to ./failed_pws.csv')
        df_tocheck.df.to_csv('failed_pws.csv')
    if pwd:
        pw_tocheck = PasswordChecker(pword=pwd)
        if pw_tocheck.check_pass() == True:
            print('This password has been exposed!')
        else:
            print('Not is known hash database. Running additional checks')
            pw_tocheck.do_checks()
            print('Writing failed tests (if any) to ./failed_csv')
            pw_tocheck.df.to_csv('failed_csv')
    if gen:
        newpw = PasswordChecker(new=True)
        print(f'Your NIST compliant password is:{newpw.get()}')

if __name__ == '__main__':
    pw_checker()


