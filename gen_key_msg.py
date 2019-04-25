#!/usr/bin/env python

import random

def gen_msg():
	with open('msg.txt', 'w') as msg_file:
		string = ''
		for i in range(512):
			string += chr(random.randint(0, 255))

		msg_file.write(string.encode('hex'))

def gen_key():
	with open('key.txt', 'w') as key_file:
		string = ''
		for i in range(16):
			string += chr(random.randint(0, 255))

		key_file.write(string.encode('hex'))

gen_msg()
# gen_key()