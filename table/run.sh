#!/bin/bash

#../gen_key_msg.py
#make -j4
for i in {1..10000}
do
	../gen_key_msg.py
	./aes_ecb $(cat key.txt) "$(cat msg.txt)"
done
