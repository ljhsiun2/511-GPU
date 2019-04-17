#!/bin/bash

./aes_ecb $(cat ../key.txt) "$(cat ../msg.txt)"