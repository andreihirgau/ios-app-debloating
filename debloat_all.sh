#!/bin/bash

declare -a bloated_files=("./binaries/ios/big_useless_func" "./binaries/ios/called_func" "./binaries/ios/hello_world" "./binaries/ios/xor_count_ios")
for f in "${bloated_files[@]}"
do
	python debloat.py $f -a uncalled_functions
done
