#!/bin/sh
# Copyright (c) 2024 Tobias Bengtsson
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

export VERSION=$(cat version.txt)

echo '[workspace]' > Cargo.toml
echo '# WARNING: This file is managed by the gen_crate.sh script' >> Cargo.toml
echo '' >> Cargo.toml
echo 'members = [' >> Cargo.toml
echo '    "crc-fast-gen",' >> Cargo.toml

while read c
do
    export PACKAGE_NAME=$(echo $c | cut -d , -f 1)
    if [ "$PACKAGE_NAME" = crate ]
    then
	continue
    fi
    export POLY=$(echo $c | cut -d , -f 2)
    export INIT=$(echo $c | cut -d , -f 3)
    export OUTPUT_XOR=$(echo $c | cut -d , -f 4)
    export LOREM=$(echo $c | cut -d , -f 5)
    export LOREM_ALIGNED=$(echo $c | cut -d , -f 6)
    export CHECK=$(echo $c | cut -d , -f 7)

    export PACKAGE_NAMESPACE=$(echo "$PACKAGE_NAME" | tr - _)

    echo 'Generating crate' "$PACKAGE_NAME"
    cp -rT ./crc-crate-template "./$PACKAGE_NAME"
    find "./$PACKAGE_NAME" -type f -exec sh -c 'envsubst < {} > {}.tmp; mv {}.tmp {}' \;
    echo '    "'"$PACKAGE_NAME"'",' >> Cargo.toml
done < algos.csv

echo ']' >> Cargo.toml
