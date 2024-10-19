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
