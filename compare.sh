openssl asn1parse -in yacme-key/test-examples/csr/example.csr | awk '{$1=$2=$3=$4=""; print $0}' | diff - <(openssl asn1parse -in yacme-key/test-examples/csr/example-openssl.csr | awk '{$1=$2=$3=$4=""; print $0}')
