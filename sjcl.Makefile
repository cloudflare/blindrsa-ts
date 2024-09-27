# Copyright (c) 2023 Cloudflare, Inc.
# Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0
#
# Run this file from the root of the project.
# $ make -f sjcl.Makefile

SJCL_OUTPUT_PATH=$(CURDIR)/src/sjcl

.ONESHELL:

all: ${SJCL_OUTPUT_PATH}/index.js ${SJCL_OUTPUT_PATH}/index.d.ts

${SJCL_OUTPUT_PATH}/index.js:
	cd node_modules/sjcl
	./configure --without-all --with-bn --with-convenience --compress=none \
                --with-codecBytes --with-codecHex --with-codecArrayBuffer
	make
	cp sjcl.js $@
	echo "export default sjcl;" >> $@

${SJCL_OUTPUT_PATH}/index.d.ts:
	npm i -D @types/sjcl
	cp node_modules/@types/sjcl/index.d.ts $@
	npm un -D @types/sjcl

clean:
	rm -f ${SJCL_OUTPUT_PATH}/index.d.ts ${SJCL_OUTPUT_PATH}/index.js
