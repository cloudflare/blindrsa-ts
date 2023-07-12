# Copyright (c) 2023 Cloudflare, Inc.
# Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0
#
# Run this file from the root of the project.
# $ make -f sjcl.Makefile

SJCL_OUTPUT_PATH=src/sjcl
SJCL_SRC_PATH=node_modules/sjcl

all:
	cd ${SJCL_SRC_PATH} && \
	./configure --without-all --with-bn --with-convenience --compress=none \
            --with-codecBytes --with-codecHex --with-codecArrayBuffer && \
	make
	npm i -D dts-gen
	npx dts-gen -m sjcl -o -f ${SJCL_OUTPUT_PATH}/index
	npm un -D dts-gen
	echo "export default sjcl;" >> ${SJCL_SRC_PATH}/sjcl.js
	cp ${SJCL_SRC_PATH}/sjcl.js ${SJCL_OUTPUT_PATH}/index.js

clean:
	rm -f ${SJCL_OUTPUT_PATH}/index.js ${SJCL_OUTPUT_PATH}/index.d.ts
