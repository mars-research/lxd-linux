#!/bin/bash

WLLVM_EXT=/users/vikram/.local/bin/extract-bc
BC_FILES_REPO=/local/device/bc-files


get_definitions() {
	for m in $(find . -name "*.ko"); do
		echo ">>>>>>>>>>>>>> $m";
		for s in $(nm $m | grep -i ' u '| awk '{print $NF}'); do
			cscope -d -f./cscope.out -R -L1 $s | tee -a $m.log;

		done;
	done
}

extract_bc() {
	LOGS=$(find . -name "*.ko.log")
	for log in $LOGS; do
		DRIVER_OBJ=$(echo $log | sed 's/\.log//g')
		DRIVER_BC=${DRIVER_OBJ}".bc"
		DRIVER_NAME=$(echo $log | sed 's/\.ko\.log//g' | awk -F'/' '{print $NF}')
		KERNEL_BC=$(echo $log | sed 's/\.ko\.log/_kernel.bc/g')

		FILES=$(awk '{print $1}' $log | sort | uniq)
		BC_FILES=""
		for f in $FILES; do
			OBJ_FILE=$(echo $f | sed 's/\.c/.o/g' | sed 's/\.S/.o/g');
			${WLLVM_EXT} ${OBJ_FILE};
			BC_FILES+="${OBJ_FILE}.bc "
		done
		echo "$log => $BC_FILES"
		echo ${BC_FILES_REPO}/$DRIVER_NAME
		echo ${DRIVER_OBJ} ${DRIVER_BC} 
		llvm-link -o ${KERNEL_BC} ${BC_FILES}
		echo "driver obj: $DRIVER_OBJ"
		echo "driver bc: $DRIVER_BC"
		${WLLVM_EXT} ${DRIVER_OBJ} -o ${DRIVER_BC}
		if [ ! -d "${BC_FILES_REPO}/${DRIVER_NAME}" ]; then
			mkdir -p ${BC_FILES_REPO}/${DRIVER_NAME};
		fi
		cp -v ${DRIVER_BC} ${KERNEL_BC} ${BC_FILES_REPO}/${DRIVER_NAME}
	done
}


if [ $1 == "defs" ]; then
	get_definitions;
elif [ $1 == "bc" ]; then
	extract_bc;
	fi
