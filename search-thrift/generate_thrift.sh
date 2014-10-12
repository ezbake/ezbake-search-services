#!/bin/bash
#   Copyright (C) 2013-2014 Computer Sciences Corporation
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


# echo commands before executing them

THRIFT_BINARY=${1:-thrift}

# TODO (soup): Add a way to include depedencies

function echo_and_execute_command()
{
    local cmd=$1
    echo ${cmd}
    ${cmd}
}



BUILD_DIR=`mktemp -d thrift_generator`
THRIFT_ARGS="-o ${BUILD_DIR}"
echo "GENERATING THRIFT FILES"

for f in src/main/thrift/*.thrift; do
    echo_and_execute_command "${THRIFT_BINARY} ${THRIFT_ARGS} --gen java $f"
done

for f in `find ./${BUILD_DIR}/gen-java -name "*.java"`
do
    file_name=`basename $f`
    tmp_var=`echo $f | cut -d "/" -f4-`
    dir_name=`dirname $tmp_var` 
    dest="src/main/java/${dir_name}"
    if [ ! -d $dest ]; then
        echo "Creating $dest"
        echo_and_execute_command "mkdir -p ${dest}"
    fi
    echo_and_execute_command "cp -fv $f ${dest}"
done

echo "Removing Build Directory"
echo_and_execute_command "rm -rf ${BUILD_DIR}"