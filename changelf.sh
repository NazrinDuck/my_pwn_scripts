#!/usr/bin/sh
input=$1
glibc=$2
bits=$3
pwd2_23_64bits=/mnt/e/Linux/Pwn/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64
pwd2_23_32bits=/mnt/e/Linux/Pwn/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386

pwd2_27_64bits=/mnt/e/Linux/Pwn/glibc-all-in-one/libs/2.27-3ubuntu1_amd64
pwd2_27_32bits=/mnt/e/Linux/Pwn/glibc-all-in-one/libs/2.27-3ubuntu1_i386

if test -e ../${input};then
  if test $glibc = "2.23";then
    if test $bits = "64";then
      patchelf --set-interpreter ${pwd2_23_64bits}/ld-2.23.so ../${input}
      patchelf --replace-needed libc.so.6 ${pwd2_23_64bits}/libc-2.23.so ../${input}
      echo "${input} is attached to ${bits}bits ${glibc}version glibc."
    elif test $bits = "32";then
      patchelf --set-interpreter ${pwd2_23_32bits}/ld-2.23.so ../${input}
      patchelf --replace-needed libc.so.6 ${pwd2_23_32bits}/libc-2.23.so ../${input}
      echo "${input} is attached to ${bits}bits ${glibc}version glibc."
    else
      echo "Please give bits message" >&2
      exit 1
    fi
  elif test $glibc = "2.27";then
    if test $bits = "64";then
      patchelf --set-interpreter ${pwd2_27_64bits}/ld-2.27.so ../${input}
      patchelf --replace-needed libc.so.6 ${pwd2_27_64bits}/libc-2.27.so ../${input}
      echo "${input} is attached to ${bits}bits ${glibc}version glibc."
    elif test $bits = "32";then
      patchelf --set-interpreter ${pwd2_27_32bits}/ld-2.23.so ../${input}
      patchelf --replace-needed libc.so.6 ${pwd2_27_32bits}/libc-2.23.so ../${input}
      echo "${input} is attached to ${bits}bits ${glibc}version glibc."
    else
      echo "Please give bits message" >&2
      exit 1
    fi
  else
    echo "Please give glibc version"
    exit 1
  fi
   # patchelf --set-rpath /glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ ./c-output/a.out
else
  echo "${input} not found!"
  exit 0
fi
