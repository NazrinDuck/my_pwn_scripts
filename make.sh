#!/usr/bin/zsh
#author NazrinDuck
#date 2024/2/1
compileFile(){
  printf "\n"
  if test -d ./Outputs
  then
    DIR="./Outputs/"
  else
    mkdir ./Outputs
    DIR="./Outputs/"
  fi

  if test $1 = "cpp"
  exd=".out"
  then
    g++ ${2} -Wall -O3 -o ${DIR}${3}${exd}
  elif test $1 = "c"
  then
    gcc ${2} -Wall -O3 -o ${DIR}${3}${exd}
  else
    echo "${2} isn't a c/cpp file!"
    exit
  fi
}

compileDebuggingFile(){
  printf "\n"
  if test -d ./Outputs
  then
    DIR="./Outputs/"
  else
    mkdir ./Outputs
    DIR="./Outputs/"
  fi

  exd="Dbg.out"
  if test $1 = "cpp"
  then
    g++ ${2} -g -o ${DIR}${3}${exd}
  elif test $1 = "c"
  then
    gcc ${2} -g -o ${DIR}${3}${exd}
  else
    echo "${2} isn't a c/cpp file!"
    exit
  fi
}

compileAssemblyFile(){
  printf "\n"
  if test -d ./Assemblies
  then
    DIRA="./Assemblies/"
  else
    mkdir ./Assemblies
    DIRA="./Assemblies/"
  fi

  ex=".s"
  if test $1 = "cpp"
  then
    g++ -S ${2} -o ${DIRA}${3}${ex}
  elif test $1 = "c"
  then
    gcc -S ${2} -o ${DIRA}${3}${ex}
  else
    echo "${2} isn't a c/cpp file!"
    exit
  fi
}

if (( $# == 1 ))
then
  input=$1
  fullName=${input#*/}
  name=${fullName%%.*}
  extension=${fullName#*.}

  if read -q "?Compile a this file in detail?[y/n]:"
  then
    printf "\n"
    if read -q "?Want to preserve debugging information(add -g to gcc)?[y/n]:"
    then
      compileDebuggingFile $extension $fullName $name
      echo "\nSuccess to compile ${fullName} with debugging information!"
    else
      compileFile $extension $fullName $name
      echo "\nSuccess to compile ${fullName}!"
    fi

    if read -q "?Want to preserve assembly file(.s file)?[y/n]:"
    then
      compileAssemblyFile $extension $fullName $name
      echo "\nSuccess to compile assembly file ${fullName}.s!"
    else
      printf "\n"
    fi

    if read -q "?Want to run this file?[y/n]"
    then
      echo "\n====================Start===================="
      ${DIR}${name}
      echo "\n==================== End ===================="
    fi
    exit
  else
    exn=".out"
    compileFile $extension $fullName $name
    echo "Success to compile ${fullName}!"
    echo "Running ${name}${exn}..."
    echo "====================Start===================="
    ${DIR}${name}${exn}
    echo "\n==================== End ===================="
    exit
  fi
fi

for input in $@; do
  if test -e $input
  then
    fullName=${input#*/}
    name=${fullName%%.*}
    extension=${fullName#*.}

    compileFile $extension $fullName $name
  else
    echo "${input} not found!"
    exit
  fi
done
