#!/bin/bash -e

pushd linux
  # Use the default configuration
  if [ ! -f ".config" ];
  then 
    cp config.saved .config
  fi

  # Build using all CPU threads
  make -j`nproc`
popd 