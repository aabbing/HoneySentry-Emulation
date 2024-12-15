#!/bin/bash
cd binwalk-2.3.4 && \
  sed -i 's/^install_ubireader//g' deps.sh && \
  echo y | ./deps.sh && \
  sudo python3 setup.py install