<h1 align="center">BufferSploit</h1>

<h5 align="center">
  <br>
  <a href="https://github.com/adithyan-ak/BufferSploit"><img src="https://i.imgur.com/HObHVjb.png" alt="BufferSploit"></a>
  <br>
  BufferSploit
  <br>
</h5>


### About

Stack based buffer overflows attacks made simple. BufferSploit is a semi automated CLI based tool for performing stack based buffer overflow attacks with ease.

### Requirements

- Python3

### Setup

Clone this repository in your terminal.

- ```https://github.com/adithyan-ak/BufferSploit.git```

- ```cd BufferSploit```

- ```pip3 install -r requirements.txt```

- Update the `IP` `PORT` and `CMD` variable in `buffersploit.py`

- ```python3 buffersploit.py```

### Usage

<pre>

usage: buffersploit.py [-h] [-c] [-l L] [-q Q] [-b] [-br BR] [-s] [--L L] [--P P]

optional arguments:

  -h, --help  show this help message and exit
  -c          Crash bytes size
  -l L        Length for sending a random pattern
  -q Q        Query to find the offset address
  -b          Send Badchars to the target
  -br BR      Specify the found badcharacter
  -s          Generate Shellcode
  --L L       Local address for reverse shell
  --P P       Local Port for reverse shell

  </pre>