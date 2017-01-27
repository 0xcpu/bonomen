# BOnus NOMEN - *good name*

# Hunt for Malware Critical Process Impersonation


## Requirements

   * Unix OS (developed and tested on Debian GNU/Linux 8 64-bit).
   
   * Rust programming language(developed with Rust 1.13.0), if you want to compile yourself the code.
   
   * File containing system critical processes using the following format:
   
     ```
     process name;threshold;process executable absolute path
     ```
     
     Example:
     
     ```
     init;1;/sbin/init
     sshd;2;/usr/sbin/sshd
     ```
    