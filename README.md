# BOnum NOMEN - *good name*

# Hunt for Malware Critical Process Impersonation

## How it works

The purpose of this tool is to detect process name impersonation using *Damerau-Levenshtein* algorithm.
For example, a malware process could run under the name `chr0me` (note the 0 not o), thus observing that
it's a possibly malicious process becomes harder.

To detect a process that tries to become stealth by process name impersonation, `bonomen` reads all the
running processes on your system and compares their names with the processes(that you) provided in a file.

The processes you trust should be included in a file provided to `bonomen` at runtime with `-f` command line
option, otherwise `bonomen` searches for the default file `default_procs.txt`.
Every process should be written on a separate line, following the format:

```
process name;threshold;executable path
```
     
where:
     
`process name`    - is the name of the process you trust, for example `init`
     
`threshold`       - is the maximum distance between process names, for example between `chrome` and `chr0me` the distance is 1.
     
`executable path` - is the path to the executable of the process you trust, for example `/sbin/init`. This is used to
 		    check for processes that may be whitelisted.


## Requirements

   * Unix OS (developed and tested on Debian GNU/Linux 8 64-bit).

   * Windows OS (developed and tested on Windows 10 64-bit).
   
   * Rust programming language version >= 1.13.0
   
   * File containing system critical processes using the following format:
   
     ```
     process name;threshold;process executable absolute path
     ```
     
     Example:
     
     ```
     init;1;/sbin/init
     sshd;2;/usr/sbin/sshd
     ```
    
## References & Acknowledgements

   * [Damerau-Levenshtein distance](https://en.wikipedia.org/wiki/Damerau%E2%80%93Levenshtein_distance)

   * [Rust Docs](https://www.rust-lang.org/en-US/documentation.html)

   * Rust IRC #rust, especially to @retep998 and @DoumanAsh for helping with Windows support, @mbrubeck, @steveklabnik, @Quxxy, @Havvy. Thank you!

   * [Detect-Respong blog](https://detect-respond.blogspot.ro/2016/11/hunting-for-malware-critical-process.html) The implementation idea came from this article. Thank you!