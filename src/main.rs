#[macro_use]
extern crate clap;

#[macro_use]
extern crate log;

#[cfg(target_os = "linux")]
extern crate psutil;

extern crate strsim;

extern crate libc;

extern crate term;

#[cfg(target_os = "windows")]
extern crate winapi;

#[cfg(target_os = "windows")]
extern crate kernel32;

use clap::{Arg, App};

#[cfg(target_os = "linux")]
use psutil::process::Process;

use strsim::damerau_levenshtein;

use std::error::Error;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::io::{BufRead, BufReader, Write, stdout};
use std::process::exit;
use std::mem::size_of;
use std::ptr;

use winapi::psapi::*;
use winapi::winnt::WCHAR;
use winapi::winnt::HANDLE;
use winapi::winnt::PROCESS_QUERY_INFORMATION;
use winapi::winnt::PROCESS_VM_READ;
use winapi::minwindef::HMODULE;
use winapi::minwindef::DWORD;
use winapi::minwindef::FALSE;
use winapi::minwindef::MAX_PATH;

use kernel32::OpenProcess;
use kernel32::K32EnumProcessModules;
use kernel32::K32GetModuleBaseNameW;
use kernel32::K32EnumProcesses;

mod types;

const BONOMEN_BANNER: &'static str = r"
      =======  ======= ==    == ======= ========== ====== ==    ==
      ||   //  ||   || ||\\  || ||   || ||\\  //|| ||     ||\\  ||
      ||====   ||   || || \\ || ||   || ||  ||  || ||==== || \\ ||
      ||   \\  ||   || ||  \\|| ||   || ||  ||  || ||     ||  \\||
      =======  ======= ==    == ======= ==  ==  == ====== ==    ==";

const DEFAULT_FILE: &'static str = "default_procs.txt";

fn main() {
    // Handle command line arguments
    let matches = App::new(BONOMEN_BANNER)
        .version(crate_version!())
        .author(crate_authors!())
        .about("Detect critical process impersonation")
        .arg(Arg::with_name("file")
             .short("f")
             .long("file")
             .value_name("FILE")
             .help("File containing critical processes path, threshold, whitelist")
             .takes_value(true))
        .arg(Arg::with_name("verbose")
             .short("v")
             .long("verbose")
             .help("Verbose mode"))
        .get_matches();

    let mut terminal = term::stdout().unwrap();

    match terminal.attr(term::Attr::Reverse) {
        Ok(ok)   => ok,
        Err(why) => println!("{}", why.description()),
    }
    println!("{}\n\tAuthor(s):{} Version:{}\n",
             BONOMEN_BANNER, crate_authors!(), crate_version!());
    terminal.reset().unwrap();
    
    #[cfg(unix)]
    unsafe {
       	if libc::geteuid() != 0 {
            terminal.attr(term::Attr::Bold).unwrap();
            terminal.fg(term::color::RED).unwrap();
            println!("{}", "BONOMEN needs root privileges to read process executable path!");
            terminal.reset().unwrap();
            let _ = stdout().flush();
            
            exit(0);
        }
    };

    let file_name = matches.value_of("file").unwrap_or(DEFAULT_FILE);
    let verb_mode = if matches.is_present("verbose") { true } else { false };

    // Load known standard system processes
    terminal.fg(term::color::GREEN).unwrap();
    println!("Standard processes file: {}", file_name);
    terminal.reset().unwrap();
    let crit_proc_vec = read_procs_file(&file_name);

    let mut r: u32 = 0;

    #[cfg(unix)] {
        // Read current active processes
        let sys_procs_vec = read_unix_system_procs();
        
        // Check for process name impersonation
        r = check_procs_impers(&crit_proc_vec, &sys_procs_vec, &verb_mode, &mut terminal);
    }

    #[cfg(windows)] {
        read_win_system_procs();
    }

    if r > 0 {
        terminal.fg(term::color::RED).unwrap();
    } else {
        terminal.fg(term::color::GREEN).unwrap();
    }
    println!("Found {} suspicious processes.\n{}", r, "Done!");
    terminal.reset().unwrap();
    let _ = stdout().flush();
}

// Read standard system processes from a file.
// Each line in the file is of the format:
// <process name>:<threshold value>:<process absolute path>
fn read_procs_file(file_name: &str) -> Vec<types::ProcProps> {
    let path    = Path::new(file_name);
    let display = path.display();

    let file = match File::open(&path) {
        Err(why) => panic!("couldn't open {}: {}", display, why.description()),
        Ok(file) => file,
    };
    
    let mut procs = Vec::new();

    // Read whole file line by line, and unwrap each line
    let reader = BufReader::new(file);
    let lines  = reader.lines().map(|l| l.unwrap());

    for line in lines {
        // Split each line into a vector
        let v: Vec<_> = line.split(';').map(|s| s.to_string()).collect();
        assert!(v.len() >= 3, "Invalid format, line: {}", line);
        let mut wl    = Vec::new();

        // Push process absolute path, may be more than 1 path
        for i in 2 .. v.len() {
            wl.push(v[i].to_string());
        }

        procs.push(types::ProcProps {
            name:      v[0].to_string(),
            threshold: v[1].parse::<u32>().unwrap(),
            whitelist: wl
        });
    }

    procs
}

// Read running processes
#[cfg(target_os = "linux")]
fn read_unix_system_procs() ->  Vec<Process> {
    psutil::process::all().unwrap()
}

#[cfg(target_os = "windows")]
fn read_win_system_procs() {
    const SIZE: usize = 1024;
    let mut pids = [0; SIZE];
    let mut written = 0;
    unsafe {
        let _ = K32EnumProcesses(pids.as_mut_ptr(), (pids.len() * size_of::<DWORD>()) as u32, &mut written);
    }
    let processes = &pids[..(written / size_of::<DWORD>() as u32) as usize]; // Slice trick thanks to WindowsBunny @ #rust

    const name_sz: usize = 64;
    let mut sz_process_name = [0; name_sz];
    
    for i in 0 .. processes.len() {
        let process_id: DWORD = processes[i];
        unsafe {
            let h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
	    
            
            if h_process.is_null() {
                let mut h_mod = ptr::null_mut();
                let mut cb_needed = ptr::null_mut();
	        
                K32EnumProcessModules(h_process, h_mod, size_of::<HMODULE>() as u32, cb_needed);
		
                K32GetModuleBaseNameW(h_process, *h_mod, sz_process_name.as_mut_ptr(), name_sz as u32);
            }
	}
        println!("pid: {}, name: {:?}", process_id, &sz_process_name[..]);
    }
}

fn is_whitelisted(proc_path: &str, whitelist: &Vec<std::string::String>) -> bool {
    whitelist.iter().any(|p| p == proc_path)
}

#[cfg(target_os = "linux")]
fn check_procs_impers(crit_procs_vec: &Vec<types::ProcProps>,
                      sys_procs_vec : &Vec<Process>,
                      verb_mode     : &bool,
                      terminal      : &mut Box<term::StdoutTerminal>) -> u32 {
    // Number of suspicious processes
    let mut susp_procs: u32 = 0;

    for sys_proc in sys_procs_vec.iter() {
        let exe_path = match sys_proc.exe() {
            Ok(path) => path,
            Err(why) => PathBuf::from(why.description()),
        };

        if *verb_mode {
            terminal.fg(term::color::BRIGHT_GREEN).unwrap();
            println!("> Checking system process: {}", sys_proc.comm);
            println!("> system process executable absolute path: {}", exe_path.to_str().unwrap());
        }

        for crit_proc in crit_procs_vec.iter() {
            let threshold = damerau_levenshtein(&sys_proc.comm, &crit_proc.name);
            if *verb_mode {
                terminal.fg(term::color::CYAN).unwrap();
                println!( "\tagainst critical process: {}, distance: {}", crit_proc.name, threshold);
                terminal.reset().unwrap();
            }

            if threshold > 0 && threshold <= crit_proc.threshold as usize &&
                !is_whitelisted(&(exe_path.to_str().unwrap()), &crit_proc.whitelist) {
                    terminal.fg(term::color::RED).unwrap();
                    println!("Suspicious: {} <-> {} : distance {}", sys_proc.comm, crit_proc.name, threshold);
                    terminal.reset().unwrap();

                    susp_procs += 1;
            }
        }
    }

    susp_procs
}
