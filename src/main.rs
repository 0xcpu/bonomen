#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;

extern crate psutil;

extern crate strsim;

use clap::{Arg, App};

use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::io::{BufRead, BufReader};

use psutil::process::Process;

use strsim::damerau_levenshtein;

mod types;
mod logger;

const BONOMEN_BANNER: &'static str = r"
      =======  ======= ==    == ======= ========== ====== ==    ==
      ||   //  ||   || ||\\  || ||   || ||\\  //|| ||     ||\\  ||
      ||====   ||   || || \\ || ||   || ||  ||  || ||==== || \\ ||
      ||   \\  ||   || ||  \\|| ||   || ||  ||  || ||     ||  \\||
      =======  ======= ==    == ======= ==  ==  == ====== ==    ==";

const DEFAULT_FILE: &'static str = "default_procs.txt";

fn main() {
    // Init logger
    logger::init().expect("failed to init logger");
    info!("starting up!");

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
        .get_matches();

    println!("{}\n\tAuthor(s):{} Version:{}\n",
             BONOMEN_BANNER, crate_authors!(), crate_version!());
    
    let file_name = matches.value_of("file").unwrap_or(DEFAULT_FILE);

    // Load known standard system processes
    println!("Standard processes file: {}", file_name);
    let crit_proc_vec = read_procs_file(&file_name);

    // If user didn't input a process name, then check all running processes    
    let sys_procs_vec = read_system_procs();

    check_procs_impers(&crit_proc_vec, &sys_procs_vec);
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
fn read_system_procs() ->  Vec<Process> {
    psutil::process::all().unwrap()
}

fn is_whitelisted(proc_path: &std::string::String, whitelist: &Vec<std::string::String>) -> bool {
    whitelist.iter().any(|p| p == proc_path)
}

fn check_procs_impers(crit_procs_vec: &Vec<types::ProcProps>,
                      sys_procs_vec:  &Vec<Process>) {
    for sys_proc in sys_procs_vec.iter() {
        for crit_proc in crit_procs_vec.iter() {
            let threshold = damerau_levenshtein(&sys_proc.comm, &crit_proc.name);

            if threshold > 0 && threshold <= crit_proc.threshold as usize &&
                !is_whitelisted(&sys_proc.comm, &crit_proc.whitelist) {
                println!("Suspicious: {} <-> {} : distance {}", sys_proc.comm, crit_proc.name, threshold);
            }
        }
    }
}
