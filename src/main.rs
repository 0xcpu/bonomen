#[macro_use]
extern crate clap;

use clap::{Arg, App};

mod types;

use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::io::BufRead;
use std::io::BufReader;
use std::collections::HashMap;

const BONOMEN_BANNER: &'static str = r"
      =======  ======= ==    == ======= ========== ====== ==    ==
      ||   //  ||   || ||\\  || ||   || ||\\  //|| ||     ||\\  ||
      ||====   ||   || || \\ || ||   || ||  ||  || ||==== || \\ ||
      ||   \\  ||   || ||  \\|| ||   || ||  ||  || ||     ||  \\||
      =======  ======= ==    == ======= ==  ==  == ====== ==    ==";

const DEFAULT_FILE: &'static str = "default_procs.txt";

fn main() {
    let matches = App::new(BONOMEN_BANNER)
        .version(crate_version!())
        .author(crate_authors!())
        .about("Detect critical process impersonation")
        .arg(Arg::with_name("proc")
             .short("p")
             .long("proc")
             .value_name("NAME")
             .help("Name of the process to check for impersonation")
             .takes_value(true)
             .required(true))
        .arg(Arg::with_name("file")
             .short("f")
             .long("file")
             .value_name("FILE")
             .help("File containing critical processes path, threshold, whitelist")
             .takes_value(true))
        .get_matches();

    println!("{}\n\tAuthor(s):{} Version:{}\n",
             BONOMEN_BANNER, crate_authors!(), crate_version!());
    
    let proc_name = matches.value_of("proc").unwrap();
    let file_name = matches.value_of("file").unwrap_or(DEFAULT_FILE);

    println!("Testing process with name: {}", proc_name);
    println!("Standard processes file: {}", file_name);

    let crit_proc_hm = read_procs_file(&file_name);
    for (pn, prop) in crit_proc_hm {
        println!("{} : {}", pn, prop.threshold);
        for wle in prop.whitelist.iter() {
            println!("{}", wle);
        }
    }
}

fn read_procs_file(file_name: &str) -> HashMap<std::string::String, types::ProcProps> {
    let path    = Path::new(file_name);
    let display = path.display();

    let file = match File::open(&path) {
        Err(why) => panic!("couldn't open {}: {}", display, why.description()),
        Ok(file) => file,
    };
    
    let mut hash_map = HashMap::new();

    let reader = BufReader::new(file);
    let lines  = reader.lines().map(|l| l.unwrap());

    for line in lines {
        let v: Vec<_> = line.split(';').map(|s| s.to_string()).collect();
        let mut wl    = Vec::new();

        for i in 2 .. v.len() {
            wl.push(v[i].to_string());
        }
        
        hash_map.insert(v[0].to_string(), types::ProcProps{ threshold: v[1].parse::<u32>().unwrap(),
                                                whitelist: wl
        });
    }

    hash_map
}
