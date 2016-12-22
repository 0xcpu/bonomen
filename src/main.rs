#[macro_use]
extern crate clap;

use clap::{Arg, App};

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
}
