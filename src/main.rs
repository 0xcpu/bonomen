extern crate clap;

use clap::{Arg, App};

fn main() {
    let matches = App::new("=== BONOMEN ===")
        .version("0.1")
        .author("ner0x652 cornel.punga@gmail.com")
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
}
