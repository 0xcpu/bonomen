pub struct ProcProps {
    pub name     : ::std::string::String,
    pub threshold: u32,
    pub whitelist: Vec<::std::string::String>,
}

#[cfg(windows)]
pub struct WinProc {
    pub name:     ::std::string::String,
    pub exe_path: ::std::string::String,
}
