use log::{LogRecord, LogLevel, LogMetadata};

struct BonomenLogger;

impl ::log::Log for BonomenLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= LogLevel::Info
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }
}

pub fn init() -> Result<(), ::log::SetLoggerError> {
    ::log::set_logger(|max_log_level| {
        max_log_level.set(::log::LogLevelFilter::Info);
        Box::new(BonomenLogger)
    })
}
