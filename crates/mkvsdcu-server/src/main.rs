fn main() {
    if let Err(error) = mkvsdcu_server::run() {
        eprintln!("mkvdc-server: fatal: {error}");
        std::process::exit(1);
    }
}
