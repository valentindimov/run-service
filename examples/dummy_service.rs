use std::io::prelude::*;
use std::thread::sleep;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open("log.txt")?;
    loop {
        file.write(b"Test file I/O!\n")?;
        println!("Test stdout!");
        eprintln!("Test stderr!");
        sleep(Duration::from_secs(1));
    }
}
