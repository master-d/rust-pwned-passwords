extern crate sha1;

use std::env;
use std::fs;
use std::io::Write;
use std::io::BufRead;
use std::io::BufReader;

fn check_pwd(password: &[u8]) {
    let mut m = sha1::Sha1::new();
    m.update(password);
    let hash = m.digest().to_string();
    println!("{} {} bytes",hash, hash.len());
}

fn get_file_from_hash(hash: &String) -> fs::File {
        let folder_bytes = &hash[..2];
        let file_bytes = &hash[2..4];
        let filename = format!("hashes/{}/{}.txt",folder_bytes,file_bytes);
        let file = match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(filename) {
                Ok(file) => file,
                Err(e) => panic!("{}", e)
            };
        return file;
}

fn update_hash_fs(file_path: &String) {
    let mut ufile = match fs::File::open(file_path) {
        Ok(file) => file,
        Err(e) => {
            panic!("{}", e);
        }
    };
    let mut br = BufReader::new(ufile);
    for line_r in br.lines() {
        let line = match line_r {
            Ok(line) => line,
            Err(e) => panic!("{}", "Error reading line of file")
        };
        let mut hash_file = get_file_from_hash(&line);
        hash_file.write(line.as_bytes());
        //println!("{} {} {}", hash_folder, hash_file, line);
    }
}

fn main() {

    let args: Vec<String> = env::args().collect();
    match args.len() {
        1 => println!("Please enter a password to check for pwnage"),
        2 => check_pwd(args[1].as_bytes()),
        _ => {
            // check 1st argument to see what operation user wants to perform
            match args[1].as_ref() {
                "-f" => update_hash_fs(&args[2]),
                _ => println!("Unknown command '{}'", args[1])
            }
        }
    }    
}
