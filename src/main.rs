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

fn get_file_from_hash(hash: &String, create_file: bool) -> Option<fs::File> {
        let folder_bytes = &hash[..2];
        let file_bytes = &hash[2..4];
        let dir = format!("hashes/{}",folder_bytes);
        let filename = format!("{}/{}.txt",dir,file_bytes);
        if create_file {
            match fs::create_dir_all(&dir) {
                Ok(d) => d,
                Err(e) => panic!("Could not create folder {}",dir)
            };
        }
        let file = match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(create_file)
            .open(filename) {
                Ok(file) => Some(file),
                Err(e) => {
                    println!("file error: {}", e);
                    None
                }
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
            Ok(line) => {
                match get_file_from_hash(&line, true) {
                    Some(mut file) => { 
                        println!("Opened File for hash:{}", line);
                        seek_bs(&file);
                        file.write(format!("{}\n",line).as_bytes());
                    },
                    None => panic!("Could not create/open file for hash:{}", line)
                }
            },
            Err(e) => panic!("{}", "Error reading line of file")
        };
        //println!("{} {} {}", hash_folder, hash_file, line);
    }
}

fn seek_bs(file: &fs::File) {
    
}

fn main() {

    let args: Vec<String> = env::args().collect();
    match args.len() {
        1 => println!("Usage: rpwned [PASSWORD]\n\
        Check password for pwnage.\n\n\
        \t-f [HASH_FILE]\tcreate hash file structure from pwned password file or update file"),
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
