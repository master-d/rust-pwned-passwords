extern crate sha1;

use std::env;
use std::string::String;
use std::fs;
use std::io::Write;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Read;
use std::io::Error;

struct HashFile {
    file: fs::File,
    size: u64,
    hash: String
}
impl HashFile {
    pub fn new(hash: String, create_file: bool) -> Result<HashFile,Error> {
        let dir: String = {
            let folder_bytes = &hash[..2];
            format!("hashes/{}",folder_bytes)
        };
        let filename = {
            let file_bytes = &hash[2..4];
            format!("{}/{}.txt",dir,file_bytes)
        };
        if create_file {
            match fs::create_dir_all(&dir) {
                Ok(d) => d,
                Err(e) => panic!("Could not create folder {}",dir)
            };
        }
        println!("Opening file {}", filename);
        match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(create_file)
            .open(filename) {
                Ok(file) => {
                    let size = file.metadata().unwrap().len();
                    Ok(HashFile { file, size, hash })
                },
                Err(e) => {
                    Err(e)
                }
            }
    }
    pub fn seek(&mut self) {
        let mut pos = self.size as i64/2;
        if pos >= 40 {
            println!("Seeking to {} bytes", pos);
            self.file.seek(SeekFrom::Current(pos));
        }
    }
    pub fn read_hash(&mut self) -> String {
        let mut buf: [u8; 40] = [0; 40];
        self.file.read_exact(&mut buf);
        unsafe {
            String::from_utf8_unchecked(buf[..].to_vec())
        }
    }
    pub fn write_hash(&mut self, hash: &String) {
        self.seek();
        let line = format!("{}\n",hash);
        self.file.write(line.as_bytes());
    }

    pub fn check_pwd(&mut self) -> bool {
        println!("Checking for hash {} (filesize {} bytes)",self.hash, self.size);
        let seekto = self.size as i64/2;
        self.binary_search(seekto);
        let cmp_hash = self.read_hash();
        self.hash == cmp_hash
    }

    pub fn binary_search(&mut self, seekto: i64) {
        println!("Checking row {}", seekto/40);
        match seekto%40 {
            0 => {
                self.file.seek(SeekFrom::Current(seekto));
                let cmp_hash = self.read_hash();
                println!("Found hash: {}", cmp_hash);
                // found a match (exit binary search)
                if (cmp_hash == self.hash) {
                    return;
                } 

                if (cmp_hash > self.hash) {
                    self.binary_search(seekto/2);
                } else {
                    self.binary_search(-seekto/2);
                }
            },
            _ => return
        }
    }
    
} // end HashFile impl

pub fn get_hash_for_pwd(password: &String) -> String {
    let mut m = sha1::Sha1::new();
    m.update(password.as_bytes() );
    m.digest().to_string().to_uppercase()
}

pub fn update_hash_fs(file_path: &String) {
    let mut update_file = match fs::File::open(file_path) {
        Ok(file) => file,
        Err(e) => {
            panic!("{}", e);
        }
    };
    let mut update_br = BufReader::new(update_file);
    for line_br in update_br.lines() {
        let line = match line_br {
            Ok(line) => {
                println!("Opening File for hash:{}", line);
                let mut hf = HashFile::new(line, true).expect("Error loading file");
                //hf.file.write(format!("{}\n",line).as_bytes());
            },
            Err(e) => panic!("{} {}", "Error reading line of update file", file_path)
        };
        //println!("{} {} {}", hash_folder, hash_file, line);
    }
}



fn main() {

    let args: Vec<String> = env::args().collect();
    match args.len() {
        1 => println!("Usage: rpwned [PASSWORD]\n\
        Check password for pwnage.\n\n\
        \t-f [HASH_FILE]\tcreate hash file structure from pwned password file or update file\n\
        \t-h [PASSWORD]\tgenerate hash for supplied password and exit\n"),
        2 => {
            let hash = get_hash_for_pwd(&args[1]);
            println!("Checking {} for pwnage -- {}", args[1], hash);
            match HashFile::new(hash, false) {
                Ok(mut hf) => {
                    if hf.check_pwd() {
                        println!("HASH FOUND!");
                    } else {
                        println!("hash not found");
                    }
                },
                Err(e) => println!("{:?}",e)
            }
        },
        _ => {
            // check 1st argument to see what operation user wants to perform
            match args[1].as_ref() {
                "-f" => {
                    update_hash_fs(&args[2]);
                },
                "-h" => {
                    println!("Hash for '{}' is {}", args[2], get_hash_for_pwd(&args[2]));
                }
                _ => {
                    println!("Unknown command '{}'", args[1])
                }
            }
        }
    }    
}
