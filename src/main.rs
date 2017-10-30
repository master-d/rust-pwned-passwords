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

struct HashFile {
    file: fs::File,
    size: u64,
    hash: String
}
impl HashFile {
    pub fn new(hash: String, create_file: bool) -> Option<HashFile> {
        let dir: String = {
            let folder_bytes = &hash[..2];
            format!("hashes/{}",folder_bytes)
        };
        let filename = {
            let file_bytes = &hash[2..4];
            format!("{:?}/{}.txt",dir,file_bytes)
        };
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
                Ok(file) => {
                    let size = file.metadata().unwrap().len();
                    Some(HashFile { file, size, hash })
                },
                Err(e) => {
                    None
                }
            };
        return file;
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

    pub fn check_pwd(&mut self) {
        println!("Checking for hash {} ({} bytes)",self.hash, self.hash.len());
        //match HashFile::new(hash, false) {
        //    Some(mut hf) => {
                self.seek();
                let fhash = self.read_hash();
                println!("Read hash from file {:?}",fhash)
        //    },
        //    None => println!("Hash file does not exist for hash")
        //}
    }
} // end HashFile impl

pub fn get_hash_for_pwd(password: String) -> String {
    let mut m = sha1::Sha1::new();
    m.update(password.as_bytes() );
    m.digest().to_string()
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
        \t-f [HASH_FILE]\tcreate hash file structure from pwned password file or update file"),
        2 => {
            let hash = get_hash_for_pwd(args[1].to_string());
            println!("Checking {} for pwnage -- {}", args[1], hash);
            match HashFile::new(hash, false) {
                Some(mut hf) => {
                    hf.check_pwd();
                },
                None => println!("Hash file does not exist")
            }
        },
        _ => {
            // check 1st argument to see what operation user wants to perform
            match args[1].as_ref() {
                "-f" => {
                    update_hash_fs(&args[2])
                }
                _ => println!("Unknown command '{}'", args[1])
            }
        }
    }    
}
