use clap::Parser;
use squashfs::SqsIoReader;
use squashfs::Superblock;

use anyhow::Result;
use std::fs::File;

use data_encoding::HEXLOWER;
use ring::digest::{Context, Digest, SHA256};
use std::io::{BufReader, Read, Seek, SeekFrom};

/// Calculate SHA-256 over meaningful bytes in squash4 image
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Name of squash4 image
    #[clap(short, long, value_parser)]
    image: String,
}

fn sha256_digest<R: Read>(mut reader: R, max: usize, blocksize: usize) -> Result<Digest> {
    let mut context = Context::new(&SHA256);
    let mut buffer = vec![0; blocksize];
    let mut read = 0;

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        read = read + count;
        if read > max {
            context.update(&buffer[..count - (read - max)]);
            break;
        }
        context.update(&buffer[..count]);
    }

    Ok(context.finish())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut file = File::open(args.image)?;

    let mut reader = Box::new(file.try_clone()?) as SqsIoReader;

    let mut sb = Superblock::new();
    sb.load(&mut reader)?;

    let _tb = sb.to_table();

    //println!("{}", tb);

    file.seek(SeekFrom::Start(0))?;
    let fsize = file.metadata()?.len();
    let reader = BufReader::new(file);
    let digest = sha256_digest(reader, sb.bytes_used as usize, sb.block_size as usize)?;

    // println!(
    //     "Size in blocks and the reminder: {}:{}",
    //     fsize / 512 as u64,
    //     fsize % 512 as u64
    // );

    println!("Data size for SHA-256: {}", sb.bytes_used);
    println!("Padding size: {}", fsize - sb.bytes_used);

    println!("SHA-256 digest is {}", HEXLOWER.encode(digest.as_ref()));

    Ok(())
}
