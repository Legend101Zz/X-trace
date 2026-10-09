use std::io::Write; use std::time::Instant;
fn main(){ let d=std::env::var("TMPDIR").unwrap(); let dir=std::path::Path::new(&d).join("fsb"); std::fs::create_dir_all(&dir).unwrap();
 for round in 0..2 { let t=Instant::now(); for i in 0..50 { let p=dir.join(format!("f{round}-{i}")); let mut f=std::fs::File::create(&p).unwrap(); f.write_all(&[1u8;4096]).unwrap(); f.sync_all().unwrap(); std::fs::File::open(&dir).unwrap().sync_all().unwrap(); }
 println!("50x(file sync_all + dir sync_all): {:?}", t.elapsed()); }
 let t=Instant::now(); for i in 0..50 { let p=dir.join(format!("g{i}")); let mut f=std::fs::File::create(&p).unwrap(); f.write_all(&[1u8;4096]).unwrap(); f.sync_data().unwrap(); } println!("50x sync_data: {:?}", t.elapsed());
}
