use lief::Binary;
use std::fs::File;
use std::path::Path;

// Selecting Features to Classify Malware
// https://2012.infosecsouthwest.com/files/speaker_materials/ISSW2012_Selecting_Features_to_Classify_Malware.pdf
fn main() {
    let path = Path::new("./putty.exe");
    let mut file = File::open(path).unwrap();

    match Binary::from(&mut file) {
        Some(Binary::ELF(elf)) => {
            println!("elf\n{:?}", elf);
        },
        Some(Binary::PE(pe)) => {
            println!("DebugSize: {:?}", pe.data_directories().nth(6).unwrap().size());
            println!("ImageVersion: {:?}", pe.optional_header().major_image_version());
            println!("latRVA: {:?}", pe.data_directories().nth(12).unwrap().rva());
            println!("ExportSize: {:?}", pe.data_directories().next().unwrap().size());
            println!("ResourceSize: {:?}", pe.data_directories().nth(2).unwrap().size());
            println!("VirtualSize2: {:?}", pe.sections().nth(1).unwrap().virtual_size());
            println!("NumberOfSections: {:?}", pe.header().nb_sections());
        },
        Some(Binary::MachO(macho)) => {
            println!("mac\n{:?}", macho);
        },
        None => {
            println!("Unknown format");
        }
    }
}