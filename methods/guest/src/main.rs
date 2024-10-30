use risc0_zkvm::guest::env;

use sha2::{Digest, Sha256};

const EXPECTED_IMAGE: &[u8] = b"image: teeheehee/err_err_ttyl@sha256:50c3f8a00bbc47533504b026698e1e6409b4938109506c4e5a3baaae95116eb7";
const EXPECTED_LENGTH: usize = 1837;
const EXPECTED_IMAGE_IDX_START: usize = 40;
const EXPECTED_IMAGE_IDX_END: usize = EXPECTED_IMAGE_IDX_START + EXPECTED_IMAGE.len(); // 141
// 70ec07c39cd7cfb1672318bd586b37ee2f7133c4f3f41b948289db8d93fe2c4b
const EXPECTED_SHA256: &[u8] = b"p\xec\x07\xc3\x9c\xd7\xcf\xb1g#\x18\xbdXk7\xee/q3\xc4\xf3\xf4\x1b\x94\x82\x89\xdb\x8d\x93\xfe,K";

fn main() {
    let mut compose_file = [0u8; EXPECTED_LENGTH];
    env::read_slice(&mut compose_file);

    let actual_length = compose_file.len();
    if actual_length != EXPECTED_LENGTH {
        println!("bad input length. exp: {EXPECTED_LENGTH}, act: {actual_length}");
        env::commit(&1u8);
        return;
    }

    let image = &compose_file[EXPECTED_IMAGE_IDX_START..EXPECTED_IMAGE_IDX_END];
    if image != EXPECTED_IMAGE {
        // let imgstr = std::str::from_utf8(image).unwrap();
        println!("bad image content");
        env::commit(&2u8);
        return;
    }

    // calculate sha256
    let mut hasher = Sha256::new();
    hasher.update(&compose_file);
    let hash = hasher.finalize().to_vec();
    if &hash != EXPECTED_SHA256 {
        println!("incorrect hash");
        env::commit(&3u8);
        return;
    }

    env::commit(&0u8);
}
