use std::time::Instant;

use crate::test_circuit::ZKPTest;

mod test_circuit;

fn main() {
    println!("====== Parameter generation for Nano Sync initiated ======");
    let start = Instant::now();

    ZKPTest::setup().unwrap();

    println!("====== Parameter generation for Nano Sync finished ======");
    println!("Total time elapsed: {:?} seconds", start.elapsed());
}
