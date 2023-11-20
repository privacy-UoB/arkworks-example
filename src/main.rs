use std::time::Instant;

use crate::test_circuit::ZKPTest;

mod test_circuit;

fn main() {
    println!("====== ZKP test initiated ======");
    let start = Instant::now();

    ZKPTest::run().unwrap();

    println!("====== ZKP test finished ======");
    println!("Total time elapsed: {:?} seconds", start.elapsed());
}
