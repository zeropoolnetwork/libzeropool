# libzeropool (WIP)

This is library with circuits and cryptography of ZeroPool.

## Benchmark

```bash
cargo test --release -- --nocapture test_circuit_tx_setup_and_prove
```

Benchmark result on Intel Core i9-9880H

```
Time elapsed in setup() is: 48.573000645s
Time elapsed in prove() is: 6.915143894s
Time elapsed in verify() is: 5.104347ms
```

