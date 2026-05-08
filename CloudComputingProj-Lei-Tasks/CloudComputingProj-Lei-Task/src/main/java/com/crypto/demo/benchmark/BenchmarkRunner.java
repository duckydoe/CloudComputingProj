package com.crypto.demo.benchmark;

import com.crypto.demo.util.CryptoConfig;
import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.Collection;

/**
 * BENCHMARK RUNNER
 *
 * Drives the JMH benchmark suite and prints a formatted summary table
 * comparing RSA-4096 vs ML-KEM-768 performance.
 *
 * Run: Right-click BenchmarkRunner.java -> Run As -> Java Application
 *
 * NOTE: JMH benchmarks take time to run properly.
 *   - 3 warmup iterations + 5 measurement iterations per benchmark
 *   - Total runtime: approximately 5-10 minutes
 *   - This is normal — JMH needs enough samples for statistical accuracy
 */
public class BenchmarkRunner {

    public static void main(String[] args) throws Exception {
        CryptoConfig.init();

        System.out.println("╔══════════════════════════════════════════════════╗");
        System.out.println("║         JMH BENCHMARK SUITE                      ║");
        System.out.println("║  RSA-4096 vs ML-KEM-768 vs AES-256               ║");
        System.out.println("║  COSC370 - Lei Tapungot                          ║");
        System.out.println("╚══════════════════════════════════════════════════╝\n");

        System.out.println("Starting JMH benchmarks...");
        System.out.println("  Warmup    : 3 iterations x 1 second each");
        System.out.println("  Measure   : 5 iterations x 1 second each");
        System.out.println("  Fork      : 1 JVM per benchmark");
        System.out.println("  Est. time : 5-10 minutes\n");
        System.out.println("Raw JMH output follows:\n");
        System.out.println("─".repeat(60));

        // Build JMH options — run all benchmarks in CryptoBenchmark
        Options opts = new OptionsBuilder()
                .include(CryptoBenchmark.class.getSimpleName())
                .warmupIterations(3)
                .measurementIterations(5)
                .forks(1)
                .shouldDoGC(true)
                .build();

        Collection<RunResult> results = new Runner(opts).run();

        // Print formatted summary table
        System.out.println("\n" + "─".repeat(60));
        System.out.println("\n╔══════════════════════════════════════════════════════════════════╗");
        System.out.println("║                    BENCHMARK RESULTS SUMMARY                     ║");
        System.out.println("╠══════════════════════════╦═══════════╦═══════════╦═══════════════╣");
        System.out.println("║ Benchmark                ║ Score     ║ Error     ║ Units         ║");
        System.out.println("╠══════════════════════════╬═══════════╬═══════════╬═══════════════╣");

        for (RunResult result : results) {
            String name  = result.getPrimaryResult().getLabel();
            double score = result.getPrimaryResult().getScore();
            double error = result.getPrimaryResult().getScoreError();
            String unit  = result.getPrimaryResult().getScoreUnit();

            // Shorten the benchmark name for display
            String shortName = name
                    .replace("com.crypto.demo.benchmark.CryptoBenchmark.", "")
                    .replace("CryptoBenchmark.", "");

            System.out.printf("║ %-24s ║ %9.3f ║ ± %7.3f ║ %-13s ║%n",
                    shortName, score, error, unit);
        }

        System.out.println("╚══════════════════════════╩═══════════╩═══════════╩═══════════════╝");

        // Print interpretation
        System.out.println("\n── INTERPRETATION ─────────────────────────────────────────────────");
        System.out.println("KEY GENERATION:");
        System.out.println("  rsaKeyGen    — Slow because finding large primes is expensive");
        System.out.println("  mlkemKeyGen  — Fast because ML-KEM uses lattice sampling instead");
        System.out.println("  aesKeyGen    — Baseline: pure random bytes, no math required\n");

        System.out.println("ENCRYPT / ENCAPSULATE:");
        System.out.println("  rsaEncrypt      — Modular exponentiation with public key (faster side)");
        System.out.println("  mlkemEncapsulate— Lattice operations, consistently faster than RSA\n");

        System.out.println("DECRYPT / DECAPSULATE:");
        System.out.println("  rsaDecrypt      — Modular exponentiation with private key (slower side)");
        System.out.println("  mlkemDecapsulate— Lattice operations, faster and constant-time\n");

        System.out.println("CIPHERTEXT SIZE:");
        System.out.println("  rsaCiphertextSize  — 512 bytes (RSA-4096 modulus size)");
        System.out.println("  mlkemCiphertextSize— 1088 bytes (larger, but quantum-safe)\n");

        System.out.println("CONCLUSION:");
        System.out.println("  ML-KEM-768 is significantly faster than RSA-4096 for key exchange.");
        System.out.println("  The larger ciphertext (1088 vs 512 bytes) is an acceptable tradeoff");
        System.out.println("  for quantum resistance. Data is still encrypted with AES-256-GCM.");
    }
}