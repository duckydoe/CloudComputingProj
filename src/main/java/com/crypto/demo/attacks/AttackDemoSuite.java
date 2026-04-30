package com.crypto.demo.attacks;
 
import com.crypto.demo.util.CryptoConfig;
 
/**
 * ATTACK DEMONSTRATION SUITE
 *
 * Runs all three attack demos in sequence.
 * Each demo can also be run independently via its own main() method.
 *
 * Attacks covered:
 *   1. Bleichenbacher (1998) — PKCS#1 v1.5 padding oracle
 *   2. Timing side-channel  — RSA decryption time leaks key bits
 *   3. ROCA (2017)          — Infineon TPM weak key fingerprint
 *
 * Run: Right-click AttackDemoSuite.java -> Run As -> Java Application
 */
public class AttackDemoSuite {
 
    public static void main(String[] args) throws Exception {
        CryptoConfig.init();
 
        System.out.println("╔══════════════════════════════════════════════════╗");
        System.out.println("║         ATTACK DEMONSTRATION SUITE               ║");
        System.out.println("║  COSC370 - Lei Tapungot                          ║");
        System.out.println("╚══════════════════════════════════════════════════╝");
        System.out.println();
 
        // ── Attack 1: Bleichenbacher ──────────────────────────────────
        System.out.println("════════════════════════════════════════════════════");
        System.out.println("  ATTACK 1 OF 3: BLEICHENBACHER (1998)");
        System.out.println("════════════════════════════════════════════════════");
        BleichenbacherDemo.main(args);
 
        System.out.println("\n\n");
 
        // ── Attack 2: Timing Side-Channel ─────────────────────────────
        System.out.println("════════════════════════════════════════════════════");
        System.out.println("  ATTACK 2 OF 3: TIMING SIDE-CHANNEL (Kocher 1996)");
        System.out.println("════════════════════════════════════════════════════");
        TimingAttackDemo.main(args);
 
        System.out.println("\n\n");
 
        // ── Attack 3: ROCA ────────────────────────────────────────────
        System.out.println("════════════════════════════════════════════════════");
        System.out.println("  ATTACK 3 OF 3: ROCA CVE-2017-15361");
        System.out.println("════════════════════════════════════════════════════");
        RocaDemo.main(args);
 
        System.out.println("\n\n");
 
        // ── Final Summary ─────────────────────────────────────────────
        System.out.println("╔══════════════════════════════════════════════════╗");
        System.out.println("║              ATTACK SUITE SUMMARY                ║");
        System.out.println("╠══════════════════════════════════════════════════╣");
        System.out.println("║ Attack           │ Root Cause      │ Our Defense ║");
        System.out.println("╠══════════════════════════════════════════════════╣");
        System.out.println("║ Bleichenbacher   │ PKCS#1 v1.5     │ RSA-OAEP   ║");
        System.out.println("║ Timing Attack    │ Variable-time   │ Blinding   ║");
        System.out.println("║ ROCA             │ Weak prime gen  │ SecureRandom║");
        System.out.println("╚══════════════════════════════════════════════════╝");
    }
}