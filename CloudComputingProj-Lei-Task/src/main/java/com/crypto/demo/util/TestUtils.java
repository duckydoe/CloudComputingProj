package com.crypto.demo.util;

import java.util.HexFormat;

public final class TestUtils {

    private static final HexFormat HEX = HexFormat.of();

    public static String toHex(byte[] bytes) {
        return HEX.formatHex(bytes).toUpperCase();
    }

    public static void section(String title) {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("  " + title);
        System.out.println("=".repeat(60));
    }

    public static void row(String label, Object value) {
        System.out.printf("  %-28s %s%n", label + ":", value);
    }

    public static long time(Runnable task) {
        long start = System.nanoTime();
        task.run();
        return (System.nanoTime() - start) / 1_000_000;
    }

    public static void timeAndPrint(String label, Runnable task) {
        long ms = time(task);
        row(label + " (ms)", ms);
    }

    private TestUtils() {}
}