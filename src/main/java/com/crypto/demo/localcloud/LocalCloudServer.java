package com.crypto.demo.localcloud;

import com.crypto.demo.crypto.EnvelopeCrypto;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;

public class LocalCloudServer {

    private static final String STORAGE = "cloud_storage.txt";

    public static void main(String[] args) throws Exception {

        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        server.createContext("/", exchange -> {
            String html =
                    "<h1>Local Cloud Server</h1>" +
                    "<p>Use /upload?data=hello</p>" +
                    "<p>Use /view</p>";

            send(exchange, html);
        });

        server.createContext("/upload", exchange -> {
            try {
                String query = exchange.getRequestURI().getQuery();

                if (query == null || !query.startsWith("data=")) {
                    send(exchange, "Usage: /upload?data=yourtext");
                    return;
                }

                String data = query.substring(5);

                String encrypted = EnvelopeCrypto.encrypt(data);

                Files.writeString(Path.of(STORAGE), encrypted);

                send(exchange,
                        "Uploaded to cloud.<br><br>Encrypted Data:<br>" + encrypted);

            } catch (Exception e) {
                e.printStackTrace();
                try {
                    send(exchange, "Error occurred: " + e.getMessage());
                } catch (IOException ioException) {
                    ioException.printStackTrace();
                }
            }
        });

        server.createContext("/view", exchange -> {
            if (!Files.exists(Path.of(STORAGE))) {
                send(exchange, "No stored cloud data.");
                return;
            }

            String content = Files.readString(Path.of(STORAGE));

            send(exchange,
                    "<h2>Stored Ciphertext</h2><p>" + content + "</p>");
        });

        server.start();

        System.out.println("Local Cloud Server Running:");
        System.out.println("http://localhost:8080");
    }

    private static String encrypt(String text) throws Exception {

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey key = kg.generateKey();

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE,
                key,
                new GCMParameterSpec(128, iv));

        byte[] encrypted =
                cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static void send(HttpExchange exchange, String response)
            throws IOException {

        exchange.sendResponseHeaders(200, response.length());

        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }
}