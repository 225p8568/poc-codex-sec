package com.example;

import java.io.*;
import java.sql.*;
import javax.servlet.http.*;
import javax.xml.parsers.*;
import org.xml.sax.InputSource;

/**
 * Intentionally vulnerable Java Servlet — for CodeQL scanning.
 * DO NOT deploy in production.
 */
public class VulnerableApp extends HttpServlet {

    private static final String DB_URL  = "jdbc:mysql://localhost/app";
    // VULNERABILITY 1 – Hardcoded credentials
    private static final String DB_USER = "root";
    private static final String DB_PASS = "password123";

    // ---------------------------------------------------------------- //
    // VULNERABILITY 2 – SQL Injection                                   //
    // ---------------------------------------------------------------- //
    protected void doGet(HttpServletRequest req, HttpServletResponse res)
            throws IOException, ServletException {
        String username = req.getParameter("username");
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
            // SQL injection: user input concatenated into query
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(
                    "SELECT * FROM users WHERE name = '" + username + "'");
            PrintWriter out = res.getWriter();
            while (rs.next()) {
                out.println(rs.getString("name"));
            }
        } catch (SQLException e) {
            throw new ServletException(e);
        }
    }

    // ---------------------------------------------------------------- //
    // VULNERABILITY 3 – OS Command Injection                           //
    // ---------------------------------------------------------------- //
    public String ping(String host) throws IOException {
        // Command injection: user-controlled host passed to Runtime.exec with shell
        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c 1 " + host});
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line).append("\n");
        return sb.toString();
    }

    // ---------------------------------------------------------------- //
    // VULNERABILITY 4 – Path Traversal                                 //
    // ---------------------------------------------------------------- //
    public String readFile(String filename) throws IOException {
        // Path traversal: filename not sanitized
        File file = new File("/var/www/files/" + filename);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line).append("\n");
        reader.close();
        return sb.toString();
    }

    // ---------------------------------------------------------------- //
    // VULNERABILITY 5 – XXE (XML External Entity Injection)            //
    // ---------------------------------------------------------------- //
    public void parseXml(String xmlData) throws Exception {
        // XXE: external entity expansion not disabled
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new InputSource(new StringReader(xmlData)));
    }

    // ---------------------------------------------------------------- //
    // VULNERABILITY 6 – Insecure Deserialization                       //
    // ---------------------------------------------------------------- //
    public Object deserialize(byte[] data) throws Exception {
        // Insecure deserialization: arbitrary class instantiation
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    // ---------------------------------------------------------------- //
    // VULNERABILITY 7 – Weak Cryptography (MD5)                        //
    // ---------------------------------------------------------------- //
    public String hashPassword(String password) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
