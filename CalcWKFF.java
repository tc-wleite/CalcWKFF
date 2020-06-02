package gpinf.wkff;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;

import sun.security.provider.MD4;

/**
 * Calculate hashes in WKFF (Well Known File Filter) format.
 * @author Wladimir Leite (GPINF/SP)
 */
public class CalcWKFF {
    private static MessageDigest digestMD5_512, digestMD5_64K, digestMD5total, digestMD4, digestEdonkey, digestSHA1, digestSHA256, digestMD5_1M;
    private static final int edonkeyBlock = 9500 << 10;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("CalcWKFF: Calculate hashes in WKFF (Well Known File Filter) format.");
            System.err.println("Usage: java -jar calcwkff.jar input-folder > output-file-name.txt");
            return;
        }
        digestMD5_512 = MessageDigest.getInstance("MD5");
        digestMD5_64K = MessageDigest.getInstance("MD5");
        digestMD5_1M = MessageDigest.getInstance("MD5");
        digestMD5total = MessageDigest.getInstance("MD5");
        digestMD4 = MD4.getInstance();
        digestEdonkey = MD4.getInstance();
        digestSHA1 = MessageDigest.getInstance("SHA1");
        digestSHA256 = MessageDigest.getInstance("SHA-256");
        System.out.println("#MD5 Complete File               *MD5 First 64K bytes              *Edonkey Hash                     *SHA1                                     *MD5 First 512 bytes              *File Length  *File Name             *MD5 First 1MB                    *SHA256");
        process(new File(args[0]));
    }

    private static void process(File folder) throws Exception {
        File[] files = folder.listFiles();
        if (files == null) return;
        for (File file : files) {
            if (file.isDirectory()) {
                process(file);
            } else {
                String name = clean(file.getName());
                try {
                    String[] hash = getHashes(file);
                    String length = String.format("%012d", file.length());
                    System.out.println(hash[0] + " *" + hash[1] + " *" + hash[2] + " *" + hash[3] + " *" + hash[4] + " *" + length + " *" + name.trim() + " *" + hash[5] + " *" + hash[6]);
                    System.out.flush();
                } catch (Exception e) {
                    System.err.println(file);
                }
            }
        }
    }

    private static String clean(String name) {
        int p2 = name.lastIndexOf("].");
        if (p2 > 0) {
            int p1 = name.lastIndexOf('[', p2);
            if (p1 > 0 && p1 < p2 - 1) {
                boolean ok = true;
                for (int i = p1 + 1; i < p2; i++) {
                    if (!Character.isDigit(name.charAt(i))) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    return name.substring(0, p1) + name.substring(p2 + 1);
                }
            }
        }
        return name;
    }

    private static String[] getHashes(File file) throws Exception {
        digestMD5_512.reset();
        digestMD5_64K.reset();
        digestMD5_1M.reset();
        digestMD5total.reset();
        digestMD4.reset();
        digestEdonkey.reset();
        digestSHA1.reset();
        digestSHA256.reset();
        InputStream is = new BufferedInputStream(new FileInputStream(file), (int) Math.min(file.length(), 1 << 20));
        byte[] buffer = new byte[512];
        int read = 0;
        int size = 0;
        long lsize = 0;
        while ((read = is.read(buffer)) > 0) {
            if (size == edonkeyBlock) {
                size = 0;
                byte[] sum = digestMD4.digest();
                digestEdonkey.update(sum);
                digestMD4.reset();
            }
            digestMD5total.update(buffer, 0, read);
            digestSHA1.update(buffer, 0, read);
            digestSHA256.update(buffer, 0, read);
            digestMD4.update(buffer, 0, read);
            size += read;
            lsize += read;
            if (lsize <= 512) digestMD5_512.update(buffer, 0, read);
            if (lsize <= 64 << 10) digestMD5_64K.update(buffer, 0, read);
            if (lsize <= 1 << 20) digestMD5_1M.update(buffer, 0, read);
        }
        is.close();
        String edonkey = "";
        if (file.length() <= edonkeyBlock) {
            edonkey = getHash(digestMD4);
        } else {
            byte[] sum = digestMD4.digest();
            digestEdonkey.update(sum);
            edonkey = getHash(digestEdonkey);
        }
        return new String[] {getHash(digestMD5total),getHash(digestMD5_64K),edonkey,getHash(digestSHA1),getHash(digestMD5_512),getHash(digestMD5_1M),getHash(digestSHA256)};
    }

    private static String getHash(MessageDigest digest) throws Exception {
        byte[] sum = digest.digest();
        BigInteger bigInt = new BigInteger(1, sum);
        String output = bigInt.toString(16);
        int len = sum.length * 2;
        StringBuilder sb = new StringBuilder(len);
        int add = len - output.length();
        for (int i = 0; i < add; i++) {
            sb.append('0');
        }
        sb.append(output);
        return sb.toString();
    }
}