import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;

public class DictionaryAttack {
    public static void main(String[] args) {
        try{
            passwordBruteForce("66f12623a2fa30f5db67af3b10d4afa72d54eb39c088571b2f681bd37f50f24d","ismsap");
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void passwordBruteForce(String pattern, String prefix) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        Provider provider=Security.getProvider("BC");
        if (provider == null) {
            System.out.println("Bouncy Castle isn't available.");
        } else {
            System.out.println("Bouncy Castle is available.");
        }

        long  tstart=System.currentTimeMillis();


        File passwordFile=new File("ignis-10M.txt");

        if(passwordFile.exists()){
            FileReader fileReader=new FileReader(passwordFile);
            BufferedReader bufferedReader=new BufferedReader(fileReader);
            String line=null;
            boolean isFound=false;

            System.out.println("Starting search for matching password for the provided hash value.");
            System.out.println("------------------------------------------------------------------\n");
            do{
                line=bufferedReader.readLine();
                if(line!=null){
                    String prefixedPassword=prefix+line;

                    MessageDigest md5=MessageDigest.getInstance("MD5","BC");
                    MessageDigest sha256=MessageDigest.getInstance("SHA-256","BC");

                    md5.update(prefixedPassword.getBytes());
                    sha256.update(md5.digest());

                    if(pattern.toLowerCase().equals(getHexStringFromByteArray(sha256.digest()))){
                        System.out.println("Password found: "+line);
                        isFound=true;
                    }

                }
            }while(line!=null && !isFound);

            if(!isFound){
                System.out.println("Password not found in current file");
            }

        }else{
            System.out.println("Password File not found. No operation executed.");
        }


        long tfinal=System.currentTimeMillis();
        System.out.println("Duration is : "+(tfinal-tstart));
    }

    private static String getHexStringFromByteArray(byte[] values){
        StringBuilder sb=new StringBuilder();
        for(byte value:values){
            sb.append(String.format("%02x",value));
        }
        return sb.toString();
    }
}
