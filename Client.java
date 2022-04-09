
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author hp
 */
public class Client extends RSAKeyGen{
    
   
    
    public static void main(String args[]) throws Exception{
        
        Socket socket= null;
        InputStreamReader inputstreamreader=null;
        OutputStreamWriter outputstreamwriter=null;
        BufferedReader bufferedreader=null;
        BufferedWriter bufferedwriter=null;
        
        PublicKey publicKey=null;
        PublicKey publicKey1=null;
        PrivateKey privateKey = null;
        
        String host=args[0];
        int port=Integer.parseInt(args[1]);
        String user_id=args[2];
        
        FileInputStream fin_pub,fin_prv;
        
        ObjectInputStream objStream_pub,objStream_prv;
        
        File file=new File(user_id+".prv");
        
        if(file.exists()){
            
            fin_pub = new FileInputStream(user_id+".pub");
            objStream_pub = new ObjectInputStream(fin_pub);
            publicKey=(PublicKey) objStream_pub.readObject();
        
            fin_prv =new FileInputStream(user_id+".prv");
            objStream_prv= new ObjectInputStream(fin_prv);
        
            privateKey=(PrivateKey) objStream_prv.readObject();
            
        }
        else{
            
            String[] arguments= new String[]{user_id};
            RSAKeyGen.main(arguments);
            
            fin_pub = new FileInputStream(user_id+".pub");
            objStream_pub = new ObjectInputStream(fin_pub);
            publicKey=(PublicKey) objStream_pub.readObject();
        
            fin_prv =new FileInputStream(user_id+".prv");
            objStream_prv= new ObjectInputStream(fin_prv);
        
            privateKey=(PrivateKey) objStream_prv.readObject();
            
        }
        
        
        
        socket=new Socket(host,port); 
        outputstreamwriter=new OutputStreamWriter(socket.getOutputStream());
        bufferedwriter=new BufferedWriter(outputstreamwriter);
        
        bufferedwriter.write(user_id);
        bufferedwriter.newLine();
        bufferedwriter.flush();
        
        
            
        try{
            
            //socket=new Socket("localhost",9999);
            
            inputstreamreader=new InputStreamReader(socket.getInputStream());
            outputstreamwriter=new OutputStreamWriter(socket.getOutputStream());
            
            bufferedreader=new BufferedReader(inputstreamreader);
            bufferedwriter=new BufferedWriter(outputstreamwriter);
            
            
            
            while(true){
                
                System.out.println("\nChoose option 1, 2 or 3");
                System.out.println("1. Check Messages");
                System.out.println("2. Send Message");
                System.out.println("3. Exit");
                
                Scanner sc=new Scanner(System.in);
                
                if(sc.hasNextInt()){
                    int option=sc.nextInt();
                    sc.nextLine();
                    bufferedwriter.write(Integer.toString(option)+","+user_id);
                    bufferedwriter.newLine();
                    bufferedwriter.flush();

                    if(option==1){

                        String mssg;
                        while(!(mssg=bufferedreader.readLine()).equals("stop")){

                            if(mssg.equals("empty")){
                                System.out.println("\nYou have no Messages\n");
                                break;
                            }
                            else{
                            List list = new ArrayList(Arrays.asList(mssg.split(",")));

                            try{
                                byte[] encryptedBytes=Base64.getDecoder().decode(list.get(1).toString());
                                Cipher cipher=Cipher.getInstance("RSA/ECB/PKCS1Padding");
                                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                                byte[] decryptedBytes=cipher.doFinal(encryptedBytes);
                                String decryptedMessg=new String(decryptedBytes,"UTF-8");

                                System.out.println("Sender: "+list.get(0));
                                System.out.println("Date Time: "+list.get(2));
                                System.out.println("Message: "+decryptedMessg+"\n");
                            }


                            catch(BadPaddingException | IllegalArgumentException e){
                                System.out.println("\nSender: "+list.get(0));
                                System.out.println("Date Time: "+list.get(2));
                                System.out.println("Message: "+list.get(1)+"\n");
                            }


                            }

                        }

                    }

                    else if(option==2){
                        System.out.println("Enter recipients userid(type 'all' for posting without encryption)");
                        String rec=sc.nextLine();
                        System.out.println("Enter Message");
                        String mssg=sc.nextLine();
                        LocalDateTime myDateObj = LocalDateTime.now();
                        DateTimeFormatter myFormatObj = DateTimeFormatter.ofPattern("E MMM dd yyyy HH:mm:ss");
                        String formattedDate = myDateObj.format(myFormatObj);

                        String final_messg="";

                        Signature sign = Signature.getInstance("SHA256withRSA");
                        sign.initSign(privateKey);


                        if(rec.equals("all")){

                            final_messg=user_id+"%"+rec+"%"+mssg+"%"+formattedDate;

                            byte[] bytes = final_messg.getBytes();
                            sign.update(bytes);
                            byte[] signature = sign.sign();

                            bufferedwriter.write(final_messg+"%"+Base64.getEncoder().encodeToString(signature));
                            bufferedwriter.newLine();
                            bufferedwriter.flush();

                        }


                        else{

                            try{

                                FileInputStream fin=new FileInputStream(rec+".pub");
                            ObjectInputStream objStream=new ObjectInputStream(fin);
                            publicKey1=(PublicKey) objStream.readObject();


                            byte[] messgtoBytes=mssg.getBytes();
                            Cipher cipher=Cipher.getInstance("RSA/ECB/PKCS1Padding");
                            cipher.init(Cipher.ENCRYPT_MODE, publicKey1);
                            byte[] encryptedBytes=cipher.doFinal(messgtoBytes);
                            String encryptedMessg=Base64.getEncoder().encodeToString(encryptedBytes);

                            final_messg=user_id+"%"+rec+"%"+encryptedMessg+"%"+formattedDate;


                            byte[] bytes = final_messg.getBytes();
                            sign.update(bytes);
                            byte[] signature = sign.sign();

                            //System.out.println(Base64.getEncoder().encodeToString(signature));

                            bufferedwriter.write(final_messg+"%"+Base64.getEncoder().encodeToString(signature));
                            bufferedwriter.newLine();
                            bufferedwriter.flush();

                            }

                            catch(FileNotFoundException e){
                                System.out.println("\n"+rec+" is not a User"+"\n");
                                bufferedwriter.write("error");
                                bufferedwriter.newLine();
                                bufferedwriter.flush();

                            }


                        }


                    }

                    else if(option==3){
                        break;
                    }

                    else{
                        System.out.println("Invalid option");
                       
                    }
                }
                else{
                    System.out.println("Invalid option");
                }
            }
            
            
        }
        
        
        catch(Exception e){
            e.printStackTrace();
        }
        
        finally{
            try{
                if(socket!=null){
                    socket.close();
                }
                
                if(inputstreamreader!=null){
                    inputstreamreader.close();
                }
                
                if(outputstreamwriter!=null){
                    outputstreamwriter.close();
                }
                
                if(bufferedreader!=null){
                    bufferedreader.close();
                }
                
                if(bufferedwriter!=null){
                    bufferedwriter.close();
                }
            }
            
            catch(Exception e){
                e.printStackTrace();
            }
        }
    }
    
}
