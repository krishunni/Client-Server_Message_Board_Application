
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author hp
 */
public class Server {
    
   
    
    public static void main(String args[]) throws IOException, Exception{
        
        Socket socket=null;
        InputStreamReader inputstreamreader=null;
        OutputStreamWriter outputstreamwriter=null;
        BufferedReader bufferedreader=null;
        BufferedWriter bufferedwriter=null;
        ServerSocket serversocket=null;
        
        int port=Integer.parseInt(args[0]);
        
        
        serversocket=new ServerSocket(port);
        
        
        PublicKey publicKey = null;
        
        ArrayList<ArrayList> ml = new ArrayList();
        
        System.out.println("Server started");
        
        
        int i=0;
        while(true){
            
            
            try{
                
                
                socket=serversocket.accept();
                
                
                inputstreamreader=new InputStreamReader(socket.getInputStream());
                outputstreamwriter=new OutputStreamWriter(socket.getOutputStream());
            
                bufferedreader=new BufferedReader(inputstreamreader);
                bufferedwriter=new BufferedWriter(outputstreamwriter);
                
                String user_id=bufferedreader.readLine();
                System.out.println(user_id+" Connected");
                
                
                FileInputStream  fin =new FileInputStream(user_id+".pub");
                ObjectInputStream objStream = new ObjectInputStream(fin);

                publicKey=(PublicKey) objStream.readObject();
                
                
                
                
                while(true){
                    String str=bufferedreader.readLine();
                    List option = new ArrayList(Arrays.asList(str.split(",")));
                    //System.out.println(option.get());
                    
                    if(option.get(0).equals("1")){
                        
                        if(!(ml.isEmpty())){
                            for (int k=0;k<ml.size();k++){
                               
                                bufferedwriter.write((String) ml.get(k).get(0)+","+(String) ml.get(k).get(2)+","+(String) ml.get(k).get(3));
                                bufferedwriter.newLine();
                                bufferedwriter.flush();
                                
                            
                            }
                            bufferedwriter.write("stop");
                            bufferedwriter.newLine();
                            bufferedwriter.flush();
                            
                        }
                        else{
                        bufferedwriter.write("empty");
                        bufferedwriter.newLine();
                        bufferedwriter.flush();
                        }
                    }
                    
                    
                    if(option.get(0).equals("2")){
                        
                        Signature sign = Signature.getInstance("SHA256withRSA");
                        
                        String mssg=bufferedreader.readLine();
                        
                        if(!(mssg.equals("error"))){
                            
                            List list = list = new ArrayList(Arrays.asList(mssg.split("%")));
                        
                        
                            //System.out.println(list);
                            //System.out.println(ml);

                             String final_messg=list.get(0)+"%"+list.get(1)+"%"+list.get(2)+"%"+list.get(3);
                             byte[] bytes = final_messg.getBytes();

                             String signa=(String) list.get(4);
                             byte[] signature=Base64.getDecoder().decode(signa);

                             sign.initVerify(publicKey);
                             sign.update(bytes);



                             boolean bool = sign.verify(signature);

                             if(bool) {
                                 ml.add((ArrayList) list);

                                 ml.get(i).add(list);

                                 System.out.println("Signature verified");
                                 i+=1;


                             } else {
                                 System.out.println("Signature failed");
                             }

                             System.out.println(ml);


                        }
                   
                        
                    }
                    
                    if(option.get(0).equals("3")){
                        break;
                    }
                }
                
                socket.close();
                inputstreamreader.close();
                outputstreamwriter.close();
                bufferedreader.close();
                bufferedwriter.close();
            }
            
            
            
            
            catch(Exception e){
                System.out.println("Error has occured");
            }
        }
    }
    
}
