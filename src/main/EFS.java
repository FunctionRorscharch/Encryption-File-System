package main;
import java.io.File;
import java.util.Arrays;
/**
 *
 * 
 * @modifier Hector Feng
 */
public class EFS extends Utility{
    
    public EFS(Editor e)
    {
        super(e);
        set_username_password();
    }
    
    public static byte[] compensate(byte[] a) throws Exception {
    	if(a.length>1024)
    	{
    		a[1023]=a[1024];
    		byte[] rst=Arrays.copyOfRange(a, 0, 1024);
    		return rst;
    	}
    	else
    	{
    		return a;
    	}
    }
    @Override
//    public void create(String file_name, String user_name, String password) throws Exception {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
    public void create(String file_name, String user_name, String password) throws Exception 
    {
    	File dir = new File(file_name);     
        dir.mkdirs();                     
        File meta = new File(dir, "0");         
        String toWrite = "";      
        toWrite = "0\n";     
        toWrite += user_name;   
        
        while (toWrite.length() < Config.BLOCK_SIZE)
            toWrite += '\0';
        byte[] bytetoWrite = toWrite.getBytes("utf-8");
        byte[] bytepassword = password.getBytes("utf-8");
        byte[] encryptedMeta=encript_AES(compensate(bytetoWrite),bytepassword);
        save_to_file(encryptedMeta, meta);
        return;
    }

    @Override
//    public String findUser(String file_name) throws Exception {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
    public String findUser(String file_name) throws Exception {
    	File file = new File(file_name);
        File meta = new File(file, "0");
        byte[] bytepassword = password.getBytes("utf-8");
        String s = new String(decript_AES(read_from_file(meta),bytepassword));
        String[] strs = s.split("\n");
        return strs[1];  	
    }
    
//    @Override
//    public int length(String file_name, String password) throws Exception {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
    @Override
    public int length(String file_name, String password) throws Exception {
    	File file = new File(file_name);
        File meta = new File(file, "0");
        byte[] bytepassword = password.getBytes("utf-8");
        String s = new String(decript_AES(read_from_file(meta),bytepassword));
        String[] strs = s.split("\n");
        return Integer.parseInt(strs[0]); 
    }

    @Override
//    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
    	File root = new File(file_name);
        int file_length = length(file_name, password);
        if (starting_position + len > file_length) {
            throw new Exception();
        }
        int start_block = starting_position / Config.BLOCK_SIZE;
        int end_block = (starting_position + len) / Config.BLOCK_SIZE;
        String toReturn = "";
        for (int i = start_block + 1; i <= end_block + 1; i++) {
        	byte[] bytepassword = password.getBytes("utf-8");
            String temp = new String(decript_AES(read_from_file(new File(root, Integer.toString(i))),bytepassword));
            if (i == end_block + 1) {
                temp = temp.substring(0, starting_position + len - end_block * Config.BLOCK_SIZE);
            }
            if (i == start_block + 1) {
                temp = temp.substring(starting_position - start_block * Config.BLOCK_SIZE);
            }
            toReturn += temp;
        }
        return toReturn.getBytes("UTF-8");
    }
    
    
    @Override
//    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
    public void write(String file_name, int starting_position, byte[] bytecontent, String password) throws Exception {
    	String content=byteArray2String(bytecontent);
    	File root = new File(file_name);
    	byte[] bytepassword = password.getBytes("utf-8");
        int file_length = length(file_name, password);
        if (starting_position > file_length) {
            throw new Exception();
        }
        int len = content.length();
        int start_block = starting_position / Config.BLOCK_SIZE;
        int end_block = (starting_position + len) / Config.BLOCK_SIZE;
        
        for (int i = start_block + 1; i <= end_block + 1; i++) {
            int sp = (i - 1) * Config.BLOCK_SIZE - starting_position;
            int ep = (i) * Config.BLOCK_SIZE - starting_position;
            String prefix = "";
            String postfix = "";
            if (i == start_block + 1 && starting_position != start_block * Config.BLOCK_SIZE) {
                prefix = new String(decript_AES(read_from_file(new File(root, Integer.toString(i))),bytepassword));
                prefix = prefix.substring(0, starting_position - start_block * Config.BLOCK_SIZE);
                sp = Math.max(sp, 0);
            }
            if (i == end_block + 1) {
                File end = new File(root, Integer.toString(i));
                if (end.exists()) {
                    postfix = new String(decript_AES(read_from_file(new File(root, Integer.toString(i))),bytepassword));
                    if (postfix.length() > starting_position + len - end_block * Config.BLOCK_SIZE) {
                        postfix = postfix.substring(starting_position + len - end_block * Config.BLOCK_SIZE);
                    } else {
                        postfix = "";
                    }
                }
                ep = Math.min(ep, len);
            }
            String toWrite = prefix + content.substring(sp, ep) + postfix;
            while (toWrite.length() < Config.BLOCK_SIZE) {
                toWrite += '\0';
            }
            byte[] bytetoWrite = toWrite.getBytes("utf-8");
            byte[] toWriteEncryption=encript_AES(compensate(bytetoWrite),bytepassword);
            save_to_file(toWriteEncryption, new File(root, Integer.toString(i)));
        }
        //update meta data
        if (content.length() + starting_position > length(file_name, password)) {
        	
            String s = new String(decript_AES(read_from_file(new File(root, "0")),bytepassword));
            String[] strs = s.split("\n");
            strs[0] = Integer.toString(content.length() + starting_position);
            String toWrite = "";
            for (String t : strs) {
                toWrite += t + "\n";
            }
            while (toWrite.length() < Config.BLOCK_SIZE) {
                toWrite += '\0';
            }
            byte[] bytetoWrite = toWrite.getBytes("utf-8");
            byte[] encryptedMeta=encript_AES(compensate(bytetoWrite),bytepassword);
            save_to_file(encryptedMeta, new File(root, "0"));
        }
        //update hash data
        int newLen=length(file_name,password);
        String metaInfo=findUser(file_name);
        byte[] totalContext=new byte[read(file_name, 0, newLen, password).length+metaInfo.getBytes("UTF-8").length];
        System.arraycopy(read(file_name, 0, newLen, password), 0, totalContext, 0, read(file_name, 0, newLen, password).length);  
        System.arraycopy(metaInfo.getBytes("UTF-8"), 0, totalContext, read(file_name, 0, newLen, password).length, metaInfo.getBytes("UTF-8").length);
        byte[] nowHash = hash_SHA512(totalContext);
        save_to_file(nowHash, new File(root,"h"));
    }
    
    @Override
//    public boolean check_integrity(String file_name, String password) throws Exception {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
    public boolean check_integrity(String file_name, String password) throws Exception {
        File file=new File(file_name);
        File hash=new File(file,"h");
        byte[] lastHash = read_from_file(hash);
        int newLen=length(file_name,password);
        String metaInfo=findUser(file_name);
        byte[] totalContext=new byte[read(file_name, 0, newLen, password).length+metaInfo.getBytes("UTF-8").length];
        System.arraycopy(read(file_name, 0, newLen, password), 0, totalContext, 0, read(file_name, 0, newLen, password).length);  
        System.arraycopy(metaInfo.getBytes("UTF-8"), 0, totalContext, read(file_name, 0, newLen, password).length, metaInfo.getBytes("UTF-8").length);
        byte[] nowHash = hash_SHA512(totalContext);
            
        if(Arrays.equals(nowHash, lastHash))
            return true;
        else return false;               
    }
    @Override
//    public void cut(String file_name, int length, String password) throws Exception {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
    public void cut(String file_name, int len, String password) throws Exception {
        byte[] bytepassword = password.getBytes("utf-8");
    	File root = new File(file_name);
        int file_length = length(file_name, password);
        if (len > file_length) {
            throw new Exception();
        }
        int end_block = (len) / Config.BLOCK_SIZE;
        File file = new File(root, Integer.toString(end_block + 1));
        String str = new String(decript_AES(read_from_file(file),bytepassword));
        str = str.substring(0, len - end_block * Config.BLOCK_SIZE);
        while (str.length() < Config.BLOCK_SIZE) {
            str += '\0';
        }
        byte[] bytestr = str.getBytes("utf-8");
        byte[] encryptedStr=encript_AES(compensate(bytestr),bytepassword);
        save_to_file(encryptedStr, file);
        int cur = end_block + 2;
        file = new File(root, Integer.toString(cur));
        while (file.exists()) {
            file.delete();
            cur++;
        }
        //update meta data
        String s = new String(decript_AES(read_from_file(new File(root, "0")),bytepassword));
        String[] strs = s.split("\n");
        strs[0] = Integer.toString(len);
        String toWrite = "";
        for (String t : strs) {
            toWrite += t + "\n";
        }
        while (toWrite.length() < Config.BLOCK_SIZE) {
            toWrite += '\0';
        }
        byte[] bytetoWrite = toWrite.getBytes("utf-8");
        byte[] encryptedToWrite=encript_AES(bytetoWrite,bytepassword);
        save_to_file(encryptedToWrite, new File(root, "0"));
        
        //update hash data
        int newLen=length(file_name,password);
        String metaInfo=findUser(file_name);
        byte[] totalContext=new byte[read(file_name, 0, newLen, password).length+metaInfo.getBytes("UTF-8").length];
        System.arraycopy(read(file_name, 0, newLen, password), 0, totalContext, 0, read(file_name, 0, newLen, password).length);  
        System.arraycopy(metaInfo.getBytes("UTF-8"), 0, totalContext, read(file_name, 0, newLen, password).length, metaInfo.getBytes("UTF-8").length);
        byte[] nowHash = hash_SHA512(totalContext);        
        save_to_file(nowHash, new File(root,"h"));
    } 
}
