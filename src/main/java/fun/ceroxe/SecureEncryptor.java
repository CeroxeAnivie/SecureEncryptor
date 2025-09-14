package fun.ceroxe;

import plethora.management.bufferedFile.BufferedFile;
import plethora.print.log.LogType;
import plethora.print.log.Loggist;
import plethora.print.log.State;
import plethora.security.encryption.AESUtil;
import plethora.time.Time;

import java.io.*;
import java.util.Scanner;
import java.util.concurrent.CopyOnWriteArrayList;

public class SecureEncryptor {
    public static Loggist loggist;
    public static AESUtil aesUtil = new AESUtil(128);
    public static final Scanner scanner=new Scanner(System.in);
    public static void main(String[] args) {
        try {
            String currentDir = System.getProperty("user.dir");
            File logFile = new File(currentDir + File.separator + "logs" + File.separator + Time.getCurrentTimeAsFileName(false) + ".log");
            loggist=new Loggist(logFile);
            say("""
                    
                       _____                                    \s
                      / ____|                                   \s
                     | |        ___   _ __    ___   __  __   ___\s
                     | |       / _ \\ | '__|  / _ \\  \\ \\/ /  / _ \\
                     | |____  |  __/ | |    | (_) |  >  <  |  __/
                      \\_____|  \\___| |_|     \\___/  /_/\\_\\  \\___|
                                                                \s
                                                                 \
                    """);
            say("欢迎使用 Ceroxe 开发的文件安全加密工具，当前算法为 AES-128-GCM ");
            sayInfoNoNewLine("输入 0 进入加密模式，输入 1 进入解密模式：");
            String mode=scanner.nextLine();
            if (mode.equals("0")){
                doEncrypt();
                exitAndFreeze(-1);
            } else if (mode.equals("1")) {
                doDecrypt();
                exitAndFreeze(-1);
            } else {
                exitAndFreeze(-1);
            }
        }catch (Exception e){
            e.printStackTrace();
            exitAndFreeze(-1);
        }
    }


    public static void say(String str) {
        loggist.say(new State(LogType.INFO, "Main", str));
    }

    public static void say(String str, LogType logType) {
        loggist.say(new State(logType, "Main", str));
    }
    public static void sayInfoNoNewLine(String str) {
        loggist.sayNoNewLine(new State(LogType.INFO, "Main", str));
    }
    public static boolean isLegal(BufferedFile bufferedFile){
        return bufferedFile.canAccess();
    }
    public static byte[] readAllData(BufferedFile file) throws IOException {
        BufferedInputStream bufferedInputStream=new BufferedInputStream(new FileInputStream(file));
        return bufferedInputStream.readAllBytes();
    }
    public static void writeFile(BufferedFile file,byte[] data) throws IOException {
        BufferedOutputStream bufferedOutputStream=new BufferedOutputStream(new FileOutputStream(file));
        bufferedOutputStream.write(data);
        bufferedOutputStream.flush();
    }
    public static void doEncrypt(){
        sayInfoNoNewLine("请输入输入文件路径，如果为文件夹则选择目录下所有文件：");

        String inputPath=listenInputPath();
        BufferedFile inputFile=new BufferedFile(inputPath);
        if (!isLegal(inputFile)){
            say("路径不合法，或者无法访问",LogType.ERROR);
            exitAndFreeze(-1);
        }

        sayInfoNoNewLine("请输入输出文件夹路径，必须是文件夹：");
        String outputPath=listenInputPath();
        BufferedFile outputFile=new BufferedFile(outputPath);
        if (!outputFile.exists()){
            say("文件夹不存在",LogType.ERROR);
            exitAndFreeze(-1);
        } else if (outputFile.isFile()) {
            say("必须是文件夹",LogType.ERROR);
            exitAndFreeze(-1);
        } else if ( !outputFile.canWrite() || !outputFile.canRead()){
            say("无法访问文件夹",LogType.ERROR);
            exitAndFreeze(-1);
        }

        String key = aesUtil.getEncodedKey();
        say("开始加密，密钥为："+key);

        if (inputFile.isDirectory()){
            CopyOnWriteArrayList<BufferedFile> files=inputFile.getAllFiles(false);
            for (BufferedFile file : files){
                say("正在加密 "+file.getAbsolutePath());
                try {
                    byte[] data=readAllData(file);
                    BufferedFile destFile=new BufferedFile(outputPath+File.separator+file.getName()+".aes128gcm");
                    destFile.createNewFile();
                    writeFile(destFile,aesUtil.encrypt(data));
                    say("已加密 "+file.getAbsolutePath() +" 文件至 "+destFile.getAbsolutePath());
                }catch (Exception e){
                    say("无法加密 "+file.getAbsolutePath(),LogType.ERROR);
                }
            }
        }else{
            try {
                byte[] data=readAllData(inputFile);
                BufferedFile destFile=new BufferedFile(outputPath+File.separator+inputFile.getName()+".aes128gcm");
                destFile.createNewFile();
                writeFile(destFile,aesUtil.encrypt(data));
                say("已加密 "+inputFile.getAbsolutePath() +" 文件至 "+destFile.getAbsolutePath());
            }catch (Exception e){
                say("无法加密 "+inputFile.getAbsolutePath(),LogType.ERROR);
            }
        }
        say("加密完成，请保存密钥："+key);
        exitAndFreeze(-1);
    }
    public static void doDecrypt(){
        sayInfoNoNewLine("请输入当前算法的密钥：");
        try {
            aesUtil=new AESUtil(scanner.nextLine());
        }catch (Exception e){
            say("无效的密钥",LogType.ERROR);
            exitAndFreeze(-1);
        }

        sayInfoNoNewLine("请输入输入文件路径，如果为文件夹则选择目录下所有文件：");
        String inputPath=listenInputPath();
        BufferedFile inputFile=new BufferedFile(inputPath);
        if (!isLegal(inputFile)){
            say("路径不合法，或者无法访问",LogType.ERROR);
            exitAndFreeze(-1);
        }

        sayInfoNoNewLine("请输入输出文件夹路径，必须是文件夹：");
        String outputPath=listenInputPath();
        BufferedFile outputFile=new BufferedFile(outputPath);
        if (!outputFile.exists()){
            say("文件夹不存在",LogType.ERROR);
            exitAndFreeze(-1);
        } else if (outputFile.isFile()) {
            say("必须是文件夹",LogType.ERROR);
            exitAndFreeze(-1);
        } else if ( !outputFile.canWrite() || !outputFile.canRead()){
            say("无法访问文件夹",LogType.ERROR);
            exitAndFreeze(-1);
        }

        String key = aesUtil.getEncodedKey();
        say("开始解密，使用密钥："+key);

        if (inputFile.isDirectory()){
            CopyOnWriteArrayList<BufferedFile> files=inputFile.getAllFiles(false);
            for (BufferedFile file : files){
                say("正在解密 "+file.getAbsolutePath());
                try {
                    byte[] endata=readAllData(file);

                    BufferedFile destFile;
                    if (file.getAbsolutePath().endsWith(".aes128gcm")){
                        String name=file.getName();
                        name=name.substring(0,name.length()-".aes128gcm".length());
                        destFile=new BufferedFile(outputPath+File.separator+name);
                    }else{
                        destFile=new BufferedFile(outputPath+File.separator+file.getName());
                    }
                    if (destFile.exists()){
                        say("输出文件 "+inputFile.getAbsolutePath()+" 本身存在，跳过该文件",LogType.ERROR);
                        continue;
                    }else{
                        destFile.createNewFile();
                    }
                    writeFile(destFile,aesUtil.decrypt(endata));
                    say("已解密 "+file.getAbsolutePath() +" 文件至 "+destFile.getAbsolutePath());
                }catch (Exception e){
                    say("无法解密 "+file.getAbsolutePath(),LogType.ERROR);
                }
            }
        }else{
            try {
                byte[] data=readAllData(inputFile);
                BufferedFile destFile;
                if (inputFile.getAbsolutePath().endsWith(".aes128gcm")){
                    String name=inputFile.getName();
                    name=name.substring(0,name.length()-".aes128gcm".length());
                    destFile=new BufferedFile(outputPath+File.separator+name);
                }else{
                    destFile=new BufferedFile(outputPath+File.separator+inputFile.getName());
                }
                if (destFile.exists()){
                    say("输出文件 "+destFile.getAbsolutePath()+" 本身存在，跳过该文件",LogType.ERROR);
                    return;
                }else{
                    destFile.createNewFile();
                }
                writeFile(destFile,aesUtil.decrypt(data));
                say("已解密 "+inputFile.getAbsolutePath() +" 文件至 "+destFile.getAbsolutePath());
            }catch (Exception e){
                say("无法解密 "+inputFile.getAbsolutePath(),LogType.ERROR);
            }
        }
        say("解密完成");
        exitAndFreeze(-1);
    }
    public static void exitAndFreeze(int exitCode) {
        say("Press enter to exit the program...");
        scanner.nextLine();
        System.exit(exitCode);
    }
    public static String listenInputPath(){
        String inputPath=scanner.nextLine();
        if (inputPath.startsWith("\"")&&inputPath.endsWith("\"")){
            inputPath=inputPath.substring(1,inputPath.length()-1);
        }
        return inputPath;
    }
}