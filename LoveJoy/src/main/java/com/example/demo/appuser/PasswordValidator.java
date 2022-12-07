package com.example.demo.appuser;

import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class PasswordValidator implements Predicate<String> {
    @Override
    public boolean test(String password) {
        //Password must contain at least 8 character
        // Has a digital number
        // Has a Upper case letter
        // Has a lower case letter
        // Has a special character
        // Different to any of the password in the top 10000 most common passwords

        Boolean validLength = password.length() > 7;

        if (validLength && hasSpecialCharacter(password)) {
            Boolean hasNum = false;
            Boolean hasUpper = false;
            Boolean hasLow = false;

            char c;

            for (int i = 0; i < password.length(); i++) {
                c = password.charAt(i);
                if (Character.isDigit(c)) {
                    hasNum = true;
                }
                else if (Character.isUpperCase(c)) {
                    hasUpper = true;
                }
                else if (Character.isLowerCase(c)) {
                    hasLow = true;
                }
                if(hasNum && hasLow && hasUpper){
                    try{
                        Boolean notCommon = notCommon(password);
                        return notCommon;
                    }
                    catch (IOException e){
                        System.out.println("File not found");
                        return false;
                    }
                }
            }
        }
        return false;
    }

    public boolean hasSpecialCharacter(String password){
        Pattern p = Pattern.compile("[a-zA-Z0-9]*");
        Matcher m = p.matcher(password);

        if(!m.matches()){
            return true;
        }
        return false;
    }


    public boolean notCommon(String password) throws IOException {
        ClassLoader classloader = Thread.currentThread().getContextClassLoader();
        InputStream is = classloader.getResourceAsStream("commonDict.txt");
        InputStreamReader streamReader = new InputStreamReader(is, StandardCharsets.UTF_8);
        BufferedReader reader = new BufferedReader(streamReader);
        for (String line; (line = reader.readLine()) != null;) {
            if(line==password){
                return false;
            }
        }
        return true;
    }
}
