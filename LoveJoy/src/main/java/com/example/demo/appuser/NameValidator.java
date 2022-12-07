package com.example.demo.appuser;

import org.springframework.stereotype.Service;

import java.util.function.Predicate;

@Service
public class NameValidator implements Predicate<String> {
    @Override
    public boolean test(String name) {
        //Name can only contain alphabetic characters
        if(name == null){
            return false;
        }

        for (int i = 0;i<name.length();i++){
            char c = name.charAt(i);
            if(!Character.isAlphabetic(c)){
                return false;
            }
        }

        return true;
    }
}
