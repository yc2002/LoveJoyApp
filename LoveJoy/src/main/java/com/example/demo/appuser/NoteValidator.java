package com.example.demo.appuser;

import org.springframework.stereotype.Service;

import java.util.function.Predicate;

@Service
public class NoteValidator implements Predicate<String> {


    @Override
    public boolean test(String note) {
        //Note must not be empty
        //Must contain at lest an alphabetic character
        //Don't allow all special character

        if(note == null || note.length()==0){
            return false;
        }

        boolean hasAlphabet = false;

        for (int i = 0;i<note.length();i++){
            char c = note.charAt(i);

            if(Character.isAlphabetic(c)){
                hasAlphabet= true;
                continue;
            }
            if(Character.isDigit(c)){
                continue;
            }
            if(c == '.' || c==' ' || c == '-' || c == '+' || c=='(' || c ==')' || c==':'
            || c =='?' || c=='!' || c==','){
                continue;
            }
            return false;
        }

        return hasAlphabet;
    }
}
