package com.example.demo.appuser;

import org.springframework.stereotype.Service;
import java.util.regex.*;

import java.util.function.Predicate;

@Service
public class EmailValidator implements Predicate<String> {
    @Override
    public boolean test(String email) {

        //RFC 5322 regular expression for email validation prevent SQL injection
        String regex = "^[a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+$";

        return Pattern.compile(regex).matcher(email).matches();
    }
}
