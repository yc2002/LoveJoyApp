package com.example.demo.appuser;

import org.springframework.stereotype.Service;

import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class TeleValidator implements Predicate<String> {
    @Override

    public boolean test(String number) {
        //Uk telephone regex
        String regex = "^(?:(?:\\(?(?:0(?:0|11)\\)?[\\s-]?\\(?|\\+)44\\)?[\\s-]?(?:\\(?0\\)?[\\s-]?)?)|(?:\\(?0))" +
                "(?:(?:\\d{5}\\)?[\\s-]?\\d{4,5})|(?:\\d{4}\\)?[\\s-]?(?:\\d{5}|\\d{3}[\\s-]?" +
                "\\d{3}))|(?:\\d{3}\\)?[\\s-]?\\d{3}[\\s-]?\\d{3,4})|(?:\\d{2}\\)?[\\s-]?\\d{4}[\\s-]?" +
                "\\d{4}))(?:[\\s-]?(?:x|ext\\.?|\\#)\\d{3,4})?$";
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(number);

        return m.matches();
    }

    //Values that match the regex:
    //01222 555 555 | (010) 55555555 #2222 | 0122 555 5555#222 | 07222 555555 | (07222) 555555 | +44 7222 555 555
    // | +447222555555 | +44 7222 555 555 | (0722) 5555555 #2222

    //Values that do not match the regex:
    // 01222 555 5555 | (010) 55555555 #22 | 0122 5555 5555#222 | 7222 555555 | +44 07222 555555 | (+447222) 555555
    // | (+447222)555555 | +44(7222)555555 | (0722) 5555555 #22
}
