package com.example.demo.appuser;

import com.example.demo.email.EmailSender;
import com.example.demo.request.EvaluationRequest;
import com.example.demo.request.EvaluationRequestService;
import com.example.demo.request.RequestDetails;
import com.example.demo.security.config.SecureDetailGenerator;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.UUID;

@Service
@Transactional
@AllArgsConstructor
public class AppUserService implements UserDetailsService {
    private final PasswordValidator passwordValidator;
    private final NameValidator nameValidator;
    private final TeleValidator teleValidator;
    private final NoteValidator noteValidator;

    public static final int MAX_FAILED_ATTEMPTS = 3;

    private static final long LOCK_TIME_DURATION = 24 * 60 * 60 * 1000; // 24 hours

    private final EmailValidator emailValidator;
    private final EmailSender emailSender;

    private final static String USER_NOT_FOUND_MSG =
            "user with email %s not found";

    private final AppUserRepository appUserRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final EvaluationRequestService evaluationRequestService;

    private final SecureDetailGenerator secureDetailGenerator;

    @Override
    public UserDetails loadUserByUsername(String email)
            throws UsernameNotFoundException {
        return appUserRepository.findByEmail(email)
                .orElseThrow(() ->
                        new UsernameNotFoundException(
                                String.format(USER_NOT_FOUND_MSG, email)));
    }


    public void register(AppUser appUser, String siteURL) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        // Validate user input
        boolean isValidEmail = emailValidator.
                test(appUser.getEmail());

        boolean isValidPassword = passwordValidator.test(appUser.getPassword());

        boolean isValidFirstName = nameValidator.test(appUser.getFirstName());

        boolean isValidLastName = nameValidator.test(appUser.getLastName());

        boolean isValidTele = teleValidator.test(appUser.getTeleNumber());
        if (!isValidEmail) {
            throw new IllegalStateException("Email not valid");
        }
        if (!isValidPassword) {
            throw new IllegalStateException("Password not valid");
        }
        if (!isValidFirstName) {
            throw new IllegalStateException("First Name not valid");
        }
        if (!isValidLastName) {
            throw new IllegalStateException("Last Name not valid");
        }
        if (!isValidTele) {
            throw new IllegalStateException("Telephone Number not valid");
        }

        boolean userExists = appUserRepository
                .findByEmail(appUser.getEmail())
                .isPresent();

        //Encryption algorithm
        String algorithm = "AES/CBC/PKCS5Padding";
        SecretKey key = secureDetailGenerator.generateKey(256);
        IvParameterSpec ivParameterSpec = secureDetailGenerator.generateIv();

        //check if user already registered in database, throw error if user is already registered and verified
        // If the user is found but not verified, send another verification email to user's email address.
        if (userExists) {
            AppUser user = (AppUser) loadUserByUsername(appUser.getEmail());

            if (user.isEnabled()) {
                throw new IllegalStateException("Email already taken");
            }

            //generate unique ID for verification purpose
            String code = UUID.randomUUID().toString();
            user.setVerificaton_code(code);
            user.setEnabled(false);
            appUserRepository.updateVertificationCodeByEmail(user.getVerificaton_code(), user.getEmail());
            String verifyURL = siteURL + "/verify?code=" + user.getVerificaton_code();

            //decrypt use's First name for sending verification email
            String decryptedFirstName = secureDetailGenerator.decrypt(algorithm, appUser.getFirstName(), key, ivParameterSpec);

            emailSender.send(
                    appUser.getEmail(),
                    buildEmail(decryptedFirstName, verifyURL));
            return;
        }

        //If user is not found in database, register user
        //1. Encode Password (bCrypt)
        //2. Encrypt sensitive information e.g. Name, Telephone Number
        //3. Generate UNIQUE verification code for verification purpose, and set user as not enabled i.e. not verified
        //   and role as a User i.e. not verified
        //4. Save the details in database
        //5. Send verification email to user's email address

        String encodedPassword = bCryptPasswordEncoder
                .encode(appUser.getPassword());
        appUser.setPassword(encodedPassword);

        String decryptedFirstName = appUser.getFirstName();
        String encryptedFirstName = secureDetailGenerator.encrypt(algorithm, appUser.getFirstName(), key, ivParameterSpec);
        String encryptedLastName = secureDetailGenerator.encrypt(algorithm, appUser.getLastName(), key, ivParameterSpec);
        String encryptedTeleNumber = secureDetailGenerator.encrypt(algorithm, appUser.getTeleNumber(), key, ivParameterSpec);

        appUser.setFirstName(encryptedFirstName);
        appUser.setLastName(encryptedLastName);
        appUser.setTeleNumber(encryptedTeleNumber);


        String code = UUID.randomUUID().toString();
        appUser.setVerificaton_code(code);
        appUser.setEnabled(false);
        appUser.setAppUserRole(AppUserRole.USER);

        appUserRepository.save(appUser);

        String verifyURL = siteURL + "/verify?code=" + appUser.getVerificaton_code();

        emailSender.send(
                appUser.getEmail(),
                buildEmail(decryptedFirstName, verifyURL));
    }


    public boolean verify(String verificationCode) {
        AppUser appUser = appUserRepository.findByVerificationCode(verificationCode);

        if (appUser == null || appUser.isEnabled()) {
            return false;
        } else {
            appUser.setVerificaton_code(null);
            appUser.setEnabled(true);
            appUserRepository.save(appUser);

            return true;
        }
    }

    public void updateResetPasswordToken(String token, String email) throws UsernameNotFoundException {
        //find user by email then
        //if user found, update resetPasswordToken
        // otherwise throw error
        AppUser appUser = appUserRepository.getByEmail(email);
        if (appUser != null) {
            appUser.setResetPasswordToken(token);
            appUserRepository.save(appUser);
        } else {
            throw new UsernameNotFoundException("Could not find any appUser with the email " + email);
        }
    }

    //get user by ResetPasswordToken
    public AppUser getByResetPasswordToken(String token) {
        return appUserRepository.findByResetPasswordToken(token);
    }

    public void updatePassword(AppUser appUser, String newPassword) {
        //check if the new password is valid
        boolean isValidPassword = passwordValidator.test(newPassword);
        if(isValidPassword) {
            //encode new password entered by user and set the user's ResetPasswordToken to null. Save User.
            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            String encodedPassword = passwordEncoder.encode(newPassword);
            appUser.setPassword(encodedPassword);

            appUser.setResetPasswordToken(null);
            appUserRepository.save(appUser);
        }
        else{
            throw new IllegalStateException("Invalid Password");
        }
    }

    public EvaluationRequest submit_request(RequestDetails requestDetails) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String note = requestDetails.getNote();
        String contact = requestDetails.getContact().toLowerCase();
        String photo = requestDetails.getPhotos();

        Boolean validNote = noteValidator.test(note);

        if (!validNote) {
            throw new IllegalStateException("Invalid Note");
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        AppUser appUser = (AppUser) authentication.getPrincipal();

        //String algorithm = "AES/CBC/PKCS5Padding";
        //SecretKey key = secureDetailGenerator.generateKey(256);
        //IvParameterSpec ivParameterSpec = secureDetailGenerator.generateIv();



        //String encryptedNote = secureDetailGenerator.encrypt(algorithm,requestDetails.getNote(),key,ivParameterSpec);
        EvaluationRequest evaluationRequest = new EvaluationRequest(contact, note, appUser, photo);
        evaluationRequest.setOpen(true);
        evaluationRequestService.saveEvaluationRequest(evaluationRequest);

        return evaluationRequest;
    }

    public void increaseFailedAttempts(AppUser appUser) {
        int newFailAttempts = appUser.getFailedAttempt() + 1;
        appUserRepository.updateFailedAttempts(newFailAttempts, appUser.getEmail());
    }

    public void resetFailedAttempts(String email) {
        appUserRepository.updateFailedAttempts(0, email);
    }

    public void lock(AppUser appUser) {
        appUser.setAccountNonLocked(false);
        appUser.setLockTime(new Date());

        appUserRepository.save(appUser);
    }

    public boolean unlockWhenTimeExpired(AppUser user) {
        long lockTimeInMillis = user.getLockTime().getTime();
        long currentTimeInMillis = System.currentTimeMillis();

        if (lockTimeInMillis + LOCK_TIME_DURATION < currentTimeInMillis) {
            user.setAccountNonLocked(true);
            user.setLockTime(null);
            user.setFailedAttempt(0);

            appUserRepository.save(user);

            return true;
        }

        return false;
    }

    public int enableAppUser(String email) {
        return appUserRepository.enableAppUser(email);
    }


    private String buildEmail(String name, String link) {
        return "<div style=\"font-family:Helvetica,Arial,sans-serif;font-size:16px;margin:0;color:#0b0c0c\">\n" +
                "\n" +
                "<span style=\"display:none;font-size:1px;color:#fff;max-height:0\"></span>\n" +
                "\n" +
                "  <table role=\"presentation\" width=\"100%\" style=\"border-collapse:collapse;min-width:100%;width:100%!important\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">\n" +
                "    <tbody><tr>\n" +
                "      <td width=\"100%\" height=\"53\" bgcolor=\"#0b0c0c\">\n" +
                "        \n" +
                "        <table role=\"presentation\" width=\"100%\" style=\"border-collapse:collapse;max-width:580px\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" align=\"center\">\n" +
                "          <tbody><tr>\n" +
                "            <td width=\"70\" bgcolor=\"#0b0c0c\" valign=\"middle\">\n" +
                "                <table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse\">\n" +
                "                  <tbody><tr>\n" +
                "                    <td style=\"padding-left:10px\">\n" +
                "                  \n" +
                "                    </td>\n" +
                "                    <td style=\"font-size:28px;line-height:1.315789474;Margin-top:4px;padding-left:10px\">\n" +
                "                      <span style=\"font-family:Helvetica,Arial,sans-serif;font-weight:700;color:#ffffff;text-decoration:none;vertical-align:top;display:inline-block\">Confirm your email</span>\n" +
                "                    </td>\n" +
                "                  </tr>\n" +
                "                </tbody></table>\n" +
                "              </a>\n" +
                "            </td>\n" +
                "          </tr>\n" +
                "        </tbody></table>\n" +
                "        \n" +
                "      </td>\n" +
                "    </tr>\n" +
                "  </tbody></table>\n" +
                "  <table role=\"presentation\" class=\"m_-6186904992287805515content\" align=\"center\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse;max-width:580px;width:100%!important\" width=\"100%\">\n" +
                "    <tbody><tr>\n" +
                "      <td width=\"10\" height=\"10\" valign=\"middle\"></td>\n" +
                "      <td>\n" +
                "        \n" +
                "                <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse\">\n" +
                "                  <tbody><tr>\n" +
                "                    <td bgcolor=\"#1D70B8\" width=\"100%\" height=\"10\"></td>\n" +
                "                  </tr>\n" +
                "                </tbody></table>\n" +
                "        \n" +
                "      </td>\n" +
                "      <td width=\"10\" valign=\"middle\" height=\"10\"></td>\n" +
                "    </tr>\n" +
                "  </tbody></table>\n" +
                "\n" +
                "\n" +
                "\n" +
                "  <table role=\"presentation\" class=\"m_-6186904992287805515content\" align=\"center\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse;max-width:580px;width:100%!important\" width=\"100%\">\n" +
                "    <tbody><tr>\n" +
                "      <td height=\"30\"><br></td>\n" +
                "    </tr>\n" +
                "    <tr>\n" +
                "      <td width=\"10\" valign=\"middle\"><br></td>\n" +
                "      <td style=\"font-family:Helvetica,Arial,sans-serif;font-size:19px;line-height:1.315789474;max-width:560px\">\n" +
                "        \n" +
                "            <p style=\"Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c\">Hi " + name + ",</p><p style=\"Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c\"> Thank you for registering. Please click on the below link to activate your account: </p><blockquote style=\"Margin:0 0 20px 0;border-left:10px solid #b1b4b6;padding:15px 0 0.1px 15px;font-size:19px;line-height:25px\"><p style=\"Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c\"> <a href=\"" + link + "\">Activate Now</a> </p></blockquote>\n Link will expire in 15 minutes. <p>See you soon</p>" +
                "           \n" +
                "      </td>\n" +
                "      <td width=\"10\" valign=\"middle\"><br></td>\n" +
                "    </tr>\n" +
                "    <tr>\n" +
                "      <td height=\"30\"><br></td>\n" +
                "    </tr>\n" +
                "  </tbody></table><div class=\"yj6qo\"></div><div class=\"adL\">\n" +
                "\n" +
                "</div></div>";
    }

    public AppUser getAppUserByEmail(String email) {
        return appUserRepository.getAppUserByEmail(email);
    }
}