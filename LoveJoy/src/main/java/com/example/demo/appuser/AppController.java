package com.example.demo.appuser;

import com.example.demo.appuser.AppUser;
import com.example.demo.appuser.AppUserService;
import com.example.demo.email.EmailService;
import com.example.demo.request.EvaluationRequest;
import com.example.demo.request.EvaluationRequestRepository;
import com.example.demo.request.RequestDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.data.repository.query.Param;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.multipart.MultipartFile;
import java.io.*;
import java.nio.file.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.UUID;

@Controller
public class AppController {

    @Autowired
    private AppUserService appUserService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private EvaluationRequestRepository evaluationRequestRepository;

    @Value("${recaptcha.secret}")
    private String recaptchaSecret;

    @Value("${recaptcha.url}")
    private String recaptchaUrl;

    @GetMapping("/")
    public String index() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return "index";
        }

        return "home";
    }

    @GetMapping("/login")
    public String showlogin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return "login";
        }

        return "home";
    }

    @PostMapping("/logout")
    public String logoutPage(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null){
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        return "index";
    }

    @GetMapping("/register")
    public String registerationForm(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            model.addAttribute("appUser", new AppUser());
            return "register";
        }
        return "home";
    }

    @PostMapping("/process_register")
    public String processRegister(AppUser appUser, HttpServletRequest request)
            throws UnsupportedEncodingException, MessagingException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String gRecaptchaResponse = request.getParameter("g-recaptcha-response");
        verifyReCaptCha(gRecaptchaResponse);
        appUserService.register(appUser, getSiteURL(request));
        return "register_success";
    }

    @GetMapping("/home")
    public String showHome() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return "login";
        }

        return "home";
    }

    private String getSiteURL(HttpServletRequest request) {
        String siteURL = request.getRequestURL().toString();
        return siteURL.replace(request.getServletPath(), "");
    }

    @GetMapping("/verify")
    public String verifyUser(@Param("code") String code) {
        if (appUserService.verify(code)) {
            return "verify_success";
        } else {
            return "verify_fail";
        }
    }

    @GetMapping("/forgot_password")
    public String showForgotPasswordForm() {
        return "forgotPasswordForm";
    }

    @PostMapping("/forgot_password")
    public String processForgotPassword(HttpServletRequest request, Model model) {
        String email = request.getParameter("email");
        String token = UUID.randomUUID().toString();
        String gRecaptchaResponse = request.getParameter("g-recaptcha-response");
        verifyReCaptCha(gRecaptchaResponse);

        try {
            appUserService.updateResetPasswordToken(token, email);
            String resetPasswordLink = getSiteURL(request) + "/reset_password?token=" + token;
            emailService.sendRecoveryEmail(email, resetPasswordLink);
            model.addAttribute("message", "We have sent a reset password link to your email. Please check.");

        } catch (UsernameNotFoundException ex) {
            model.addAttribute("error", ex.getMessage());
        } catch (UnsupportedEncodingException | MessagingException e) {
            model.addAttribute("error", "Error while sending email");
        }

        return "forgotPasswordForm";
    }



    @GetMapping("/reset_password")
    public String showResetPasswordForm(@Param(value = "token") String token, Model model) {
        AppUser appUser = appUserService.getByResetPasswordToken(token);
        model.addAttribute("token", token);

        if (appUser == null) {
            model.addAttribute("message", "Invalid Token");
            return "message";
        }

        return "resetPassword";
    }

    @PostMapping("/reset_password")
    public String processResetPassword(HttpServletRequest request, Model model) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String token = request.getParameter("token");
        String password = request.getParameter("password");
        String gRecaptchaResponse = request.getParameter("g-recaptcha-response");
        verifyReCaptCha(gRecaptchaResponse);

        AppUser appUser = appUserService.getByResetPasswordToken(token);
        model.addAttribute("title", "Reset your password");

        if (appUser == null) {
            model.addAttribute("message", "Invalid Token");
            return "message";
        }
        else
        {
            appUserService.updatePassword(appUser, password);
            model.addAttribute("message", "You have successfully changed your password.");
        }
        return "message";
    }


    @GetMapping("/request")
    public String showRequest(Model model){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return "login";
        }
        model.addAttribute("requestDetails",new RequestDetails());
        return "request";
    }

    @PostMapping("/process_request")
    public RedirectView processRequest(@ModelAttribute RequestDetails requestDetails,
        @RequestParam("image") MultipartFile multipartFile, HttpServletRequest request) throws IOException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        String gRecaptchaResponse = request.getParameter("g-recaptcha-response");
        verifyReCaptCha(gRecaptchaResponse);

        //create a new file name
        String fileName = StringUtils.cleanPath(multipartFile.getOriginalFilename());
        String new_file_name = UUID.randomUUID().toString();

        requestDetails.setPhotos(new_file_name);
        EvaluationRequest evaluationRequest = appUserService.submit_request(requestDetails);

        String uploadDir = "request-photos/" + evaluationRequest.getId();
        saveFile(uploadDir, new_file_name, multipartFile);
        return new RedirectView("/");
    }

    private void verifyReCaptCha(String gRecaptchaResponse) {
        HttpHeaders headers = new HttpHeaders();

        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("secret",recaptchaSecret);
        map.add("response",gRecaptchaResponse);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        RestTemplate restTemplate = new RestTemplate();

        ResponseEntity<String> response = restTemplate.postForEntity(recaptchaUrl,request, String.class);
    }

    @GetMapping("/listRequest")
    public String listRequest(Model model) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return "login";
        }

        AppUser appUser = (AppUser) authentication.getPrincipal();
        AppUserRole appUserRole = appUser.getAppUserRole();
        if(appUserRole == AppUserRole.ADMIN){
            List<EvaluationRequest> listRequest = evaluationRequestRepository.findAll();
            model.addAttribute("listRequest", listRequest);

            return "listRequest";
        }
        return "home";
    }

    public static void saveFile(String uploadDir, String fileName,
                                MultipartFile multipartFile) throws IOException {

        //Prevent Relative Path Attack using normalized Path
        Path uploadPath = Paths.get(uploadDir).normalize();

        final String BASE_PATH ="request-photos/";

        File file = new File(BASE_PATH,uploadPath.toString());

        if (file.isAbsolute())
        {
            throw new RuntimeException("Directory traversal attempt - absolute path not allowed");
        }

        String pathUsingCanonical;
        String pathUsingAbsolute;
        try
        {
            pathUsingCanonical = file.getCanonicalPath();
            pathUsingAbsolute = file.getAbsolutePath();
        }
        catch (IOException e)
        {
            throw new RuntimeException("Directory traversal attempt?", e);
        }


        // Require the absolute path and canonicalized path match.
        // This is done to avoid directory traversal
        // attacks, e.g. "1/../2/"
        if (! pathUsingCanonical.equals(pathUsingAbsolute))
        {
            throw new RuntimeException("Directory traversal attempt?");
        }




        if (!Files.exists(uploadPath)) {
            Files.createDirectories(uploadPath);
        }

        try (InputStream inputStream = multipartFile.getInputStream()) {
            Path filePath = uploadPath.resolve(fileName);
            Files.copy(inputStream, filePath, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException ioe) {
            throw new IOException("Could not save image file: " + fileName, ioe);
        }
    }
}
