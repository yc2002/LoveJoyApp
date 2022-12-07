package com.example.demo.request;

import com.example.demo.appuser.AppUser;
import com.example.demo.appuser.AppUserRepository;
import com.example.demo.appuser.AppUserService;
import com.example.demo.security.config.SecureDetailGenerator;
import lombok.AllArgsConstructor;
import org.apache.catalina.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Service
@AllArgsConstructor
public class EvaluationRequestService {
    private final EvaluationRequestRepository evaluationRequestRepository;
    private final SecureDetailGenerator secureDetailGenerator;

    public void saveEvaluationRequest(EvaluationRequest evaluationRequest){evaluationRequestRepository.save(evaluationRequest);}

    public EvaluationRequest getRequestByAppUser(AppUser appUser){return evaluationRequestRepository.findEvaluationRequestByAppUser(appUser);}

    public EvaluationRequest getRequestById(Long id){return evaluationRequestRepository.findEvaluationRequestById(id);}

    public void setOpen(Boolean status){evaluationRequestRepository.updateOpen(status);}

    public String dcryptedNote(String note) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String algorithm = "AES/CBC/PKCS5Padding";
        SecretKey key = secureDetailGenerator.generateKey(256);
        IvParameterSpec ivParameterSpec = secureDetailGenerator.generateIv();
        return secureDetailGenerator.decrypt(algorithm,note,key,ivParameterSpec);
    }
}
